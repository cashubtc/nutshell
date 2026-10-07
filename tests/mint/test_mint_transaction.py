import json

import pytest

from cashu.core.base import (
    Amount,
    BlindedMessage,
    Method,
    MintQuote,
    MintQuoteState,
    Unit,
)
from cashu.core.crypto.bls_dhke import step1_alice
from cashu.core.crypto.secp import PrivateKey
from cashu.core.crypto.transcript import (
    TransactionShape,
    TranscriptBlindedOutput,
    TranscriptChangeOutput,
    TranscriptQuote,
    transaction_inputs,
)
from cashu.core.models import (
    PostMeltQuoteRequest,
    PostMintQuoteRequest,
    PostTransactionRequest,
    TransactionChangeOutput,
    TransactionMeltOutput,
    TransactionQuoteInput,
)
from cashu.core.nuts import nut20
from cashu.core.settings import settings
from cashu.core.split import amount_split
from cashu.mint.ledger import Ledger
from tests.helpers import is_fake

INVOICE_62_SAT = "lnbcrt620n1pn0r3vepp5zljn7g09fsyeahl4rnhuy0xax2puhua5r3gspt7ttlfrley6valqdqqcqzzsxqyz5vqsp577h763sel3q06tfnfe75kvwn5pxn344sd5vnays65f9wfgx4fpzq9qxpqysgqg3re9afz9rwwalytec04pdhf9mvh3e2k4r877tw7dr4g0fvzf9sny5nlfggdy6nduy2dytn06w50ls34qfldgsj37x0ymxam0a687mspp0ytr8"


def output(ledger: Ledger, amount: int) -> BlindedMessage:
    B_ = step1_alice(nut20.generate_keypair()[1])[0].format().hex()
    return BlindedMessage(amount=amount, B_=B_, id=ledger.keyset.id)


def quote_witness(privkey: str, shape: TransactionShape, quote_id: str) -> str:
    _, _, quotes = transaction_inputs(shape)
    signature = PrivateKey(bytes.fromhex(privkey)).sign_schnorr(quotes[quote_id].digest)
    return json.dumps({"signatures": [signature.hex()]})


async def locked_quote(ledger: Ledger, amount: int):
    privkey, pubkey = nut20.generate_keypair()
    quote = await ledger.mint_quote(
        PostMintQuoteRequest(amount=amount, unit="sat", pubkey=pubkey)
    )
    return (await ledger.get_mint_quote(quote.quote)), privkey


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="fake backend pays the invoice")
async def test_transaction_mint_quote_to_melt_with_change(ledger: Ledger):
    melt = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=INVOICE_62_SAT)
    )
    quote, privkey = await locked_quote(ledger, 70)
    change_privkey, change_key = nut20.generate_keypair()
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=70, quote_id=quote.quote)],
        melt_quote_outputs=[
            TranscriptQuote(amount=melt.amount + melt.fee_reserve, quote_id=melt.quote)
        ],
        change_quote_outputs=[TranscriptChangeOutput(bytes.fromhex(change_key))],
    )
    request = PostTransactionRequest(
        mint_quote_inputs=[
            TransactionQuoteInput(
                quote=quote.quote,
                amount=70,
                witness=quote_witness(privkey, shape, quote.quote),
            )
        ],
        melt_quote_outputs=[
            TransactionMeltOutput(quote=melt.quote, fee_reserve=melt.fee_reserve)
        ],
        change_quote_outputs=[TransactionChangeOutput(pubkey=change_key)],
    )
    result = await ledger.transaction(request)
    assert result.state == "PAID"
    assert result.melt_quotes[0].state == "PAID"
    fee_paid = (await ledger.get_melt_quote(melt.quote)).fee_paid
    (change_quote,) = result.change_quotes
    assert change_quote is not None
    assert change_quote.method == "change"
    assert change_quote.amount == 70 - 62 - fee_paid
    assert change_quote.pubkey == change_key
    assert change_quote.request == result.digest
    assert (await ledger.get_mint_quote(quote.quote)).issued

    # A resend returns the record rather than spending again.
    again = await ledger.transaction(request)
    assert again.digest == result.digest and again.state == "PAID"
    assert again.change_quotes[0] and again.change_quotes[0].quote == change_quote.quote

    # The change quote redeems like any locked quote.
    change = change_quote.amount
    outputs = [output(ledger, a) for a in amount_split(change)]
    signature = nut20.sign_mint_quote_v3(
        change_quote.quote, change, outputs, change_privkey
    )
    promises = await ledger.mint(
        outputs=outputs, quote_id=change_quote.quote, signature=signature
    )
    assert sum(p.amount for p in promises) == change
    assert (await ledger.get_mint_quote(change_quote.quote)).issued


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="fake backend pays the invoice")
async def test_transaction_fee_overrun_does_not_eat_surplus(ledger: Ledger, monkeypatch):
    melt = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=INVOICE_62_SAT)
    )
    backend = ledger.backends[Method.bolt11][Unit.sat]
    pay_invoice = backend.pay_invoice

    async def overrun(quote, fee_limit):
        payment = await pay_invoice(quote, fee_limit)
        payment.fee = Amount(Unit.sat, melt.fee_reserve + 5)
        return payment

    monkeypatch.setattr(backend, "pay_invoice", overrun)
    quote, privkey = await locked_quote(ledger, 70)
    _, change_key = nut20.generate_keypair()
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=70, quote_id=quote.quote)],
        melt_quote_outputs=[
            TranscriptQuote(amount=melt.amount + melt.fee_reserve, quote_id=melt.quote)
        ],
        change_quote_outputs=[TranscriptChangeOutput(bytes.fromhex(change_key))],
    )
    result = await ledger.transaction(
        PostTransactionRequest(
            mint_quote_inputs=[
                TransactionQuoteInput(
                    quote=quote.quote,
                    amount=70,
                    witness=quote_witness(privkey, shape, quote.quote),
                )
            ],
            melt_quote_outputs=[
                TransactionMeltOutput(quote=melt.quote, fee_reserve=melt.fee_reserve)
            ],
            change_quote_outputs=[TransactionChangeOutput(pubkey=change_key)],
        )
    )
    assert result.state == "PAID"
    assert result.change_quotes[0] is not None
    assert result.change_quotes[0].amount == 70 - 62 - melt.fee_reserve

@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="fake backend pays the quote")
async def test_transaction_quote_to_outputs_and_change(ledger: Ledger):
    quote, privkey = await locked_quote(ledger, 8)
    _, change_key = nut20.generate_keypair()
    outputs = [output(ledger, 4)]
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=8, quote_id=quote.quote)],
        blinded_outputs=[
            TranscriptBlindedOutput(
                amount=4,
                keyset_id=bytes.fromhex(ledger.keyset.id),
                B_=bytes.fromhex(o.B_),
            )
            for o in outputs
        ],
        change_quote_outputs=[TranscriptChangeOutput(bytes.fromhex(change_key))],
    )
    result = await ledger.transaction(
        PostTransactionRequest(
            mint_quote_inputs=[
                TransactionQuoteInput(
                    quote=quote.quote,
                    amount=8,
                    witness=quote_witness(privkey, shape, quote.quote),
                )
            ],
            blinded_outputs=outputs,
            change_quote_outputs=[TransactionChangeOutput(pubkey=change_key)],
        )
    )
    assert result.state == "PAID"
    assert [s.amount for s in result.signatures] == [4]
    assert result.change_quotes[0] is not None
    assert result.change_quotes[0].amount == 4
    assert (await ledger.get_transaction(result.digest)).signatures[0].C_ == (
        result.signatures[0].C_
    )


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="fake backend pays the quote")
async def test_transaction_rejects_blank_outputs_and_imbalance(ledger: Ledger):
    quote, privkey = await locked_quote(ledger, 8)
    outputs = [output(ledger, 4)]
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=8, quote_id=quote.quote)],
        blinded_outputs=[
            TranscriptBlindedOutput(
                amount=4,
                keyset_id=bytes.fromhex(ledger.keyset.id),
                B_=bytes.fromhex(o.B_),
            )
            for o in outputs
        ],
    )
    quote_input = TransactionQuoteInput(
        quote=quote.quote, amount=8, witness=quote_witness(privkey, shape, quote.quote)
    )
    # Without a remainder quote the 4 left over has nowhere to go.
    with pytest.raises(Exception, match="do not balance"):
        await ledger.transaction(
            PostTransactionRequest(
                mint_quote_inputs=[quote_input], blinded_outputs=outputs
            )
        )
    with pytest.raises(Exception, match="blank outputs"):
        await ledger.transaction(
            PostTransactionRequest(
                mint_quote_inputs=[quote_input], blinded_outputs=[output(ledger, 0)]
            )
        )
    # The quote was released and is still spendable.
    assert (await ledger.get_mint_quote(quote.quote)).paid


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="fake backend fails the payment")
async def test_transaction_failed_payment_releases_quote(ledger: Ledger):
    melt = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=INVOICE_62_SAT)
    )
    quote, privkey = await locked_quote(ledger, 62 + melt.fee_reserve)
    amount = quote.amount
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=amount, quote_id=quote.quote)],
        melt_quote_outputs=[TranscriptQuote(amount=amount, quote_id=melt.quote)],
    )
    request = PostTransactionRequest(
        mint_quote_inputs=[
            TransactionQuoteInput(
                quote=quote.quote,
                amount=amount,
                witness=quote_witness(privkey, shape, quote.quote),
            )
        ],
        melt_quote_outputs=[
            TransactionMeltOutput(quote=melt.quote, fee_reserve=melt.fee_reserve)
        ],
    )
    settings.fakewallet_pay_invoice_state = "FAILED"
    settings.fakewallet_payment_state = "FAILED"
    try:
        result = await ledger.transaction(request)
    finally:
        settings.fakewallet_pay_invoice_state = "SETTLED"
        settings.fakewallet_payment_state = "SETTLED"
    assert result.state == "FAILED"
    assert (await ledger.get_mint_quote(quote.quote)).paid
    # A FAILED transaction may be resubmitted, and replaces its record.
    assert (await ledger.transaction(request)).state == "PAID"


def draw(ledger: Ledger, quote, privkey: str, amount: int):
    outputs = [output(ledger, a) for a in amount_split(amount)]
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=amount, quote_id=quote.quote)],
        blinded_outputs=[
            TranscriptBlindedOutput(
                amount=o.amount,
                keyset_id=bytes.fromhex(ledger.keyset.id),
                B_=bytes.fromhex(o.B_),
            )
            for o in outputs
        ],
    )
    return PostTransactionRequest(
        mint_quote_inputs=[
            TransactionQuoteInput(
                quote=quote.quote,
                amount=amount,
                witness=quote_witness(privkey, shape, quote.quote),
            )
        ],
        blinded_outputs=outputs,
    )


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="fake backend pays the quote")
async def test_transaction_draws_a_quote_in_parts(ledger: Ledger):
    quote, privkey = await locked_quote(ledger, 8)
    assert (await ledger.transaction(draw(ledger, quote, privkey, 4))).state == "PAID"
    part = await ledger.get_mint_quote(quote.quote)
    assert part.paid and part.amount_issued == 4 and part.mintable == 4
    with pytest.raises(Exception, match="exceeds the quote's mintable"):
        await ledger.transaction(draw(ledger, quote, privkey, 5))
    assert (await ledger.transaction(draw(ledger, quote, privkey, 4))).state == "PAID"
    done = await ledger.get_mint_quote(quote.quote)
    assert done.issued and done.amount_issued == 8 and done.mintable == 0


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="fake backend pays the quote")
async def test_mint_rechecks_a_quote_drawn_after_reading(ledger: Ledger, monkeypatch):
    quote, privkey = await locked_quote(ledger, 8)
    stale = await ledger.get_mint_quote(quote.quote)
    assert (await ledger.transaction(draw(ledger, quote, privkey, 4))).state == "PAID"

    async def stale_read(quote_id):
        return stale

    monkeypatch.setattr(ledger, "get_mint_quote", stale_read)
    with pytest.raises(Exception, match="does not match quote amount"):
        await ledger.mint(outputs=[output(ledger, 8)], quote_id=quote.quote)
    assert (await ledger.crud.get_mint_quote(quote_id=quote.quote, db=ledger.db)).paid

def test_pending_revert_keeps_amount_issued():
    quote = MintQuote(
        quote="q",
        method="bolt11",
        request="r",
        checking_id="c",
        unit="sat",
        amount=8,
        state=MintQuoteState.paid,
        amount_paid=8,
        amount_issued=4,
    )
    quote.state = MintQuoteState.pending
    quote.state = MintQuoteState.paid
    assert quote.amount_issued == 4 and quote.mintable == 4


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="fake backend pays the quote")
async def test_transaction_rejects_a_mismatched_fee_reserve(ledger: Ledger):
    melt = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=INVOICE_62_SAT)
    )
    quote, privkey = await locked_quote(ledger, 70)
    _, change_key = nut20.generate_keypair()
    for melt_output in (
        TransactionMeltOutput(quote=melt.quote, fee_reserve=melt.fee_reserve + 1),
        TransactionMeltOutput(
            quote=melt.quote, fee_reserve=melt.fee_reserve, fee_index=0
        ),
    ):
        with pytest.raises(Exception, match="fee_reserve does not match|fee_options"):
            await ledger.transaction(
                PostTransactionRequest(
                    mint_quote_inputs=[
                        TransactionQuoteInput(
                            quote=quote.quote, amount=70, witness="{}"
                        )
                    ],
                    melt_quote_outputs=[melt_output],
                    change_quote_outputs=[
                        TransactionChangeOutput(pubkey=change_key)
                    ],
                )
            )
    assert (await ledger.get_mint_quote(quote.quote)).paid
