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
    TranscriptMintQuoteOutput,
    TranscriptQuote,
    rotation_quote_id,
    transaction_inputs,
)
from cashu.core.helpers import calculate_number_of_blank_outputs
from cashu.core.models import (
    PostMeltQuoteRequest,
    PostMintQuoteRequest,
    PostTransactionRequest,
    TransactionMeltOutput,
    TransactionMintQuoteOutput,
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


def transcript_rotation(c: TransactionMintQuoteOutput, melt_quote: str):
    return TranscriptMintQuoteOutput(
        bytes.fromhex(c.pubkey), rotation_quote_id(melt_quote)
    )


def transcript_outputs(ledger: Ledger, outputs):
    return [
        TranscriptBlindedOutput(
            amount=o.amount,
            keyset_id=bytes.fromhex(ledger.keyset.id),
            B_=bytes.fromhex(o.B_),
        )
        for o in outputs
    ]


def test_quote_input_fee_defaults_to_the_keyset_fee(monkeypatch):
    monkeypatch.setattr(settings, "mint_input_fee_ppk", 100)
    monkeypatch.setattr(settings, "mint_quote_input_fee_ppk", None)
    assert settings.quote_input_fee_ppk == 100
    monkeypatch.setattr(settings, "mint_quote_input_fee_ppk", 0)
    assert settings.quote_input_fee_ppk == 0


async def locked_quote(ledger: Ledger, amount: int):
    privkey, pubkey = nut20.generate_keypair()
    quote = await ledger.mint_quote(
        PostMintQuoteRequest(amount=amount, unit="sat", pubkey=pubkey)
    )
    return (await ledger.get_mint_quote(quote.quote)), privkey


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="fake backend pays the invoice")
async def test_transaction_mint_quote_to_melt_with_blank_change(ledger: Ledger):
    melt = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=INVOICE_62_SAT)
    )
    quote, privkey = await locked_quote(ledger, 70)
    # 70 in: the melt and its reserve, the surplus in proofs, the reserve's change in blanks.
    surplus = 70 - 62 - melt.fee_reserve
    outputs = [output(ledger, a) for a in amount_split(surplus)] + [
        output(ledger, 0)
        for _ in range(calculate_number_of_blank_outputs(melt.fee_reserve))
    ]
    rotation = TransactionMintQuoteOutput(pubkey=nut20.generate_keypair()[1])
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=70, quote_id=quote.quote, pubkey=bytes.fromhex(quote.pubkey), issued=quote.amount_issued or 0)],
        blinded_outputs=transcript_outputs(ledger, outputs),
        melt_quote_outputs=[
            TranscriptQuote(amount=melt.amount + melt.fee_reserve, quote_id=melt.quote)
        ],
        mint_quote_outputs=[transcript_rotation(rotation, melt.quote)],
    )
    request = PostTransactionRequest(
        mint_quote_inputs=[
            TransactionQuoteInput(
                quote=quote.quote,
                amount=70,
                witness=quote_witness(privkey, shape, quote.quote),
            )
        ],
        blinded_outputs=outputs,
        melt_quote_outputs=[
            TransactionMeltOutput(quote=melt.quote, fee_reserve=melt.fee_reserve)
        ],
        mint_quote_outputs=[rotation],
    )
    result = await ledger.transaction(request)
    assert result.state == "PAID"
    assert result.melt_quotes[0].state == "PAID"
    fee_paid = (await ledger.get_melt_quote(melt.quote)).fee_paid
    assert sum(s.amount for s in result.signatures) == surplus + melt.fee_reserve - fee_paid
    assert result.melt_quotes[0].change == result.signatures
    # The outputs were signed, so no rotation quote was created.
    assert result.mint_quotes == [None]
    assert (await ledger.get_mint_quote(quote.quote)).issued

    # The inputs are spent: a resend is refused.
    with pytest.raises(Exception):
        await ledger.transaction(request)



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
    surplus = 70 - 62 - melt.fee_reserve
    outputs = [output(ledger, a) for a in amount_split(surplus)] + [output(ledger, 0)]
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=70, quote_id=quote.quote, pubkey=bytes.fromhex(quote.pubkey), issued=quote.amount_issued or 0)],
        blinded_outputs=transcript_outputs(ledger, outputs),
        melt_quote_outputs=[
            TranscriptQuote(amount=melt.amount + melt.fee_reserve, quote_id=melt.quote)
        ],
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
            blinded_outputs=outputs,
            melt_quote_outputs=[
                TransactionMeltOutput(quote=melt.quote, fee_reserve=melt.fee_reserve)
            ],
        )
    )
    assert result.state == "PAID"
    # The overrun is the mint's: the surplus is signed in full and the blank stays empty.
    assert sum(s.amount for s in result.signatures) == surplus


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="fake backend pays the quote")
async def test_transaction_rotation_quote_needs_a_melt(ledger: Ledger):
    quote, privkey = await locked_quote(ledger, 8)
    outputs = [output(ledger, 8)]
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=8, quote_id=quote.quote, pubkey=bytes.fromhex(quote.pubkey), issued=quote.amount_issued or 0)],
        blinded_outputs=transcript_outputs(ledger, outputs),
    )
    quote_input = TransactionQuoteInput(
        quote=quote.quote, amount=8, witness=quote_witness(privkey, shape, quote.quote)
    )
    rotation = TransactionMintQuoteOutput(pubkey=nut20.generate_keypair()[1])
    with pytest.raises(Exception, match="needs a melt and blinded outputs"):
        await ledger.transaction(
            PostTransactionRequest(
                mint_quote_inputs=[quote_input],
                blinded_outputs=outputs,
                mint_quote_outputs=[rotation],
            )
        )
    with pytest.raises(Exception, match="at most one mint quote output"):
        await ledger.transaction(
            PostTransactionRequest(
                mint_quote_inputs=[quote_input],
                blinded_outputs=outputs,
                mint_quote_outputs=[rotation, rotation],
            )
        )
    # Only the rotation quote here: a fixed amount is refused, not ignored.
    with pytest.raises(Exception):
        TransactionMintQuoteOutput.model_validate(
            {"pubkey": rotation.pubkey, "amount": 8}
        )
    result = await ledger.transaction(
        PostTransactionRequest(mint_quote_inputs=[quote_input], blinded_outputs=outputs)
    )
    assert result.state == "PAID"
    assert [s.amount for s in result.signatures] == [8]
    assert result.mint_quotes == []



@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="fake backend pays the quote")
async def test_transaction_rejects_blank_outputs_and_imbalance(ledger: Ledger):
    quote, privkey = await locked_quote(ledger, 8)
    outputs = [output(ledger, 4)]
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=8, quote_id=quote.quote, pubkey=bytes.fromhex(quote.pubkey), issued=quote.amount_issued or 0)],
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
    # The 4 left over has nowhere to go.
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
    quote, privkey = await locked_quote(ledger, 62 + melt.fee_reserve + 2)
    outputs = [output(ledger, 2), output(ledger, 0)]
    rotation = TransactionMintQuoteOutput(pubkey=nut20.generate_keypair()[1])
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=quote.amount, quote_id=quote.quote, pubkey=bytes.fromhex(quote.pubkey), issued=quote.amount_issued or 0)],
        blinded_outputs=transcript_outputs(ledger, outputs),
        melt_quote_outputs=[
            TranscriptQuote(amount=melt.amount + melt.fee_reserve, quote_id=melt.quote)
        ],
        mint_quote_outputs=[transcript_rotation(rotation, melt.quote)],
    )
    request = PostTransactionRequest(
        mint_quote_inputs=[
            TransactionQuoteInput(
                quote=quote.quote,
                amount=quote.amount,
                witness=quote_witness(privkey, shape, quote.quote),
            )
        ],
        blinded_outputs=outputs,
        melt_quote_outputs=[
            TransactionMeltOutput(quote=melt.quote, fee_reserve=melt.fee_reserve)
        ],
        mint_quote_outputs=[rotation],
    )
    settings.fakewallet_pay_invoice_state = "FAILED"
    settings.fakewallet_payment_state = "FAILED"
    try:
        result = await ledger.transaction(request)
    finally:
        settings.fakewallet_pay_invoice_state = "SETTLED"
        settings.fakewallet_payment_state = "SETTLED"
    assert result.state == "FAILED"
    assert result.mint_quotes == [None]
    assert (await ledger.get_mint_quote(quote.quote)).paid
    # The failure released the inputs, so the request runs again.
    assert (await ledger.transaction(request)).state == "PAID"



def draw(ledger: Ledger, quote, privkey: str, amount: int):
    outputs = [output(ledger, a) for a in amount_split(amount)]
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=amount, quote_id=quote.quote, pubkey=bytes.fromhex(quote.pubkey), issued=quote.amount_issued or 0)],
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
    stale = draw(ledger, quote, privkey, 4)  # signed at amount_issued 0
    assert (await ledger.transaction(draw(ledger, quote, privkey, 4))).state == "PAID"
    part = await ledger.get_mint_quote(quote.quote)
    assert part.paid and part.amount_issued == 4 and part.mintable == 4
    # The witness binds the quote's state (NUT-10): one signed before the draw is void.
    with pytest.raises(Exception, match="Signature for mint request invalid"):
        await ledger.transaction(stale)
    with pytest.raises(Exception, match="exceeds the quote's mintable"):
        await ledger.transaction(draw(ledger, part, privkey, 5))
    assert (await ledger.transaction(draw(ledger, part, privkey, 4))).state == "PAID"
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

@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="fake backend pays the quote")
async def test_a_pending_quote_takes_no_other_draw(ledger: Ledger):
    quote, privkey = await locked_quote(ledger, 8)
    await ledger.db_write._set_mint_quotes_pending([quote.quote])
    try:
        with pytest.raises(Exception, match="pending"):
            await ledger.transaction(draw(ledger, quote, privkey, 4))
    finally:
        await ledger.db_write._unset_mint_quotes_pending(
            quote_ids=[quote.quote], state=MintQuoteState.paid
        )
    assert (await ledger.get_mint_quote(quote.quote)).amount_issued == 0


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
                )
            )
    assert (await ledger.get_mint_quote(quote.quote)).paid
