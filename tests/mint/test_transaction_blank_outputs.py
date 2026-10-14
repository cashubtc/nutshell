from typing import List

import pytest

from cashu.core.base import Amount, BlindedMessage, Method, Unit
from cashu.core.crypto.transcript import (
    TransactionShape,
    TranscriptBlindedOutput,
    TranscriptQuote,
)
from cashu.core.models import (
    PostMeltQuoteRequest,
    PostTransactionRequest,
    TransactionMeltOutput,
    TransactionQuoteInput,
)
from cashu.core.nuts import nut20
from cashu.core.split import amount_split
from cashu.mint.transaction import fill_blanks
from tests.helpers import is_fake
from tests.mint.test_mint_transaction import (
    INVOICE_62_SAT,
    change_output,
    locked_quote,
    output,
    quote_witness,
    transcript_change,
)

pytestmark = pytest.mark.skipif(not is_fake, reason="requires FakeWallet")


async def melt_with_outputs(ledger, surplus: int, outputs: List[BlindedMessage]):
    """A quote input paying the 62 sat invoice, `outputs` and `surplus` to the remainder quote."""
    melt = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=INVOICE_62_SAT)
    )
    amount = 62 + melt.fee_reserve + sum(o.amount for o in outputs) + surplus
    quote, key = await locked_quote(ledger, amount)
    change_out = change_output(nut20.generate_keypair()[1])
    shape = TransactionShape(
        mint_quote_inputs=[
            TranscriptQuote(
                amount=amount,
                quote_id=quote.quote,
                pubkey=bytes.fromhex(quote.pubkey),
                issued=quote.amount_issued or 0,
            )
        ],
        blinded_outputs=[
            TranscriptBlindedOutput(
                amount=o.amount, keyset_id=bytes.fromhex(o.id), B_=bytes.fromhex(o.B_)
            )
            for o in outputs
        ],
        melt_quote_outputs=[
            TranscriptQuote(amount=62 + melt.fee_reserve, quote_id=melt.quote)
        ],
        change_quote_outputs=[transcript_change(change_out)],
    )
    request = PostTransactionRequest(
        mint_quote_inputs=[
            TransactionQuoteInput(
                quote=quote.quote,
                amount=amount,
                witness=quote_witness(key, shape, quote.quote),
            )
        ],
        blinded_outputs=outputs,
        melt_quote_outputs=[
            TransactionMeltOutput(quote=melt.quote, fee_reserve=melt.fee_reserve)
        ],
        change_quote_outputs=[change_out],
    )
    return melt, request


@pytest.mark.asyncio
async def test_blank_outputs_take_the_melt_change(ledger):
    # Blanks around amount outputs, one amount output after every blank.
    amounts = [0, 4, 0, 0, 2]
    outputs = [output(ledger, a) for a in amounts]
    melt, request = await melt_with_outputs(ledger, 5, outputs)
    result = await ledger.transaction(request)
    assert result.state == "PAID"
    stored = await ledger.get_melt_quote(melt.quote)
    change = 5 + melt.fee_reserve - stored.fee_paid
    imprint = sorted(amount_split(change), reverse=True)
    assert len(imprint) == 2  # the last blank stays at zero
    # The first blanks in request order take the change; the trailing zero blank is omitted.
    expected = [(outputs[0].B_, imprint[0]), (outputs[1].B_, 4)]
    expected += [(outputs[2].B_, imprint[1]), (outputs[4].B_, 2)]
    assert [s.amount for s in result.signatures] == [a for _, a in expected]
    signed = await ledger.crud.get_blinded_messages_melt_id(
        melt_id=melt.quote, db=ledger.db, signed=True
    )
    assert [(m.B_, m.amount) for m in signed] == expected
    assert [s.C_ for s in result.signatures] == [m.C_ for m in signed]
    assert [s.C_ for s in result.melt_quotes[0].change or []] == [
        m.C_ for m in signed
    ]
    assert [s.C_ for s in stored.change or []] == [m.C_ for m in signed]
    # The blanks took all the change: the remainder quote is not created.
    assert result.change_quotes == [None]
    assert not await ledger.crud.get_blinded_messages_melt_id(
        melt_id=melt.quote, db=ledger.db, signed=False
    )


@pytest.mark.asyncio
async def test_blank_outputs_after_rotation_leave_change_to_the_remainder(
    ledger, monkeypatch
):
    outputs = [output(ledger, 4), output(ledger, 0)]
    melt, request = await melt_with_outputs(ledger, 5, outputs)
    backend = ledger.backends[Method.bolt11][Unit.sat]
    original = backend.pay_invoice

    async def rotate_then_pay(quote, fee_limit):
        result = await original(quote, fee_limit)
        ledger.keysets[outputs[0].id].active = False
        return result

    monkeypatch.setattr(backend, "pay_invoice", rotate_then_pay)
    result = await ledger.transaction(request)
    assert result.state == "PAID"
    assert result.signatures == []
    assert not result.melt_quotes[0].change
    fee_paid = (await ledger.get_melt_quote(melt.quote)).fee_paid
    assert result.change_quotes[0] is not None
    assert result.change_quotes[0].amount == 4 + 5 + melt.fee_reserve - fee_paid


@pytest.mark.asyncio
async def test_blank_outputs_with_zero_change_sign_nothing(ledger, monkeypatch):
    outputs = [output(ledger, 0), output(ledger, 0)]
    melt, request = await melt_with_outputs(ledger, 0, outputs)
    backend = ledger.backends[Method.bolt11][Unit.sat]
    pay_invoice = backend.pay_invoice

    async def spend_reserve(quote, fee_limit):
        payment = await pay_invoice(quote, fee_limit)
        payment.fee = Amount(Unit.sat, melt.fee_reserve)
        return payment

    monkeypatch.setattr(backend, "pay_invoice", spend_reserve)
    result = await ledger.transaction(request)
    assert result.state == "PAID"
    assert result.signatures == []
    assert not result.melt_quotes[0].change
    assert result.change_quotes == [None]


def test_fill_blanks_takes_the_largest_amount_left():
    pow2 = [2**i for i in range(8)]
    assert fill_blanks(6, pow2, 3) == [4, 2]
    assert fill_blanks(13, pow2, 2) == [8, 4]  # the remainder quote takes 1
    assert fill_blanks(0, pow2, 2) == []
    # Without the power of two, amounts repeat.
    assert fill_blanks(8, [1, 2, 4], 2) == [4, 4]
    assert fill_blanks(8, [4, 1, 2], 3) == [4, 4]
    assert fill_blanks(7, [5, 1, 3], 3) == [5, 1, 1]
