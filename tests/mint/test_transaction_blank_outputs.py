import asyncio
import json
from typing import List

import pytest

from cashu.core.base import Amount, BlindedMessage, Method, Unit
from cashu.core.crypto.transcript import (
    TransactionShape,
    TranscriptBlindedOutput,
    TranscriptQuote,
    remainder_quote_id,
)
from cashu.core.json_rpc.base import JSONRPCSubscriptionKinds
from cashu.core.models import (
    PostMeltQuoteRequest,
    PostTransactionRequest,
    TransactionMeltOutput,
    TransactionMintQuoteOutput,
    TransactionQuoteInput,
)
from cashu.core.nuts import nut20
from cashu.core.nuts.nuts import WEBSOCKETS_NUT
from cashu.core.settings import settings
from cashu.core.split import amount_split
from cashu.mint.transaction import fill_blanks
from tests.helpers import is_fake
from tests.mint.test_mint_transaction import (
    INVOICE_62_SAT,
    locked_quote,
    output,
    quote_witness,
    transcript_remainder,
)
from tests.mint.test_mint_websocket_protocol import FakeWebSocket

pytestmark = pytest.mark.skipif(not is_fake, reason="requires FakeWallet")


async def melt_with_outputs(
    ledger, outputs: List[BlindedMessage], with_remainder: bool = True
):
    """A quote input paying the 62 sat invoice and `outputs`, with a remainder quote."""
    melt = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=INVOICE_62_SAT)
    )
    amount = 62 + melt.fee_reserve + sum(o.amount for o in outputs)
    quote, key = await locked_quote(ledger, amount)
    remainders = (
        [TransactionMintQuoteOutput(pubkey=nut20.generate_keypair()[1])]
        if with_remainder
        else []
    )
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
        mint_quote_outputs=[transcript_remainder(r, melt.quote) for r in remainders],
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
        mint_quote_outputs=remainders,
    )
    return melt, request


@pytest.mark.asyncio
async def test_blank_outputs_take_the_melt_change(ledger, monkeypatch):
    monkeypatch.setattr(settings, "lightning_reserve_fee_min", 6000)
    # Blanks around amount outputs, one amount output after every blank.
    amounts = [0, 4, 0, 0, 2]
    outputs = [output(ledger, a) for a in amounts]
    melt, request = await melt_with_outputs(ledger, outputs)
    result = await ledger.transaction(request)
    assert result.state == "PAID"
    stored = await ledger.get_melt_quote(melt.quote)
    change = melt.fee_reserve - stored.fee_paid
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
    # The outputs were signed: the remainder quote is not created.
    assert result.mint_quotes == [None]
    assert not await ledger.crud.get_blinded_messages_melt_id(
        melt_id=melt.quote, db=ledger.db, signed=False
    )


def _rotate_during_payment(ledger, monkeypatch, keyset_id: str):
    backend = ledger.backends[Method.bolt11][Unit.sat]
    original = backend.pay_invoice

    async def rotate_then_pay(quote, fee_limit):
        result = await original(quote, fee_limit)
        ledger.keysets[keyset_id].active = False
        return result

    monkeypatch.setattr(backend, "pay_invoice", rotate_then_pay)


@pytest.mark.asyncio
async def test_after_rotation_the_remainder_quote_holds_outputs_and_blank_change(
    ledger, monkeypatch
):
    monkeypatch.setattr(settings, "lightning_reserve_fee_min", 6000)
    outputs = [output(ledger, 4), output(ledger, 0)]
    melt, request = await melt_with_outputs(ledger, outputs)
    keyset = ledger.keysets[outputs[0].id]
    _rotate_during_payment(ledger, monkeypatch, outputs[0].id)
    result = await ledger.transaction(request)
    assert result.state == "PAID"
    assert result.signatures == []
    assert not result.melt_quotes[0].change
    change = melt.fee_reserve - (await ledger.get_melt_quote(melt.quote)).fee_paid
    # One blank holds the largest amount of the change; the rest stays with the mint.
    (remainder,) = result.mint_quotes
    assert remainder is not None
    assert remainder.amount == 4 + sum(fill_blanks(change, keyset.amounts, 1))
    assert remainder.method == "txout"
    assert remainder.pubkey == request.mint_quote_outputs[0].pubkey


@pytest.mark.asyncio
async def test_after_rotation_without_a_remainder_quote_the_value_is_forfeit(
    ledger, monkeypatch
):
    outputs = [output(ledger, 4), output(ledger, 0)]
    melt, request = await melt_with_outputs(ledger, outputs, with_remainder=False)
    _rotate_during_payment(ledger, monkeypatch, outputs[0].id)
    result = await ledger.transaction(request)
    assert result.state == "PAID"
    assert result.signatures == []
    assert result.mint_quotes == []



@pytest.mark.asyncio
async def test_txout_subscription_before_the_remainder_quote_exists(ledger, monkeypatch):
    outputs = [output(ledger, 4), output(ledger, 0)]
    melt, request = await melt_with_outputs(ledger, outputs)
    quote_id = remainder_quote_id(melt.quote)
    websocket = FakeWebSocket()
    client = ledger.events.add_client(websocket, ledger.db, ledger.crud)  # type: ignore
    try:
        client.add_subscription(
            JSONRPCSubscriptionKinds.TXOUT_MINT_QUOTE, [quote_id], "sub-1"
        )
        await asyncio.sleep(0.1)
        assert websocket.sent == []  # no quote yet, so no initial state

        _rotate_during_payment(ledger, monkeypatch, outputs[0].id)
        await ledger.transaction(request)
        await asyncio.sleep(0.1)
        (message,) = [json.loads(m) for m in websocket.sent]
        payload = message["params"]["payload"]
        assert message["params"]["subId"] == "sub-1"
        assert (payload["quote"], payload["state"]) == (quote_id, "PAID")
    finally:
        ledger.events.remove_client(client)


def test_txout_mint_quote_is_advertised(ledger):
    entries = ledger.mint_features[WEBSOCKETS_NUT]["supported"]
    assert {"method": "txout", "unit": "sat", "commands": ["txout_mint_quote"]} in entries

@pytest.mark.asyncio
async def test_blank_outputs_with_zero_change_sign_nothing(ledger, monkeypatch):
    outputs = [output(ledger, 0), output(ledger, 0)]
    melt, request = await melt_with_outputs(ledger, outputs)
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
    assert result.mint_quotes == [None]


def test_fill_blanks_takes_the_largest_amount_left():
    pow2 = [2**i for i in range(8)]
    assert fill_blanks(6, pow2, 3) == [4, 2]
    assert fill_blanks(13, pow2, 2) == [8, 4]  # 1 stays with the mint
    assert fill_blanks(0, pow2, 2) == []
    # Without the power of two, amounts repeat.
    assert fill_blanks(8, [1, 2, 4], 2) == [4, 4]
    assert fill_blanks(8, [4, 1, 2], 3) == [4, 4]
    assert fill_blanks(7, [5, 1, 3], 3) == [5, 1, 1]
