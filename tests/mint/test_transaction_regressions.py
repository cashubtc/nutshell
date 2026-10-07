import asyncio

import pytest
from fastapi import FastAPI, Request, Response

from cashu.core.base import Method, Unit
from cashu.core.crypto.transcript import (
    TransactionShape,
    TranscriptBlindedOutput,
    TranscriptChangeOutput,
    TranscriptQuote,
    transaction_inputs,
)
from cashu.core.errors import KeysetInactiveError, TransactionError
from cashu.core.models import (
    PostMeltQuoteRequest,
    PostTransactionRequest,
    TransactionChangeOutput,
    TransactionMeltOutput,
    TransactionQuoteInput,
)
from cashu.core.nuts import nut20
from cashu.core.settings import settings
from cashu.mint.middleware import BlindAuthMiddleware
from tests.helpers import is_fake
from tests.mint.test_mint_transaction import (
    INVOICE_62_SAT,
    draw,
    locked_quote,
    output,
    quote_witness,
)

pytestmark = pytest.mark.skipif(not is_fake, reason="requires FakeWallet")


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [False, True])
async def test_redeem_remainder_through_mint(ledger, change):
    quote, key = await locked_quote(ledger, 8)
    if change:
        change_key, pubkey = nut20.generate_keypair()
        shape = TransactionShape(
            mint_quote_inputs=[TranscriptQuote(amount=8, quote_id=quote.quote)],
            change_quote_outputs=[TranscriptChangeOutput(bytes.fromhex(pubkey))],
        )
        result = await ledger.transaction(
            PostTransactionRequest(
                mint_quote_inputs=[
                    TransactionQuoteInput(
                        quote=quote.quote,
                        amount=8,
                        witness=quote_witness(key, shape, quote.quote),
                    )
                ],
                change_quote_outputs=[TransactionChangeOutput(pubkey=pubkey)],
            )
        )
        assert result.change_quotes[0] is not None
        quote = await ledger.get_mint_quote(result.change_quotes[0].quote)
        key = change_key
    await ledger.transaction(draw(ledger, quote, key, 4))
    outputs = [output(ledger, 4)]
    signature = nut20.sign_mint_quote_v3(quote.quote, 4, outputs, key)
    signatures = await ledger.mint(
        outputs=outputs, quote_id=quote.quote, signature=signature
    )
    assert sum(s.amount for s in signatures) == 4
    assert (await ledger.get_mint_quote(quote.quote)).issued


@pytest.mark.asyncio
async def test_settlement_after_rotation(ledger, monkeypatch):
    melt = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=INVOICE_62_SAT)
    )
    amount = 62 + melt.fee_reserve + 4
    quote, key = await locked_quote(ledger, amount)
    outputs = [output(ledger, 4)]
    _, change_key = nut20.generate_keypair()
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=amount, quote_id=quote.quote)],
        blinded_outputs=[
            TranscriptBlindedOutput(
                amount=4,
                keyset_id=bytes.fromhex(outputs[0].id),
                B_=bytes.fromhex(outputs[0].B_),
            )
        ],
        melt_quote_outputs=[
            TranscriptQuote(amount=62 + melt.fee_reserve, quote_id=melt.quote)
        ],
        change_quote_outputs=[TranscriptChangeOutput(bytes.fromhex(change_key))],
    )
    # A melt with outputs needs a remainder quote: rotation would strand them otherwise.
    with pytest.raises(TransactionError, match="remainder quote"):
        await ledger.transaction(
            PostTransactionRequest(
                mint_quote_inputs=[
                    TransactionQuoteInput(quote=quote.quote, amount=amount, witness="")
                ],
                blinded_outputs=outputs,
                melt_quote_outputs=[
                    TransactionMeltOutput(quote=melt.quote, fee_reserve=melt.fee_reserve)
                ],
            )
        )
    backend = ledger.backends[Method.bolt11][Unit.sat]
    original = backend.pay_invoice

    async def rotate_then_pay(quote, fee_limit):
        result = await original(quote, fee_limit)
        ledger.keysets[outputs[0].id].active = False
        return result

    monkeypatch.setattr(backend, "pay_invoice", rotate_then_pay)
    result = await ledger.transaction(
        PostTransactionRequest(
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
            change_quote_outputs=[TransactionChangeOutput(pubkey=change_key)],
        )
    )
    # The rotated keyset signs nothing (NUT-02); the outputs' value is change.
    assert result.state == "PAID"
    assert result.signatures == []
    fee_paid = (await ledger.get_melt_quote(melt.quote)).fee_paid
    assert result.change_quotes[0] is not None
    assert result.change_quotes[0].amount == amount - 62 - fee_paid
    assert (await ledger.get_mint_quote(quote.quote)).issued
    with pytest.raises(KeysetInactiveError):
        await ledger._sign_blinded_messages([output(ledger, 4)])


@pytest.mark.asyncio
@pytest.mark.parametrize("recovery", ["poll", "startup"])
async def test_internal_quote_only_recovers_finalization(ledger, monkeypatch, recovery):
    source, key = await locked_quote(ledger, 8)
    monkeypatch.setattr(settings, "fakewallet_brr", False)
    destination, _ = await locked_quote(ledger, 8)
    melt = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=destination.request)
    )
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=8, quote_id=source.quote)],
        melt_quote_outputs=[TranscriptQuote(amount=8, quote_id=melt.quote)],
    )
    original = ledger._finalize_melt_paid

    async def interrupted(*args, **kwargs):
        raise asyncio.CancelledError()

    monkeypatch.setattr(ledger, "_finalize_melt_paid", interrupted)
    request = PostTransactionRequest(
        mint_quote_inputs=[
            TransactionQuoteInput(
                quote=source.quote,
                amount=8,
                witness=quote_witness(key, shape, source.quote),
            )
        ],
        melt_quote_outputs=[
            TransactionMeltOutput(quote=melt.quote, fee_reserve=melt.fee_reserve)
        ],
    )
    with pytest.raises(asyncio.CancelledError):
        await ledger.transaction(request)
    monkeypatch.setattr(ledger, "_finalize_melt_paid", original)
    digest = transaction_inputs(shape)[0].hex()
    if recovery == "startup":
        await ledger._check_pending_proofs_and_melt_quotes()
        row = await ledger.db.fetchone(
            "SELECT state FROM transactions WHERE digest = :digest", {"digest": digest}
        )
        assert row["state"] == "PAID"
    result = await ledger.get_transaction(digest)
    assert result.state == "PAID"
    assert (await ledger.get_mint_quote(source.quote)).issued
    assert (await ledger.transaction(request)).state == "PAID"


@pytest.mark.asyncio
@pytest.mark.parametrize("with_melt", [False, True])
async def test_interrupted_acceptance_can_retry(ledger, monkeypatch, with_melt):
    melt = None
    if with_melt:
        melt = await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=INVOICE_62_SAT)
        )
    amount = melt.amount + melt.fee_reserve if melt else 8
    quote, key = await locked_quote(ledger, amount)
    if melt:
        shape = TransactionShape(
            mint_quote_inputs=[TranscriptQuote(amount=amount, quote_id=quote.quote)],
            melt_quote_outputs=[TranscriptQuote(amount=amount, quote_id=melt.quote)],
        )
        request = PostTransactionRequest(
            mint_quote_inputs=[
                TransactionQuoteInput(
                    quote=quote.quote,
                    amount=amount,
                    witness=quote_witness(key, shape, quote.quote),
                )
            ],
            melt_quote_outputs=[
                TransactionMeltOutput(quote=melt.quote, fee_reserve=melt.fee_reserve)
            ],
        )
    else:
        request = draw(ledger, quote, key, amount)
    original = ledger._store_blinded_messages

    async def cancelled(*args, **kwargs):
        raise asyncio.CancelledError()

    monkeypatch.setattr(ledger, "_store_blinded_messages", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await ledger.transaction(request)
    monkeypatch.setattr(ledger, "_store_blinded_messages", original)
    assert (await ledger.get_mint_quote(quote.quote)).mintable == amount
    assert not await ledger.db.fetchall("SELECT * FROM transactions")
    if melt:
        assert (await ledger.get_melt_quote(melt.quote)).unpaid
    assert (await ledger.transaction(request)).state == "PAID"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/v1/transaction", "/v1/mint/change"])
async def test_new_routes_require_blind_auth(ledger, monkeypatch, path):
    monkeypatch.setattr(settings, "mint_require_auth", True)
    monkeypatch.setattr(
        settings, "mint_auth_oicd_discovery_url", "https://example.invalid/discovery"
    )
    monkeypatch.setattr(settings, "mint_auth_oicd_client_id", "test")
    monkeypatch.setattr("cashu.mint.middleware.auth_ledger", ledger)
    middleware = BlindAuthMiddleware(FastAPI())

    async def call_next(request):
        return Response(status_code=200)

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": [],
            "query_string": b"",
        }
    )
    with pytest.raises(Exception, match="Missing blind auth token"):
        await middleware.dispatch(request, call_next)
