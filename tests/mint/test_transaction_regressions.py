import asyncio

import pytest
from fastapi import FastAPI, Request, Response

from cashu.core.base import (
    MeltQuote,
    MeltQuoteState,
    Method,
    MintQuote,
    MintQuoteState,
    Unit,
)
from cashu.core.crypto.transcript import (
    TransactionShape,
    TranscriptBlindedOutput,
    TranscriptQuote,
)
from cashu.core.errors import TransactionError
from cashu.core.models import (
    PostMeltQuoteRequest,
    PostTransactionRequest,
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
async def test_redeem_the_rest_of_a_drawn_quote_through_mint(ledger):
    quote, key = await locked_quote(ledger, 8)
    await ledger.transaction(draw(ledger, quote, key, 4))
    outputs = [output(ledger, 4)]
    # The NUT-04 mint signs at the quote's state after the draw (NUT-10).
    issued = (await ledger.get_mint_quote(quote.quote)).amount_issued
    assert issued == 4
    signature = nut20.sign_mint_quote_v3(quote.quote, 4, outputs, key, issued)
    signatures = await ledger.mint(
        outputs=outputs, quote_id=quote.quote, signature=signature
    )
    assert sum(s.amount for s in signatures) == 4
    assert (await ledger.get_mint_quote(quote.quote)).issued


@pytest.mark.asyncio
async def test_melt_quote_change_carries_the_output_signatures(ledger):
    melt = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=INVOICE_62_SAT)
    )
    amount = 62 + melt.fee_reserve + 6
    quote, key = await locked_quote(ledger, amount)
    outputs = [output(ledger, 4), output(ledger, 2)]
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=amount, quote_id=quote.quote, pubkey=bytes.fromhex(quote.pubkey), issued=quote.amount_issued or 0)],
        blinded_outputs=[
            TranscriptBlindedOutput(
                amount=o.amount, keyset_id=bytes.fromhex(o.id), B_=bytes.fromhex(o.B_)
            )
            for o in outputs
        ],
        melt_quote_outputs=[
            TranscriptQuote(amount=62 + melt.fee_reserve, quote_id=melt.quote)
        ],
    )
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
        )
    )
    assert result.state == "PAID"
    signed = [s.C_ for s in result.signatures]
    assert [s.amount for s in result.signatures] == [4, 2]
    assert [s.C_ for s in result.melt_quotes[0].change or []] == signed
    stored = await ledger.get_melt_quote(melt.quote)
    assert [s.C_ for s in stored.change or []] == signed


@pytest.mark.asyncio
async def test_internal_melt_turns_paid_when_its_transaction_settles(
    ledger, monkeypatch
):
    source, key = await locked_quote(ledger, 14)
    monkeypatch.setattr(settings, "fakewallet_brr", False)
    destination, _ = await locked_quote(ledger, 8)
    melt = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=destination.request)
    )
    outputs = [output(ledger, 4), output(ledger, 2)]
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=14, quote_id=source.quote, pubkey=bytes.fromhex(source.pubkey), issued=source.amount_issued or 0)],
        blinded_outputs=[
            TranscriptBlindedOutput(
                amount=o.amount, keyset_id=bytes.fromhex(o.id), B_=bytes.fromhex(o.B_)
            )
            for o in outputs
        ],
        melt_quote_outputs=[TranscriptQuote(amount=8, quote_id=melt.quote)],
    )
    melt_events = []
    source_states = []
    submit = ledger.events.submit

    async def record(event):
        if isinstance(event, MeltQuote) and event.quote == melt.quote:
            melt_events.append((event.state, len(event.change or [])))
        if isinstance(event, MintQuote) and event.quote == source.quote:
            source_states.append(event.state)
        await submit(event)

    monkeypatch.setattr(ledger.events, "submit", record)
    result = await ledger.transaction(
        PostTransactionRequest(
            mint_quote_inputs=[
                TransactionQuoteInput(
                    quote=source.quote, amount=14, witness=quote_witness(key, shape, source.quote)
                )
            ],
            blinded_outputs=outputs,
            melt_quote_outputs=[
                TransactionMeltOutput(quote=melt.quote, fee_reserve=melt.fee_reserve)
            ],
        )
    )
    assert result.state == "PAID" and len(result.signatures) == 2
    paid = [e for e in melt_events if e[0] == MeltQuoteState.paid]
    assert paid and paid[0] == (MeltQuoteState.paid, 2)
    # The quote input is announced pending at acceptance, then issued at settlement.
    assert source_states == [MintQuoteState.pending, MintQuoteState.issued]


@pytest.mark.asyncio
async def test_internal_melt_finalized_by_a_poll_skips_the_backend(ledger, monkeypatch):
    source, key = await locked_quote(ledger, 8)
    monkeypatch.setattr(settings, "fakewallet_brr", False)
    destination, _ = await locked_quote(ledger, 8)
    melt = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=destination.request)
    )
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=8, quote_id=source.quote, pubkey=bytes.fromhex(source.pubkey), issued=source.amount_issued or 0)],
        melt_quote_outputs=[TranscriptQuote(amount=8, quote_id=melt.quote)],
    )
    original = ledger.melt_mint_settle_internally

    async def settle_then_poll(*args, **kwargs):
        result = await original(*args, **kwargs)
        await ledger.get_melt_quote(melt.quote)  # finalizes the transaction
        return result

    backend_calls = []

    async def pay_invoice(*args, **kwargs):
        backend_calls.append(args)
        raise AssertionError("backend called")

    monkeypatch.setattr(ledger, "melt_mint_settle_internally", settle_then_poll)
    monkeypatch.setattr(ledger.backends[Method.bolt11][Unit.sat], "pay_invoice", pay_invoice)
    result = await ledger.transaction(
        PostTransactionRequest(
            mint_quote_inputs=[
                TransactionQuoteInput(
                    quote=source.quote, amount=8, witness=quote_witness(key, shape, source.quote)
                )
            ],
            melt_quote_outputs=[
                TransactionMeltOutput(quote=melt.quote, fee_reserve=melt.fee_reserve)
            ],
        )
    )
    assert backend_calls == []
    assert result.state == "PAID"
    assert (await ledger.get_mint_quote(source.quote)).issued


@pytest.mark.asyncio
async def test_rpc_state_update_refuses_a_transaction_melt(ledger):
    melt = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=INVOICE_62_SAT)
    )
    await ledger.db.execute(
        "INSERT INTO melt_transactions (melt_quote, unit, mint_quotes, excess)"
        " VALUES (:q, 'sat', '[]', 0)",
        {"q": melt.quote},
    )
    with pytest.raises(TransactionError, match="pending transaction"):
        await ledger.db_write._update_melt_quote_state(melt.quote, MeltQuoteState.paid)
    assert (await ledger.crud.get_melt_quote(quote_id=melt.quote, db=ledger.db)).unpaid
    await ledger.db.execute("DELETE FROM melt_transactions")
    await ledger.db_write._update_melt_quote_state(melt.quote, MeltQuoteState.pending)


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
        mint_quote_inputs=[TranscriptQuote(amount=8, quote_id=source.quote, pubkey=bytes.fromhex(source.pubkey), issued=source.amount_issued or 0)],
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
    if recovery == "startup":
        await ledger._check_pending_proofs_and_melt_quotes()
        assert not await ledger.db.fetchall("SELECT * FROM melt_transactions")
    assert (await ledger.get_melt_quote(melt.quote)).paid
    assert not await ledger.db.fetchall("SELECT * FROM melt_transactions")
    assert (await ledger.get_mint_quote(source.quote)).issued
    with pytest.raises(Exception):
        await ledger.transaction(request)


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
            mint_quote_inputs=[TranscriptQuote(amount=amount, quote_id=quote.quote, pubkey=bytes.fromhex(quote.pubkey), issued=quote.amount_issued or 0)],
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

    events = []
    submit = ledger.events.submit

    async def record(event):
        events.append(event)
        await submit(event)

    monkeypatch.setattr(ledger.events, "submit", record)
    monkeypatch.setattr(ledger, "_store_blinded_messages", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await ledger.transaction(request)
    monkeypatch.setattr(ledger, "_store_blinded_messages", original)
    monkeypatch.setattr(ledger.events, "submit", submit)
    assert events == []  # the rolled-back acceptance emits nothing
    assert (await ledger.get_mint_quote(quote.quote)).mintable == amount
    assert not await ledger.db.fetchall("SELECT * FROM melt_transactions")
    if melt:
        assert (await ledger.get_melt_quote(melt.quote)).unpaid
    assert (await ledger.transaction(request)).state == "PAID"


@pytest.mark.asyncio
async def test_transaction_route_requires_blind_auth(ledger, monkeypatch):
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
            "path": "/v1/transaction",
            "headers": [],
            "query_string": b"",
        }
    )
    with pytest.raises(Exception, match="Missing blind auth token"):
        await middleware.dispatch(request, call_next)
