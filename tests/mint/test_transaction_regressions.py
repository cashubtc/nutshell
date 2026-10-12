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
from cashu.core.errors import KeysetInactiveError, TransactionError
from cashu.core.models import (
    PostMeltQuoteRequest,
    PostTransactionRequest,
    TransactionMeltOutput,
    TransactionQuoteInput,
)
from cashu.core.nuts import nut20
from cashu.core.settings import settings
from cashu.mint import transaction as nut_xx
from cashu.mint.middleware import BlindAuthMiddleware
from tests.helpers import is_fake
from tests.mint.test_mint_transaction import (
    INVOICE_62_SAT,
    change_output,
    draw,
    locked_quote,
    output,
    quote_witness,
    transcript_change,
)

pytestmark = pytest.mark.skipif(not is_fake, reason="requires FakeWallet")


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [False, True])
async def test_redeem_remainder_through_mint(ledger, change):
    quote, key = await locked_quote(ledger, 8)
    if change:
        change_key, pubkey = nut20.generate_keypair()
        change_out = change_output(pubkey)
        shape = TransactionShape(
            mint_quote_inputs=[TranscriptQuote(amount=8, quote_id=quote.quote, pubkey=bytes.fromhex(quote.pubkey))],
            change_quote_outputs=[transcript_change(change_out)],
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
                change_quote_outputs=[change_out],
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
    change_out = change_output(nut20.generate_keypair()[1])
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=amount, quote_id=quote.quote, pubkey=bytes.fromhex(quote.pubkey))],
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
        change_quote_outputs=[transcript_change(change_out)],
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
            change_quote_outputs=[change_out],
        )
    )
    # The rotated keyset signs nothing (NUT-02); the outputs' value is change.
    assert result.state == "PAID"
    assert result.signatures == []
    assert not result.melt_quotes[0].change
    fee_paid = (await ledger.get_melt_quote(melt.quote)).fee_paid
    assert result.change_quotes[0] is not None
    assert result.change_quotes[0].amount == amount - 62 - fee_paid
    assert (await ledger.get_mint_quote(quote.quote)).issued
    with pytest.raises(KeysetInactiveError):
        await ledger._sign_blinded_messages([output(ledger, 4)])


@pytest.mark.asyncio
async def test_melt_quote_change_carries_the_output_signatures(ledger):
    melt = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=INVOICE_62_SAT)
    )
    amount = 62 + melt.fee_reserve + 6
    quote, key = await locked_quote(ledger, amount)
    outputs = [output(ledger, 4), output(ledger, 2)]
    change_out = change_output(nut20.generate_keypair()[1])
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=amount, quote_id=quote.quote, pubkey=bytes.fromhex(quote.pubkey))],
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
            change_quote_outputs=[change_out],
        )
    )
    assert result.state == "PAID"
    signed = [s.C_ for s in result.signatures]
    assert [s.amount for s in result.signatures] == [4, 2]
    assert [s.C_ for s in result.melt_quotes[0].change or []] == signed
    stored = await ledger.get_melt_quote(melt.quote)
    assert [s.C_ for s in stored.change or []] == signed
    # Settled ids belong to no pending melt.
    row = await ledger.db.fetchone(
        "SELECT melt_quote FROM mint_quote_id_claims WHERE quote_id = :id",
        {"id": change_out.quote_id},
    )
    assert row is not None and row["melt_quote"] is None


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
    outputs = [output(ledger, 4)]
    change_out = change_output(nut20.generate_keypair()[1])
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=14, quote_id=source.quote, pubkey=bytes.fromhex(source.pubkey))],
        blinded_outputs=[
            TranscriptBlindedOutput(
                amount=4, keyset_id=bytes.fromhex(outputs[0].id), B_=bytes.fromhex(outputs[0].B_)
            )
        ],
        melt_quote_outputs=[TranscriptQuote(amount=8, quote_id=melt.quote)],
        change_quote_outputs=[transcript_change(change_out)],
    )
    melt_events = []
    source_states = []
    submit = ledger.events.submit

    async def record(event):
        if isinstance(event, MeltQuote) and event.quote == melt.quote:
            stored = await ledger.crud.get_mint_quote(quote_id=change_out.quote_id, db=ledger.db)
            melt_events.append((event.state, len(event.change or []), stored is not None))
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
            change_quote_outputs=[change_out],
        )
    )
    assert result.state == "PAID" and len(result.signatures) == 1
    assert result.change_quotes[0] is not None and result.change_quotes[0].amount == 2
    paid = [e for e in melt_events if e[0] == MeltQuoteState.paid]
    assert paid and paid[0] == (MeltQuoteState.paid, 1, True)
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
        mint_quote_inputs=[TranscriptQuote(amount=8, quote_id=source.quote, pubkey=bytes.fromhex(source.pubkey))],
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
async def test_id_held_by_a_mint_quote_is_refused_before_reserving(ledger, monkeypatch):
    melt = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=INVOICE_62_SAT)
    )
    amount = 62 + melt.fee_reserve
    quote, key = await locked_quote(ledger, amount)
    change_out = change_output(nut20.generate_keypair()[1])
    await ledger.crud.store_mint_quote(
        quote=MintQuote(
            quote=change_out.quote_id,
            method="bolt11",
            request="lnbc-held",
            checking_id="held",
            unit="sat",
            amount=1,
            state=MintQuoteState.unpaid,
        ),
        db=ledger.db,
    )
    shape = TransactionShape(
        mint_quote_inputs=[TranscriptQuote(amount=amount, quote_id=quote.quote, pubkey=bytes.fromhex(quote.pubkey))],
        melt_quote_outputs=[TranscriptQuote(amount=amount, quote_id=melt.quote)],
        change_quote_outputs=[transcript_change(change_out)],
    )
    events, backend_calls = [], []
    submit = ledger.events.submit

    async def record(event):
        events.append(event)
        await submit(event)

    async def pay_invoice(*args, **kwargs):
        backend_calls.append(args)
        raise AssertionError("backend called")

    monkeypatch.setattr(ledger.events, "submit", record)
    monkeypatch.setattr(ledger.backends[Method.bolt11][Unit.sat], "pay_invoice", pay_invoice)
    with pytest.raises(TransactionError, match="change quote id already claimed"):
        await ledger.transaction(
            PostTransactionRequest(
                mint_quote_inputs=[
                    TransactionQuoteInput(
                        quote=quote.quote, amount=amount, witness=quote_witness(key, shape, quote.quote)
                    )
                ],
                melt_quote_outputs=[
                    TransactionMeltOutput(quote=melt.quote, fee_reserve=melt.fee_reserve)
                ],
                change_quote_outputs=[change_out],
            )
        )
    assert events == [] and backend_calls == []
    assert (await ledger.get_mint_quote(quote.quote)).mintable == amount
    assert (await ledger.crud.get_melt_quote(quote_id=melt.quote, db=ledger.db)).unpaid
    # The check inside the accepting DB transaction refuses it too.
    with pytest.raises(TransactionError, match="change quote id already claimed"):
        async with ledger.db.connect() as conn:
            await nut_xx._claim_mint_quote_ids(ledger, [change_out.quote_id], None, conn)
    assert not await ledger.db.fetchall("SELECT * FROM mint_quote_id_claims")


@pytest.mark.asyncio
async def test_rpc_state_update_refuses_a_transaction_melt(ledger):
    melt = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=INVOICE_62_SAT)
    )
    await ledger.db.execute(
        "INSERT INTO melt_transactions (melt_quote, unit, mint_quotes, change_outputs, excess)"
        " VALUES (:q, 'sat', '[]', '[]', 0)",
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
        mint_quote_inputs=[TranscriptQuote(amount=8, quote_id=source.quote, pubkey=bytes.fromhex(source.pubkey))],
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
            mint_quote_inputs=[TranscriptQuote(amount=amount, quote_id=quote.quote, pubkey=bytes.fromhex(quote.pubkey))],
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
    assert not await ledger.db.fetchall("SELECT * FROM mint_quote_id_claims")
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
