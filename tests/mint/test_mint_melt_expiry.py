import time
from unittest.mock import AsyncMock, Mock

import pytest

from cashu.core.base import Method, Unit
from cashu.core.errors import QuoteExpiredError
from cashu.core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from cashu.core.settings import settings
from cashu.lightning.base import (
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    PaymentStatusResult,
)
from cashu.lightning.lnd_grpc.lnd_grpc import LndRPCWallet
from cashu.lightning.lndrest import LndRestWallet
from cashu.mint.ledger import Ledger
from tests.helpers import get_fake_invoice, is_regtest
from tests.mint.invoice_amount_helpers import make_outputs, unblind_promises

pytestmark = [pytest.mark.asyncio, pytest.mark.skipif(is_regtest, reason="fake wallet")]


async def issue_proofs(ledger: Ledger):
    quote = await ledger.mint_quote(PostMintQuoteRequest(amount=8, unit="sat"))
    await ledger.get_mint_quote(quote.quote)
    outputs, secrets = make_outputs(ledger, 8, Unit.sat)
    promises = await ledger.mint(quote_id=quote.quote, outputs=outputs)
    return unblind_promises(ledger, promises, secrets)


@pytest.mark.parametrize("prefer_async", [False, True], ids=["sync", "async"])
async def test_expired_melt_quote_does_not_lock_proofs(
    ledger: Ledger, monkeypatch, prefer_async
):
    proofs = await issue_proofs(ledger)
    now = int(time.time())
    monkeypatch.setattr(settings, "melt_quote_ttl", 60)
    quote = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=get_fake_invoice(2, date=now))
    )
    outputs, _ = make_outputs(ledger, 1, Unit.sat)
    backend = ledger.backends[Method.bolt11][Unit.sat]
    payment = AsyncMock(return_value=PaymentResponse(result=PaymentResult.PENDING))
    set_pending = AsyncMock(wraps=ledger.db_write.verify_and_set_melt_quote_pending)
    monkeypatch.setattr(backend, "pay_invoice", payment)
    monkeypatch.setattr(
        ledger.db_write, "verify_and_set_melt_quote_pending", set_pending
    )
    monkeypatch.setattr("cashu.mint.ledger.time.time", lambda: now + 120)

    melt = ledger.async_melt if prefer_async else ledger.melt
    with pytest.raises(QuoteExpiredError, match="quote expired"):
        await melt(proofs=proofs, quote=quote.quote, outputs=outputs)

    payment.assert_not_awaited()
    set_pending.assert_not_awaited()
    assert (await ledger.get_melt_quote(quote.quote)).unpaid
    assert all(
        s.unspent for s in await ledger.db_read.get_proofs_states([p.Y for p in proofs])
    )
    assert (
        await ledger.crud.get_blinded_messages_melt_id(
            db=ledger.db, melt_id=quote.quote
        )
        == []
    )


@pytest.mark.parametrize(
    "backend_cls", [LndRestWallet, LndRPCWallet], ids=["rest", "grpc"]
)
@pytest.mark.parametrize("prepared", [False, True], ids=["before-lock", "after-lock"])
async def test_expired_invoice_does_not_strand_proofs(
    ledger: Ledger, monkeypatch, backend_cls, prepared
):
    proofs = await issue_proofs(ledger)
    now = int(time.time())
    monkeypatch.setattr(settings, "melt_quote_ttl", 7200)
    quote = await ledger.melt_quote(
        PostMeltQuoteRequest(
            unit="sat", request=get_fake_invoice(2, date=now, expiry=60)
        )
    )
    outputs, _ = make_outputs(ledger, 1, Unit.sat)
    balance_before, _ = await ledger.crud.get_balance(
        db=ledger.db, keyset=ledger.keyset
    )
    pending = None
    if prepared:
        pending = await ledger._prepare_melt(
            proofs=proofs, quote=quote.quote, outputs=outputs
        )
        assert pending.pending
        assert all(
            s.pending
            for s in await ledger.db_read.get_proofs_states([p.Y for p in proofs])
        )

    backend = object.__new__(backend_cls)
    backend.unit = Unit.sat
    backend.supports_mpp = True
    backend.endpoint = "lnd.test"
    backend.combined_creds = None
    backend.client = Mock()
    payment = AsyncMock(wraps=backend.pay_invoice)
    monkeypatch.setattr(backend, "pay_invoice", payment)
    status = AsyncMock(return_value=PaymentStatus(result=PaymentStatusResult.NOT_FOUND))
    monkeypatch.setattr(backend, "get_payment_status", status)
    monkeypatch.setattr(ledger, "backends", {Method.bolt11: {Unit.sat: backend}})
    channel = Mock(side_effect=AssertionError("must not contact LND"))
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.grpc.aio.secure_channel", channel
    )
    monkeypatch.setattr("cashu.mint.ledger.time.time", lambda: now + 120)

    with pytest.raises(QuoteExpiredError, match="invoice expired"):
        if pending is not None:
            await ledger._execute_melt_payment(pending, proofs, outputs)
        else:
            await ledger.melt(proofs=proofs, quote=quote.quote, outputs=outputs)

    payment.assert_not_awaited()
    status.assert_not_awaited()
    channel.assert_not_called()
    assert backend.client.mock_calls == []
    assert (await ledger.get_melt_quote(quote.quote)).unpaid
    assert all(
        s.unspent for s in await ledger.db_read.get_proofs_states([p.Y for p in proofs])
    )
    assert (
        await ledger.crud.get_blinded_messages_melt_id(
            db=ledger.db, melt_id=quote.quote
        )
        == []
    )
    balance_after, _ = await ledger.crud.get_balance(db=ledger.db, keyset=ledger.keyset)
    assert balance_after == balance_before


@pytest.mark.parametrize(
    "result", [PaymentStatusResult.NOT_FOUND, PaymentStatusResult.SETTLED]
)
async def test_expired_pending_quote_still_uses_backend_status(
    ledger: Ledger, monkeypatch, result
):
    proofs = await issue_proofs(ledger)
    now = int(time.time())
    monkeypatch.setattr(settings, "melt_quote_ttl", 60)
    quote = await ledger.melt_quote(
        PostMeltQuoteRequest(
            unit="sat", request=get_fake_invoice(2, date=now, expiry=60)
        )
    )
    await ledger._prepare_melt(proofs=proofs, quote=quote.quote)
    backend = ledger.backends[Method.bolt11][Unit.sat]
    status = AsyncMock(return_value=PaymentStatus(result=result))
    monkeypatch.setattr(backend, "get_payment_status", status)
    monkeypatch.setattr("cashu.mint.ledger.time.time", lambda: now + 120)

    resolved = await ledger.get_melt_quote(quote.quote)

    status.assert_awaited_once()
    states = await ledger.db_read.get_proofs_states([p.Y for p in proofs])
    if result == PaymentStatusResult.SETTLED:
        assert resolved.paid
        assert all(state.spent for state in states)
    else:
        assert resolved.pending
        assert all(state.pending for state in states)
