import asyncio
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import httpx
import pytest

from cashu.core.base import Amount, Method, Unit
from cashu.core.settings import settings
from cashu.lightning.clnrest import CLNRestWallet
from cashu.lightning.fake import FakeWallet
from cashu.lightning.lndrest import LndRestWallet
from cashu.lightning.strike import StrikeWallet
from cashu.mint.events.events import LedgerEventManager
from cashu.mint.ledger import Ledger


@pytest.fixture(scope="session")
def mint():
    """These lifecycle tests do not require a running HTTP mint."""
    yield


def shutdown_ledger(backends=None):
    ledger = object.__new__(Ledger)
    ledger.invoice_listener_tasks = []
    ledger.watchdog_tasks = []
    ledger.regular_tasks = []
    ledger.melt_tasks = set()
    ledger.events = LedgerEventManager()
    ledger.backends = backends or {}
    cast(Any, ledger).crud = object()
    cast(Any, ledger).db = SimpleNamespace(engine=SimpleNamespace(dispose=AsyncMock()))
    return ledger


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_task", [False, True])
async def test_shutdown_awaits_all_tasks_before_closing_resources(
    fail_task, monkeypatch
):
    events = []
    backend = FakeWallet()
    ledger = shutdown_ledger({Method.bolt11: {Unit.sat: backend}})
    tasks = []
    cancelled = set()

    async def background(name):
        try:
            await asyncio.Event().wait()
        finally:
            # Every task must receive cancellation before we wait on any of them.
            cancelled.add(name)
            await asyncio.sleep(0)
            assert cancelled == {"listener", "watchdog", "regular"}
            events.append(name)
            if fail_task and name == "listener":
                raise RuntimeError("background failure")

    for name, collection in (
        ("listener", ledger.invoice_listener_tasks),
        ("watchdog", ledger.watchdog_tasks),
        ("regular", ledger.regular_tasks),
    ):
        task = asyncio.create_task(background(name))
        collection.append(task)
        tasks.append(task)
    await asyncio.sleep(0)

    async def cleanup():
        assert set(events) == {"listener", "watchdog", "regular"}
        events.append("backend")

    async def dispose():
        assert events[-1] == "backend"
        events.append("database")

    monkeypatch.setattr(backend, "cleanup", AsyncMock(side_effect=cleanup))
    ledger.db.engine.dispose.side_effect = dispose
    await asyncio.wait_for(ledger.shutdown_ledger(), timeout=1)

    assert all(task.done() for task in tasks)
    if fail_task:
        assert str(tasks[0].exception()) == "background failure"
    else:
        assert tasks[0].cancelled()
    assert all(task.cancelled() for task in tasks[1:])
    assert not ledger.invoice_listener_tasks
    assert not ledger.watchdog_tasks
    assert not ledger.regular_tasks
    assert events[-2:] == ["backend", "database"]


def test_shutdown_can_repeat_on_different_event_loops(monkeypatch):
    ledger = shutdown_ledger()
    monkeypatch.setattr(ledger, "_startup_keysets", AsyncMock())
    monkeypatch.setattr(ledger, "_check_backends", AsyncMock())
    monkeypatch.setattr(ledger, "dispatch_listeners", AsyncMock(return_value=[]))
    monkeypatch.setattr(ledger, "_check_pending_proofs_and_melt_quotes", AsyncMock())
    monkeypatch.setattr(settings, "mint_watchdog_enabled", False)

    async def lifecycle():
        await ledger.startup_ledger()
        await asyncio.sleep(0)
        await ledger.shutdown_ledger()

    for _ in range(2):
        asyncio.run(lifecycle())
        assert not ledger.regular_tasks
    assert ledger.db.engine.dispose.await_count == 2


@pytest.mark.asyncio
async def test_shutdown_continues_after_backend_cleanup_failure(monkeypatch):
    failing_backend = FakeWallet()
    other_backend = FakeWallet(Unit.usd)
    failing_cleanup = AsyncMock(side_effect=OSError("connection failure"))
    other_cleanup = AsyncMock()
    monkeypatch.setattr(failing_backend, "cleanup", failing_cleanup)
    monkeypatch.setattr(other_backend, "cleanup", other_cleanup)
    ledger = shutdown_ledger(
        {Method.bolt11: {Unit.sat: failing_backend, Unit.usd: other_backend}}
    )

    await ledger.shutdown_ledger()

    failing_cleanup.assert_awaited_once()
    other_cleanup.assert_awaited_once()
    ledger.db.engine.dispose.assert_awaited_once()


@pytest.mark.asyncio
async def test_fakewallet_cleanup_cancels_only_its_own_delayed_payments(monkeypatch):
    monkeypatch.setattr(settings, "fakewallet_brr", True)
    monkeypatch.setattr(settings, "fakewallet_delay_incoming_payment", 3600)
    wallet = FakeWallet()
    other_wallet = FakeWallet()
    await wallet.create_invoice(Amount(Unit.sat, 1))
    await other_wallet.create_invoice(Amount(Unit.sat, 1))
    await asyncio.sleep(0)
    tasks = list(wallet.tasks)
    other_tasks = list(other_wallet.tasks)

    try:
        await wallet.cleanup()
        assert tasks and all(task.cancelled() for task in tasks)
        assert not wallet.tasks
        assert other_tasks and all(not task.done() for task in other_tasks)
        assert wallet.paid_invoices_queue.empty()
        await wallet.cleanup()
    finally:
        await other_wallet.cleanup()


@pytest.mark.asyncio
async def test_fakewallet_forgets_completed_payment_tasks(monkeypatch):
    monkeypatch.setattr(settings, "fakewallet_brr", True)
    monkeypatch.setattr(settings, "fakewallet_delay_incoming_payment", 0)
    wallet = FakeWallet()
    await wallet.create_invoice(Amount(Unit.sat, 1))
    await asyncio.gather(*wallet.tasks)
    await asyncio.sleep(0)

    assert not wallet.tasks
    assert wallet.paid_invoices_queue.qsize() == 1
    await wallet.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize("backend_type", [LndRestWallet, StrikeWallet, CLNRestWallet])
async def test_http_backend_reopens_after_ledger_shutdown(monkeypatch, backend_type):
    monkeypatch.setattr(settings, "mint_lnd_rest_endpoint", "https://lnd.test")
    monkeypatch.setattr(settings, "mint_lnd_rest_macaroon", "00")
    monkeypatch.setattr(settings, "mint_lnd_rest_cert", None)
    monkeypatch.setattr(settings, "mint_clnrest_url", "https://cln.test")
    monkeypatch.setattr(settings, "mint_clnrest_rune", "test-rune")
    monkeypatch.setattr(settings, "mint_clnrest_cert", None)
    monkeypatch.setattr(settings, "mint_strike_key", "test-key")
    real_client = httpx.AsyncClient
    requests = []

    def respond(request):
        data: Any
        requests.append(request)
        if backend_type is LndRestWallet:
            assert request.headers["Grpc-Metadata-macaroon"] == "00"
            data = {"balance": "1"}
        elif backend_type is CLNRestWallet:
            assert request.headers["rune"] == "test-rune"
            data = {"channels": [{"our_amount_msat": 1000}]}
        else:
            assert request.headers["Authorization"] == "Bearer test-key"
            data = [{"currency": "BTC", "total": "0.00000001"}]
        return httpx.Response(200, json=data)

    def create_client(**kwargs):
        return real_client(transport=httpx.MockTransport(respond), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", create_client)
    backend = backend_type(Unit.sat)
    ledger = shutdown_ledger({Method.bolt11: {Unit.sat: backend}})
    first_client = backend.client
    monkeypatch.setattr(ledger, "_startup_keysets", AsyncMock())
    monkeypatch.setattr(ledger, "dispatch_listeners", AsyncMock(return_value=[]))
    monkeypatch.setattr(ledger, "_check_pending_proofs_and_melt_quotes", AsyncMock())
    monkeypatch.setattr(settings, "mint_watchdog_enabled", False)
    try:
        await ledger.startup_ledger()
        assert backend.client is first_client
        await ledger.shutdown_ledger()
        assert first_client.is_closed

        await ledger.startup_ledger()
        assert backend.client is not first_client
        assert not backend.client.is_closed
        assert len(requests) == 2
    finally:
        await ledger.shutdown_ledger()
    assert backend.client.is_closed


def test_fakewallet_invoice_stream_can_restart_on_another_loop(monkeypatch):
    monkeypatch.setattr(settings, "fakewallet_brr", True)
    monkeypatch.setattr(settings, "fakewallet_delay_incoming_payment", 0)
    backend = FakeWallet()

    async def lifecycle():
        stream = backend.paid_invoices_stream()
        notification = asyncio.create_task(stream.__anext__())
        # Bind the empty queue to this event loop before publishing the invoice.
        await asyncio.sleep(0)
        try:
            invoice = await backend.create_invoice(Amount(Unit.sat, 1))
            assert (
                await asyncio.wait_for(notification, timeout=1) == invoice.checking_id
            )
        finally:
            await stream.aclose()
            await backend.cleanup()

    for _ in range(2):
        asyncio.run(lifecycle())


@pytest.mark.asyncio
@pytest.mark.parametrize("finish_payment", [False, True])
async def test_shutdown_owns_background_melts(monkeypatch, finish_payment):
    from cashu.core.base import MeltQuote, MeltQuoteState

    ledger = shutdown_ledger()
    quote = MeltQuote(
        quote="pending-melt",
        method="bolt11",
        unit="sat",
        request="lnbc1",
        checking_id="payment-hash",
        amount=1,
        fee_reserve=1,
        state=MeltQuoteState.pending,
    )
    stopped = asyncio.Event()
    complete = asyncio.Event()

    async def execute(*args):
        try:
            if not finish_payment:
                await complete.wait()
        finally:
            # Payment finalization must complete before the database closes.
            ledger.db.engine.dispose.assert_not_awaited()
            stopped.set()

    monkeypatch.setattr(ledger, "_prepare_melt", AsyncMock(return_value=quote))
    monkeypatch.setattr(ledger, "_execute_melt_payment", execute)
    response = await ledger.async_melt(proofs=[], quote=quote.quote)
    tasks = list(ledger.melt_tasks)
    assert len(tasks) == 1
    assert response.state == "PENDING"
    await asyncio.sleep(0)

    if finish_payment:
        await asyncio.gather(*tasks)
        assert not ledger.melt_tasks
    shutdown = asyncio.create_task(ledger.shutdown_ledger())
    await asyncio.sleep(0)
    if not finish_payment:
        assert not shutdown.done()
        ledger.db.engine.dispose.assert_not_awaited()
        complete.set()
    await asyncio.wait_for(shutdown, timeout=1)

    assert stopped.is_set()
    assert not ledger.melt_tasks
    assert tasks[0].done()
    assert not tasks[0].cancelled()
    ledger.db.engine.dispose.assert_awaited_once()


@pytest.mark.asyncio
async def test_shutdown_cancels_websocket_snapshots_and_notifications(monkeypatch):
    from cashu.core.base import MintQuote, MintQuoteState
    from cashu.core.json_rpc.base import JSONRPCSubscriptionKinds

    ledger = shutdown_ledger()
    websocket = SimpleNamespace(send_text=AsyncMock())
    client = ledger.events.add_client(
        cast(Any, websocket), ledger.db, cast(Any, object())
    )
    finished = set()

    async def snapshot(*args):
        try:
            await asyncio.Event().wait()
        finally:
            finished.add("snapshot")

    async def send(*args):
        try:
            await asyncio.Event().wait()
        finally:
            finished.add("notification")

    monkeypatch.setattr(client, "_init_subscriptions", snapshot)
    websocket.send_text.side_effect = send
    quote = MintQuote(
        quote="mint-quote",
        method="bolt11",
        request="lnbc1",
        checking_id="payment-hash",
        unit="sat",
        amount=1,
        state=MintQuoteState.paid,
    )
    client.add_subscription(
        JSONRPCSubscriptionKinds.BOLT11_MINT_QUOTE, [quote.quote], "sub-1"
    )
    await ledger.events.submit(quote)
    tasks = list(client.tasks)
    assert len(tasks) == 2
    await asyncio.sleep(0)

    async def dispose():
        assert finished == {"snapshot", "notification"}

    ledger.db.engine.dispose.side_effect = dispose
    await ledger.shutdown_ledger()

    assert all(task.cancelled() for task in tasks)
    assert not client.tasks
    assert not ledger.events.clients


@pytest.mark.asyncio
async def test_websocket_disconnect_awaits_its_tasks(monkeypatch):
    from fastapi import WebSocketDisconnect

    import cashu.mint.router as router
    from cashu.mint.events.client import LedgerEventClientManager

    ledger = shutdown_ledger()
    websocket = SimpleNamespace(client_state=SimpleNamespace(name="DISCONNECTED"))
    stopped = asyncio.Event()

    async def background():
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    async def start(client):
        client.create_task(background())
        await asyncio.sleep(0)
        raise WebSocketDisconnect()

    monkeypatch.setattr(router, "ledger", ledger)
    monkeypatch.setattr(router, "limit_websocket", lambda ws: None)
    monkeypatch.setattr(LedgerEventClientManager, "start", start)
    await router.websocket_endpoint(cast(Any, websocket))

    assert stopped.is_set()
    assert not ledger.events.clients


def test_event_clients_belong_to_one_ledger():
    first = LedgerEventManager()
    second = LedgerEventManager()
    first.add_client(cast(Any, object()), cast(Any, object()), cast(Any, object()))
    assert len(first.clients) == 1
    assert not second.clients


@pytest.mark.asyncio
async def test_spark_cleanup_disconnects_and_allows_reconnection(monkeypatch, tmp_path):
    import cashu.lightning.sparkl2 as spark

    monkeypatch.setattr(settings, "cashu_dir", str(tmp_path))
    monkeypatch.setattr(settings, "mint_spark_mnemonic", "test-mnemonic")
    monkeypatch.setattr(settings, "mint_spark_network", "MAINNET")
    monkeypatch.setattr(
        spark.breez_sdk_spark,
        "default_config",
        lambda network: SimpleNamespace(prefer_spark_over_lightning=False),
    )
    first_sdk = SimpleNamespace(add_event_listener=AsyncMock(), disconnect=AsyncMock())
    second_sdk = SimpleNamespace(add_event_listener=AsyncMock(), disconnect=AsyncMock())
    connect = AsyncMock(side_effect=[first_sdk, second_sdk])
    monkeypatch.setattr(spark.breez_sdk_spark, "connect", connect)
    wallet = spark.SparkL2Wallet(Unit.sat)
    await wallet._ensure_sdk()
    old_queue = wallet.payment_queue
    assert wallet.sdk is first_sdk

    await wallet.cleanup()
    first_sdk.disconnect.assert_awaited_once()
    assert wallet.sdk is None
    assert wallet.listener is None
    assert wallet.payment_queue is not old_queue
    await wallet.cleanup()
    first_sdk.disconnect.assert_awaited_once()

    await wallet._ensure_sdk()
    assert wallet.sdk is second_sdk
    assert wallet.listener is not None
    await wallet.cleanup()
    second_sdk.disconnect.assert_awaited_once()
