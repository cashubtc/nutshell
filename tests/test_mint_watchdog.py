import asyncio
import datetime
import signal
from copy import copy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from cashu.core.base import Amount, MeltQuoteState, MintBalanceLogEntry, Unit
from cashu.core.models import PostMeltQuoteRequest
from cashu.core.settings import settings
from cashu.lightning.base import StatusResponse
from cashu.mint.ledger import Ledger
from cashu.payment import payment_method_registry
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    get_real_invoice,
    is_fake,
    pay_if_regtest,
)


@pytest_asyncio.fixture(scope="function")
async def wallet():
    wallet = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet",
        name="wallet",
    )
    await wallet.load_mint()
    yield wallet


@pytest.mark.asyncio
async def test_check_balances_and_abort(ledger: Ledger):
    ok = await ledger.check_balances_and_abort(
        None,
        Amount(Unit.sat, 0),
        Amount(Unit.sat, 0),
        Amount(Unit.sat, 0),
    )
    assert ok


@pytest.mark.asyncio
async def test_dispatch_watchdogs_starts_abort_monitor(ledger: Ledger):
    tasks = await ledger.dispatch_watchdogs()
    assert any(
        task.get_coro().__qualname__ == "LedgerWatchdog.monitor_abort_queue"
        for task in tasks
    )
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_watchdog_skips_unit_with_unreported_reserves(ledger, monkeypatch):
    plugin = copy(payment_method_registry.get("bolt11"))
    plugin.method = "onchain"
    plugin.supports_balance = False
    monkeypatch.setitem(payment_method_registry._plugins, plugin.method, plugin)
    monkeypatch.setitem(ledger.backends, "onchain", {Unit.sat: object()})
    checker = AsyncMock()
    monkeypatch.setattr(ledger, "dispatch_unit_checker", checker)
    ledger.abort_queue = asyncio.Queue()

    tasks = await ledger.dispatch_watchdogs()
    try:
        await asyncio.gather(*tasks[:-1])
        # The legacy sat backend must also be skipped, while USD remains watched.
        checker.assert_awaited_once()
        assert checker.await_args.args[0] == Unit.usd
        assert ledger.abort_queue.empty()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("shared_source", [False, True])
async def test_watchdog_aggregates_reserves_once_per_funding_source(
    ledger, monkeypatch, shared_source
):
    plugin = copy(payment_method_registry.get("bolt11"))
    plugin.method = "testpay"
    # Separate Python objects may report the same wallet balance.
    monkeypatch.setattr(
        plugin, "funding_source_id", lambda backend, unit: backend.source
    )
    monkeypatch.setitem(payment_method_registry._plugins, "testpay", plugin)
    monkeypatch.setitem(payment_method_registry._plugins, "otherpay", plugin)
    first = SimpleNamespace(source="wallet-1")
    second = SimpleNamespace(source="wallet-1" if shared_source else "wallet-2")
    monkeypatch.setattr(
        ledger,
        "backends",
        {"testpay": {Unit.sat: first}, "otherpay": {Unit.sat: second}},
    )
    status = AsyncMock(
        side_effect=lambda backend: StatusResponse(
            balance=Amount(
                Unit.sat, 164 if shared_source else 100 if backend is first else 64
            )
        )
    )
    monkeypatch.setattr(plugin, "status", status)
    monkeypatch.setattr(settings, "mint_watchdog_balance_check_interval_seconds", 3600)
    # Another method issued 64 sat since the previous check. Reserves grew by
    # the same amount, so the aggregate reserve gap has not shrunk.
    await ledger.crud.store_balance_log(
        Amount(Unit.sat, 100), Amount(Unit.sat, 80), Amount(Unit.sat, 0), db=ledger.db
    )
    await ledger.db.execute(
        "UPDATE balance_log SET time = :time", {"time": ledger.db.to_timestamp("1000")}
    )
    monkeypatch.setattr(
        ledger,
        "get_unit_balance_and_fees",
        AsyncMock(return_value=(Amount(Unit.sat, 144), Amount(Unit.sat, 0))),
    )
    stored = asyncio.Event()
    store_log = ledger.crud.store_balance_log
    recorded_balances = []

    async def record_balance(*args, **kwargs):
        await store_log(*args, **kwargs)
        recorded_balances.append(args)
        stored.set()

    monkeypatch.setattr(ledger.crud, "store_balance_log", record_balance)
    ledger.abort_queue = asyncio.Queue()
    # Keep aborts observable without allowing a regression to kill pytest.
    monkeypatch.setattr(ledger, "monitor_abort_queue", asyncio.Event().wait)
    tasks = await ledger.dispatch_watchdogs()
    try:
        assert len(tasks) == 2  # One unit checker and the abort monitor.
        await asyncio.wait_for(stored.wait(), 5)
        assert recorded_balances == [
            (Amount(Unit.sat, 164), Amount(Unit.sat, 144), Amount(Unit.sat, 0))
        ]
        assert status.await_count == (1 if shared_source else 2)
        assert ledger.abort_queue.empty()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("raises", [False, True])
async def test_watchdog_does_not_compare_or_store_incomplete_balance(
    ledger, monkeypatch, raises
):
    plugin = copy(payment_method_registry.get("bolt11"))
    queried = asyncio.Event()

    async def unavailable(backend):
        queried.set()
        if raises:
            raise ConnectionError("backend unavailable")
        return StatusResponse(
            balance=Amount(Unit.sat, 0), error_message="backend unavailable"
        )

    monkeypatch.setattr(plugin, "status", unavailable)
    check = AsyncMock()
    store_log = AsyncMock()
    monkeypatch.setattr(ledger, "check_balances_and_abort", check)
    monkeypatch.setattr(ledger.crud, "store_balance_log", store_log)
    monkeypatch.setattr(settings, "mint_watchdog_balance_check_interval_seconds", 3600)
    task = asyncio.create_task(
        ledger.dispatch_unit_checker(Unit.sat, {"source": (plugin, object())})
    )
    try:
        await asyncio.wait_for(queried.wait(), 5)
        await asyncio.sleep(0)
        check.assert_not_awaited()
        store_log.assert_not_awaited()
        assert not task.done()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_check_balances_and_abort_insolvency(ledger: Ledger):
    ledger.abort_queue = asyncio.Queue()
    ok = await ledger.check_balances_and_abort(
        None,
        Amount(Unit.sat, 100),
        Amount(Unit.sat, 1000),
        Amount(Unit.sat, 0),
    )
    assert not ok
    assert not ledger.abort_queue.empty()


@pytest.mark.asyncio
async def test_check_balances_and_abort_delta_shrink_aborts(ledger: Ledger):
    ledger.abort_queue = asyncio.Queue()
    last_balance_log_entry = MintBalanceLogEntry(
        unit=Unit.sat,
        backend_balance=Amount(Unit.sat, 1064),
        keyset_balance=Amount(Unit.sat, 900),
        keyset_fees_paid=Amount(Unit.sat, 0),
        time=datetime.datetime.now(),
    )
    ok = await ledger.check_balances_and_abort(
        last_balance_log_entry,
        Amount(Unit.sat, 1064),
        Amount(Unit.sat, 964),
        Amount(Unit.sat, 0),
    )
    assert not ok
    assert not ledger.abort_queue.empty()


@pytest.mark.asyncio
async def test_monitor_abort_queue_signals_sigterm(ledger: Ledger, monkeypatch):
    ledger.abort_queue = asyncio.Queue()
    signals = []

    class _Abort(Exception):
        pass

    def fake_raise_signal(sig):
        signals.append(sig)
        raise _Abort()

    monkeypatch.setattr(signal, "raise_signal", fake_raise_signal)
    monkeypatch.setattr(settings, "mint_watchdog_ignore_mismatch", False)

    await ledger.abort_queue.put(True)
    with pytest.raises(_Abort):
        await ledger.monitor_abort_queue()
    assert signals == [signal.SIGTERM]


@pytest.mark.asyncio
async def test_monitor_abort_queue_ignores_mismatch(ledger: Ledger, monkeypatch):
    ledger.abort_queue = asyncio.Queue()
    signals = []

    def fake_raise_signal(sig):
        signals.append(sig)

    monkeypatch.setattr(signal, "raise_signal", fake_raise_signal)
    monkeypatch.setattr(settings, "mint_watchdog_ignore_mismatch", True)

    await ledger.abort_queue.put(True)
    task = asyncio.create_task(ledger.monitor_abort_queue())
    for _ in range(100):
        if ledger.abort_queue.empty():
            break
        await asyncio.sleep(0.01)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert signals == []


@pytest.mark.asyncio
async def test_balance_update_on_mint(wallet: Wallet, ledger: Ledger):
    balance_before, fees_paid_before = await ledger.get_unit_balance_and_fees(
        Unit.sat, ledger.db
    )
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    balance_after, fees_paid_after = await ledger.get_unit_balance_and_fees(
        Unit.sat, ledger.db
    )
    assert balance_after == balance_before + 64
    assert fees_paid_after == fees_paid_before


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only works with Regtest")
async def test_balance_update_on_test_melt_internal(wallet: Wallet, ledger: Ledger):
    settings.fakewallet_brr = False
    # mint twice so we have enough to pay the second invoice back
    mint_quote = await wallet.request_mint(128)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(128, quote_id=mint_quote.quote)
    assert wallet.balance == 128

    balance_before, fees_paid_before = await ledger.get_unit_balance_and_fees(
        Unit.sat, ledger.db
    )

    # create a mint quote so that we can melt to it internally
    payment_amount = 64
    mint_quote_to_pay = await wallet.request_mint(payment_amount)
    invoice_payment_request = mint_quote_to_pay.request

    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice_payment_request, unit="sat")
    )

    melt_quote_response_pre_payment = await wallet.get_melt_quote(melt_quote.quote)
    assert (
        not melt_quote_response_pre_payment.state == MeltQuoteState.paid.value
    ), "melt quote should not be paid"
    assert melt_quote_response_pre_payment.amount == payment_amount

    melt_quote_pre_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert (
        melt_quote_pre_payment.state != MeltQuoteState.paid
    ), "melt quote should not be paid"
    assert melt_quote_pre_payment.state == MeltQuoteState.unpaid

    _, send_proofs = await wallet.swap_to_send(wallet.proofs, payment_amount)
    await ledger.melt(proofs=send_proofs, quote=melt_quote.quote)
    await wallet.invalidate(send_proofs, check_spendable=True)
    assert wallet.balance == 64

    melt_quote_post_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert (
        melt_quote_post_payment.state == MeltQuoteState.paid
    ), "melt quote should be paid"

    balance_after, fees_paid_after = await ledger.get_unit_balance_and_fees(
        Unit.sat, ledger.db
    )

    # balance should have dropped
    assert balance_after == balance_before - payment_amount
    assert fees_paid_after == fees_paid_before
    # now mint
    await wallet.mint(payment_amount, quote_id=mint_quote_to_pay.quote)
    assert wallet.balance == 128

    balance_after, fees_paid_after = await ledger.get_unit_balance_and_fees(
        Unit.sat, ledger.db
    )

    # balance should be back
    assert balance_after == balance_before
    assert fees_paid_after == fees_paid_before


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only works with Regtest")
async def test_balance_update_on_melt_external(wallet: Wallet, ledger: Ledger):
    # mint twice so we have enough to pay the second invoice back
    mint_quote = await wallet.request_mint(128)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(128, quote_id=mint_quote.quote)
    assert wallet.balance == 128

    balance_before, fees_paid_before = await ledger.get_unit_balance_and_fees(
        Unit.sat, ledger.db
    )

    invoice_dict = get_real_invoice(64)
    invoice_payment_request = invoice_dict["payment_request"]

    mint_quote = await wallet.melt_quote(invoice_payment_request)

    total_amount = mint_quote.amount + mint_quote.fee_reserve
    _, send_proofs = await wallet.swap_to_send(wallet.proofs, total_amount)
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice_payment_request, unit="sat")
    )

    melt_quote_response_pre_payment = await wallet.get_melt_quote(melt_quote.quote)
    assert (
        melt_quote_response_pre_payment.state == MeltQuoteState.unpaid.value
    ), "melt quote should not be paid"
    assert melt_quote_response_pre_payment.amount == melt_quote.amount

    melt_quote_resp = await ledger.melt(proofs=send_proofs, quote=melt_quote.quote)
    fees_paid = melt_quote.fee_reserve - (
        sum([b.amount for b in melt_quote_resp.change]) if melt_quote_resp.change else 0
    )

    melt_quote_post_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert (
        melt_quote_post_payment.state == MeltQuoteState.paid
    ), "melt quote should be paid"

    balance_after, fees_paid_after = await ledger.get_unit_balance_and_fees(
        Unit.sat, ledger.db
    )
    assert balance_after == balance_before - 64 - fees_paid
    assert fees_paid_after == fees_paid_before
