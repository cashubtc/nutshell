import asyncio
import datetime
import signal

import pytest
import pytest_asyncio

from cashu.core.base import Amount, MeltQuoteState, Method, MintBalanceLogEntry, Unit
from cashu.core.models import PostMeltQuoteRequest
from cashu.core.settings import settings
from cashu.lightning.base import StatusResponse
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    get_real_invoice,
    is_fake,
    is_regtest,
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
        ledger.backends[Method.bolt11][Unit.sat],
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
async def test_check_balances_and_abort_insolvency(ledger: Ledger):
    ledger.abort_queue = asyncio.Queue()
    ok = await ledger.check_balances_and_abort(
        ledger.backends[Method.bolt11][Unit.sat],
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
        ledger.backends[Method.bolt11][Unit.sat],
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


@pytest.mark.asyncio
async def test_dispatch_backend_checker_survives_errors(ledger: Ledger, monkeypatch):
    """A failing balance check must not kill the checker task."""
    backend = ledger.backends[Method.bolt11][Unit.sat]
    ledger.check_events[(Method.bolt11, Unit.sat)] = asyncio.Event()
    monkeypatch.setattr(settings, "mint_watchdog_balance_check_interval_seconds", 0.05)

    status_calls = 0
    original_status = backend.status

    async def failing_status():
        nonlocal status_calls
        status_calls += 1
        if status_calls == 1:
            raise Exception("transient backend error")
        return await original_status()

    monkeypatch.setattr(backend, "status", failing_status)

    checks = 0

    async def counting_check(*args, **kwargs):
        nonlocal checks
        checks += 1
        return True

    monkeypatch.setattr(ledger, "check_balances_and_abort", counting_check)

    task = asyncio.create_task(
        ledger.dispatch_backend_checker(Method.bolt11, Unit.sat, backend)
    )
    await asyncio.sleep(0.3)
    assert not task.done(), "checker task died after a failed balance check"
    assert checks >= 2, "checker task did not keep checking after a failure"
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_trigger_balance_check_wakes_checker(ledger: Ledger, monkeypatch):
    monkeypatch.setattr(settings, "mint_watchdog_enabled", True)
    monkeypatch.setattr(settings, "mint_watchdog_balance_check_interval_seconds", 600)
    backend = ledger.backends[Method.bolt11][Unit.sat]
    ledger.check_events[(Method.bolt11, Unit.sat)] = asyncio.Event()

    checks = 0

    async def counting_check(*args, **kwargs):
        nonlocal checks
        checks += 1
        return True

    monkeypatch.setattr(ledger, "check_balances_and_abort", counting_check)

    task = asyncio.create_task(
        ledger.dispatch_backend_checker(Method.bolt11, Unit.sat, backend)
    )
    try:
        # wait for the initial check
        for _ in range(200):
            if checks >= 1:
                break
            await asyncio.sleep(0.01)
        assert checks == 1

        ledger.trigger_balance_check(Method.bolt11, Unit.sat)
        for _ in range(200):
            if checks >= 2:
                break
            await asyncio.sleep(0.01)
        assert checks >= 2, "triggered balance check did not wake up the checker"
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_trigger_balance_check_noop_when_disabled(ledger: Ledger, monkeypatch):
    monkeypatch.setattr(settings, "mint_watchdog_enabled", False)
    event = asyncio.Event()
    ledger.check_events[(Method.bolt11, Unit.sat)] = event
    ledger.trigger_balance_check(Method.bolt11, Unit.sat)
    assert not event.is_set()


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only works with FakeWallet")
async def test_melt_triggers_watchdog_check(
    wallet: Wallet, ledger: Ledger, monkeypatch
):
    """Finalizing a melt must summon the watchdog for an immediate balance check."""
    monkeypatch.setattr(settings, "mint_watchdog_enabled", True)
    monkeypatch.setattr(settings, "mint_watchdog_balance_check_interval_seconds", 600)
    # don't SIGTERM the test process if the fake backend balance is too low
    monkeypatch.setattr(settings, "mint_watchdog_ignore_mismatch", True)

    # give the fake backend a huge balance so the pre-melt solvency gate passes
    backend = ledger.backends[Method.bolt11][Unit.sat]

    async def rich_status():
        return StatusResponse(error_message=None, balance=Amount(Unit.sat, 2**40))

    monkeypatch.setattr(backend, "status", rich_status)

    checks = 0

    async def counting_check(*args, **kwargs):
        nonlocal checks
        checks += 1
        return True

    monkeypatch.setattr(ledger, "check_balances_and_abort", counting_check)

    tasks = await ledger.dispatch_watchdogs()
    try:
        # wait for the initial checks on startup to settle
        for _ in range(200):
            if checks >= 1:
                break
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.2)
        checks_before = checks

        mint_quote = await wallet.request_mint(64)
        await pay_if_regtest(mint_quote.request)
        await wallet.mint(64, quote_id=mint_quote.quote)
        assert wallet.balance == 64
        assert checks == checks_before, "minting should not trigger a balance check"

        # melt internally
        mint_quote_to_pay = await wallet.request_mint(32)
        melt_quote = await ledger.melt_quote(
            PostMeltQuoteRequest(request=mint_quote_to_pay.request, unit="sat")
        )
        _, send_proofs = await wallet.swap_to_send(wallet.proofs, 32)
        await ledger.melt(proofs=send_proofs, quote=melt_quote.quote)

        melt_quote_post_payment = await ledger.get_melt_quote(melt_quote.quote)
        assert melt_quote_post_payment.state == MeltQuoteState.paid

        for _ in range(300):
            if checks > checks_before:
                break
            await asyncio.sleep(0.01)
        assert checks > checks_before, "melt did not trigger an immediate balance check"
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only works with FakeWallet")
async def test_melt_refused_when_insolvent(wallet: Wallet, ledger: Ledger, monkeypatch):
    """The pre-melt solvency gate must refuse melts when the mint is insolvent."""
    monkeypatch.setattr(settings, "mint_watchdog_enabled", True)

    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    # the fake backend is broke: the issued balance exceeds the backend balance
    backend = ledger.backends[Method.bolt11][Unit.sat]

    async def broke_status():
        return StatusResponse(error_message=None, balance=Amount(Unit.sat, 1))

    monkeypatch.setattr(backend, "status", broke_status)
    event = asyncio.Event()
    ledger.check_events[(Method.bolt11, Unit.sat)] = event

    mint_quote_to_pay = await wallet.request_mint(32)
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=mint_quote_to_pay.request, unit="sat")
    )
    _, send_proofs = await wallet.swap_to_send(wallet.proofs, 32)

    with pytest.raises(Exception, match="balance mismatch"):
        await ledger.melt(proofs=send_proofs, quote=melt_quote.quote)

    # the refusal must wake up the watchdog to confirm and shut down the mint
    assert event.is_set()

    # the quote is still unpaid and the proofs were never set pending
    melt_quote_post = await ledger.get_melt_quote(melt_quote.quote)
    assert melt_quote_post.state == MeltQuoteState.unpaid
    states = await wallet.check_proof_state(send_proofs)
    assert all([s.unspent for s in states.states])
