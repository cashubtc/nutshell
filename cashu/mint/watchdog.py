import asyncio
import signal
from typing import Dict, List, Optional, Tuple

from loguru import logger

from cashu.core.db import Connection, Database

from ..core.base import Amount, Method, MintBalanceLogEntry, Unit
from ..core.settings import settings
from ..lightning.base import LightningBackend
from .protocols import SupportsBackends, SupportsDb


class LedgerWatchdog(SupportsDb, SupportsBackends):
    watcher_db: Database
    abort_queue: asyncio.Queue = asyncio.Queue(0)
    check_events: Dict[Tuple[Method, Unit], asyncio.Event]

    def __init__(self) -> None:
        self.watcher_db = Database(self.db.name, self.db.db_location)
        self.check_events = {}
        return

    async def get_unit_balance_and_fees(
        self,
        unit: Unit,
        db: Database,
        conn: Optional[Connection] = None,
    ) -> Tuple[Amount, Amount]:
        keysets = await self.crud.get_keyset(db=db, unit=unit.name, conn=conn)
        balance = Amount(unit, 0)
        fees_paid = Amount(unit, 0)
        for keyset in keysets:
            balance_update = await self.crud.get_balance(keyset, db=db, conn=conn)
            balance += balance_update[0]
            fees_paid += balance_update[1]

        return balance, fees_paid

    async def dispatch_watchdogs(self) -> List[asyncio.Task]:
        tasks = []
        for method, unitbackends in self.backends.items():
            for unit, backend in unitbackends.items():
                self.check_events[(method, unit)] = asyncio.Event()
                tasks.append(
                    asyncio.create_task(
                        self.dispatch_backend_checker(method, unit, backend)
                    )
                )
        tasks.append(asyncio.create_task(self.monitor_abort_queue()))
        if settings.mint_watchdog_ignore_mismatch:
            logger.warning(
                "MINT_WATCHDOG_IGNORE_MISMATCH is set: the watchdog will only log"
                " balance mismatches but will NOT shut down the mint. The mint is"
                " not protected against inflation."
            )
        return tasks

    async def monitor_abort_queue(self):
        while True:
            await self.abort_queue.get()
            if settings.mint_watchdog_ignore_mismatch:
                logger.warning(
                    "Ignoring balance mismatch due to MINT_WATCHDOG_IGNORE_MISMATCH setting"
                )
                continue
            logger.error(
                "Shutting down the mint due to balance mismatch. Fix the balance mismatch and restart the mint or set MINT_WATCHDOG_IGNORE_MISMATCH=True to ignore the mismatch."
            )
            signal.raise_signal(signal.SIGTERM)

    async def get_balance(self, unit: Unit) -> Tuple[Amount, Amount]:
        """Returns the balance of the mint for this unit."""
        return await self.get_unit_balance_and_fees(unit=unit, db=self.db)

    def trigger_balance_check(self, method: Method, unit: Unit) -> None:
        """Wakes up the backend checker for this method and unit so that it runs
        an immediate balance check instead of waiting for the next check interval.

        Called after balance-changing operations (e.g. after a melt is finalized)
        so that inflation is detected immediately.
        """
        if not settings.mint_watchdog_enabled:
            return
        event = self.check_events.get((method, unit))
        if event is None:
            logger.trace(
                f"No watchdog checker dispatched for method '{method.name}' and unit '{unit.name}'."
            )
            return
        logger.debug(
            f"Triggering immediate watchdog balance check for method '{method.name}' and unit '{unit.name}'."
        )
        event.set()

    async def check_melt_solvency(self, method: Method, unit: Unit) -> bool:
        """Pre-payment solvency check for melts.

        Returns True if the outstanding ecash liabilities are covered by the
        backend balance, False if the mint is insolvent. Called before a melt's
        proofs are set pending, so the liabilities still include the melt
        itself. If the check itself fails, the error is logged and True is
        returned so that a failing check does not block melts (fail-open).
        """
        if not settings.mint_watchdog_enabled:
            return True
        try:
            backend = self.backends[method][unit]
            backend_status = await backend.status()
            keyset_balance, keyset_fees_paid = await self.get_unit_balance_and_fees(
                unit, db=self.db
            )
        except Exception as e:
            logger.exception(
                f"Pre-melt solvency check failed for unit '{unit.name}': {e}."
                " Allowing the melt to proceed."
            )
            return True
        if keyset_balance + keyset_fees_paid > backend_status.balance:
            logger.error(
                f"Mint is insolvent: backend balance {backend_status.balance} is"
                " smaller than issued unit balance"
                f" {keyset_balance + keyset_fees_paid}. Refusing melt."
            )
            return False
        return True

    async def dispatch_backend_checker(
        self, method: Method, unit: Unit, backend: LightningBackend
    ) -> None:
        logger.info(
            f"Dispatching backend checker for unit: {unit.name} and backend: {backend.__class__.__name__}"
        )
        event = self.check_events[(method, unit)]
        while True:
            event.clear()
            try:
                await self._check_backend_balances(unit, backend)
            except Exception as e:
                # Never let a failed check kill the watchdog. A crashed checker
                # task would leave the mint running without any protection.
                logger.exception(
                    f"Watchdog balance check failed for unit '{unit.name}' with"
                    f" backend {backend.__class__.__name__}: {e}"
                )
            try:
                await asyncio.wait_for(
                    event.wait(),
                    timeout=settings.mint_watchdog_balance_check_interval_seconds,
                )
            except asyncio.TimeoutError:
                pass

    async def _check_backend_balances(
        self, unit: Unit, backend: LightningBackend
    ) -> bool:
        """Runs a single balance check cycle for a backend and stores a balance
        log entry if the check passed. Returns True if the balances are ok."""
        backend_status = await backend.status()
        backend_balance = backend_status.balance
        async with self.watcher_db.connect() as conn:
            last_balance_log_entry: MintBalanceLogEntry | None = None
            last_balance_log_entry = await self.crud.get_last_balance_log_entry(
                unit=unit, db=self.watcher_db
            )
            keyset_balance, keyset_fees_paid = await self.get_unit_balance_and_fees(
                unit, db=self.watcher_db, conn=conn
            )

            logger.debug(f"Last balance log entry: {last_balance_log_entry}")
            logger.debug(
                f"Backend balance {backend.__class__.__name__}: {backend_balance}"
            )
            logger.debug(
                f"Unit balance {unit.name}: {keyset_balance}, fees paid: {keyset_fees_paid}"
            )

            ok = await self.check_balances_and_abort(
                backend,
                last_balance_log_entry,
                backend_balance,
                keyset_balance,
                keyset_fees_paid,
            )

            if ok or settings.mint_watchdog_ignore_mismatch:
                await self.crud.store_balance_log(
                    backend_balance,
                    keyset_balance,
                    keyset_fees_paid,
                    db=self.db,
                    conn=conn,
                )

        return ok

    async def check_balances_and_abort(
        self,
        backend: LightningBackend,
        last_balance_log_entry: MintBalanceLogEntry | None,
        backend_balance: Amount,
        keyset_balance: Amount,
        keyset_fees_paid: Amount,
    ) -> bool:
        """Check if the backend balance and the mint balance match.
        If the mint issued more ecash than the backend can pay out, or the
        reserve gap between backend and issued balances is shrinking, signal
        the abort queue to shut down the mint.
        Returns True if the balances check succeeded, False otherwise.

        Args:
            backend (LightningBackend): Backend to check the balance against
            last_balance_log_entry (MintBalanceLogEntry | None): Last balance log entry in the database
            backend_balance (Amount): Balance of the backend
            keyset_balance (Amount): Balance of the mint

        Returns:
            bool: True if the balances check succeeded, False otherwise
        """
        if keyset_balance + keyset_fees_paid > backend_balance:
            logger.warning(
                f"Backend balance {backend.__class__.__name__}: {backend_balance} is smaller than issued unit balance {keyset_balance.unit}: {keyset_balance}"
            )
            await self.abort_queue.put(True)
            return False

        if last_balance_log_entry:
            last_balance_delta = last_balance_log_entry.backend_balance - (
                last_balance_log_entry.keyset_balance
                + last_balance_log_entry.keyset_fees_paid
            )
            current_balance_delta = backend_balance - (
                keyset_balance + keyset_fees_paid
            )
            if last_balance_delta > current_balance_delta:
                logger.warning(
                    f"Balance delta mismatch: before: {last_balance_delta} - now: {current_balance_delta}"
                )
                logger.warning(
                    f"Balances before: backend: {last_balance_log_entry.backend_balance}, issued ecash: {last_balance_log_entry.keyset_balance}, fees earned: {last_balance_log_entry.keyset_fees_paid}"
                )
                logger.warning(
                    f"Balances now: backend: {backend_balance}, issued ecash: {keyset_balance}, fees earned: {keyset_fees_paid}"
                )
                await self.abort_queue.put(True)
                return False

        return True
