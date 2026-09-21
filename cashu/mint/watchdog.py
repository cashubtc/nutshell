import asyncio
import signal
from typing import List, Optional, Tuple

from loguru import logger

from cashu.core.db import Connection, Database

from ..core.base import Amount, Method, MintBalanceLogEntry, Unit
from ..core.settings import settings
from ..lightning.base import LightningBackend
from .protocols import SupportsBackends, SupportsDb


class LedgerWatchdog(SupportsDb, SupportsBackends):
    watcher_db: Database
    abort_queue: asyncio.Queue = asyncio.Queue(0)

    def __init__(self) -> None:
        self.watcher_db = Database(self.db.name, self.db.db_location)
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

    async def check_melt_solvency(
        self, method: Method, unit: Unit, conn: Optional[Connection] = None
    ) -> bool:
        """Pre-payment solvency check for melts.

        Returns True if the outstanding ecash liabilities are covered by the
        backend balance, False if the mint is insolvent. Liabilities are the
        issued keyset balance plus the proofs currently pending: melts set
        their proofs pending before paying out, which decrements the keyset
        balance, so pending proofs are added back to keep the liabilities
        consistent across concurrent melt requests. The caller is expected to
        hold a database lock on the keyset accounting rows for this unit and
        pass its connection, so the balances read here are consistent. If the
        check itself fails, the error is logged and True is returned so that
        a failing check does not block melts (fail-open).
        """
        if not settings.mint_watchdog_enabled:
            return True
        try:
            backend = self.backends[method][unit]
            backend_status = await backend.status()
            keyset_balance, keyset_fees_paid = await self.get_unit_balance_and_fees(
                unit, db=self.db, conn=conn
            )
            pending_balance = await self.crud.get_pending_proofs_balance(
                unit=unit, db=self.db, conn=conn
            )
        except Exception as e:
            logger.exception(
                f"Pre-melt solvency check failed for unit '{unit.name}': {e}."
                " Allowing the melt to proceed."
            )
            return True
        liabilities = keyset_balance + keyset_fees_paid + pending_balance
        if liabilities > backend_status.balance:
            logger.error(
                f"Mint is insolvent: backend balance {backend_status.balance} is"
                f" smaller than outstanding liabilities {liabilities}. Refusing melt."
            )
            return False
        return True

    async def dispatch_backend_checker(
        self, method: Method, unit: Unit, backend: LightningBackend
    ) -> None:
        logger.info(
            f"Dispatching backend checker for unit: {unit.name} and backend: {backend.__class__.__name__}"
        )
        while True:
            try:
                await self._check_backend_balances(unit, backend)
            except Exception as e:
                # Never let a failed check kill the watchdog. A crashed checker
                # task would leave the mint running without any protection.
                logger.exception(
                    f"Watchdog balance check failed for unit '{unit.name}' with"
                    f" backend {backend.__class__.__name__}: {e}"
                )
            await asyncio.sleep(settings.mint_watchdog_balance_check_interval_seconds)

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
