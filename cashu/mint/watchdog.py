import asyncio
from typing import List

from loguru import logger

from ..core.base import Amount, MintBalanceLogEntry, Unit
from ..core.settings import settings
from ..lightning.base import LightningBackend
from .protocols import SupportsBackends, SupportsDb


class LedgerWatchdog(SupportsDb, SupportsBackends):
    abort_queue: asyncio.Queue = asyncio.Queue(0)

    def __init__(self) -> None:
        return

    async def dispatch_watchdogs(self) -> List[asyncio.Task]:
        tasks = []
        for method, unitbackends in self.backends.items():
            for unit, backend in unitbackends.items():
                tasks.append(
                    asyncio.create_task(self.dispatch_backend_checker(unit, backend))
                )
        tasks.append(asyncio.create_task(self.monitor_abort_queue()))
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
            raise SystemExit

    async def dispatch_backend_checker(
        self, unit: Unit, backend: LightningBackend
    ) -> None:
        logger.info(
            f"Dispatching backend checker for unit: {unit.name} and backend: {backend.__class__.__name__}"
        )
        while True:
            backend_status = await backend.status()
            backend_balance = backend_status.balance
            last_balance_log_entry: MintBalanceLogEntry | None = None
            async with self.db.connect() as conn:
                last_balance_log_entry = await self.crud.get_last_balance_log_entry(
                    unit=unit, db=self.db
                )
                keyset_balance = await self.crud.get_unit_balance(
                    unit, db=self.db, conn=conn
                )

            logger.trace(f"Last balance log entry: {last_balance_log_entry}")
            logger.trace(
                f"Backend balance {backend.__class__.__name__}: {backend_balance}"
            )
            logger.trace(f"Unit balance {unit.name}: {keyset_balance}")

            ok = await self.check_balances_and_abort(
                unit, backend, last_balance_log_entry, backend_balance, keyset_balance
            )

            if ok or settings.mint_watchdog_ignore_mismatch:
                await self.crud.store_balance_log(
                    backend_balance, keyset_balance, db=self.db
                )

            await asyncio.sleep(settings.mint_watchdog_balance_check_interval_seconds)

    async def check_balances_and_abort(
        self,
        unit: Unit,
        backend: LightningBackend,
        last_balance_log_entry: MintBalanceLogEntry | None,
        backend_balance: Amount,
        keyset_balance: Amount,
    ) -> bool:
        """Check if the backend balance and the mint balance match.
        If they don't match, log a warning and raise an exception that will shut down the mint.
        Returns True if the balances check succeeded, False otherwise.

        Args:
            unit (Unit): Unit of the balance to check
            backend (LightningBackend): Backend to check the balance against
            last_balance_log_entry (MintBalanceLogEntry | None): Last balance log entry in the database
            backend_balance (Amount): Balance of the backend
            keyset_balance (Amount): Balance of the mint

        Returns:
            bool: True if the balances check succeeded, False otherwise
        """
        if keyset_balance > backend_balance:
            logger.warning(
                f"Backend balance {backend.__class__.__name__}: {backend_balance} is smaller than issued unit balance {unit.name}: {keyset_balance}"
            )
            await self.abort_queue.put(True)
            return False

        if last_balance_log_entry:
            last_balance_delta = (
                last_balance_log_entry.backend_balance
                - last_balance_log_entry.mint_balance
            )
            current_balance_delta = backend_balance - keyset_balance
            if last_balance_delta != current_balance_delta:
                logger.warning(
                    f"Balance delta mismatch: {last_balance_delta} != {current_balance_delta}"
                )
                await self.abort_queue.put(True)
                return False

        return True
