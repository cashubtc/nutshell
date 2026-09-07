import asyncio
import signal
from typing import Any, List, Optional, Tuple

from loguru import logger

from cashu.core.db import Connection, Database

from ..core.base import Amount, Method, MintBalanceLogEntry, Unit
from ..core.settings import settings
from ..payment import PaymentMethodPlugin, payment_method_registry
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
        sources_by_unit: dict[Unit, dict[str, tuple[PaymentMethodPlugin, Any]]] = {}
        incomplete_units: set[Unit] = set()
        for method, unitbackends in self.backends.items():
            method_name = method.name if isinstance(method, Method) else method
            plugin = payment_method_registry.get(method_name)
            for unit, backend in unitbackends.items():
                if not plugin.supports_balance:
                    incomplete_units.add(unit)
                    logger.warning(
                        f"Skipping balance watchdog for unit '{unit.name}': "
                        f"payment method '{method_name}' does not report a balance"
                    )
                    continue
                sources = sources_by_unit.setdefault(unit, {})
                sources.setdefault(
                    plugin.funding_source_id(backend, unit), (plugin, backend)
                )

        for unit, sources in sources_by_unit.items():
            # Liabilities belong to the unit, not to an individual payment rail.
            # A partial reserve balance cannot safely be compared with them.
            if unit not in incomplete_units:
                tasks.append(
                    asyncio.create_task(self.dispatch_unit_checker(unit, sources))
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
            signal.raise_signal(signal.SIGTERM)

    async def get_balance(self, unit: Unit) -> Tuple[Amount, Amount]:
        """Returns the balance of the mint for this unit."""
        return await self.get_unit_balance_and_fees(unit=unit, db=self.db)

    async def dispatch_unit_checker(
        self, unit: Unit, sources: dict[str, tuple[PaymentMethodPlugin, Any]]
    ) -> None:
        logger.info(
            f"Dispatching balance checker for unit: {unit.name} and funding sources: {list(sources)}"
        )
        while True:
            try:
                statuses = await asyncio.gather(
                    *(plugin.status(backend) for plugin, backend in sources.values())
                )
                backend_balance = Amount(unit, 0)
                for status in statuses:
                    if status.error_message:
                        raise ValueError(status.error_message)
                    backend_balance += status.balance.to(unit)
            except Exception as exc:
                logger.warning(f"Skipping balance check for {unit.name}: {exc}")
                await asyncio.sleep(
                    settings.mint_watchdog_balance_check_interval_seconds
                )
                continue
            last_balance_log_entry: MintBalanceLogEntry | None = None
            async with self.watcher_db.connect() as conn:
                last_balance_log_entry = await self.crud.get_last_balance_log_entry(
                    unit=unit, db=self.watcher_db
                )
                keyset_balance, keyset_fees_paid = await self.get_unit_balance_and_fees(
                    unit, db=self.watcher_db, conn=conn
                )

                logger.debug(f"Last balance log entry: {last_balance_log_entry}")
                logger.debug(
                    f"Aggregate backend balance {unit.name}: {backend_balance}"
                )
                logger.debug(
                    f"Unit balance {unit.name}: {keyset_balance}, fees paid: {keyset_fees_paid}"
                )

                ok = await self.check_balances_and_abort(
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

            await asyncio.sleep(settings.mint_watchdog_balance_check_interval_seconds)

    async def check_balances_and_abort(
        self,
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
            last_balance_log_entry (MintBalanceLogEntry | None): Last balance log entry in the database
            backend_balance (Amount): Balance of the backend
            keyset_balance (Amount): Balance of the mint

        Returns:
            bool: True if the balances check succeeded, False otherwise
        """
        if keyset_balance + keyset_fees_paid > backend_balance:
            logger.warning(
                f"Backend balance {backend_balance} is smaller than issued unit balance {keyset_balance.unit}: {keyset_balance}"
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
