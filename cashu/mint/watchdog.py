import asyncio
from typing import List

from loguru import logger

from ..core.base import Unit
from ..core.settings import settings
from ..lightning.base import LightningBackend
from .protocols import SupportsBackends, SupportsDb


class LedgerWatchdog(SupportsDb, SupportsBackends):
    def __init__(self) -> None:
        return

    async def dispatch_watchdogs(self) -> List[asyncio.Task]:
        tasks = []
        for method, unitbackends in self.backends.items():
            for unit, backend in unitbackends.items():
                tasks.append(
                    asyncio.create_task(self.dispatch_backend_checker(unit, backend))
                )
        return tasks

    async def dispatch_backend_checker(
        self, unit: Unit, backend: LightningBackend
    ) -> None:
        logger.info(
            f"Dispatching backend checker for unit: {unit.name} and backend: {backend.__class__.__name__}"
        )
        while True:
            backend_status = await backend.status()
            backend_balance = int(backend_status.balance)
            async with self.db.connect() as conn:
                keyset_balance = await self.crud.get_unit_balance(
                    unit, db=self.db, conn=conn
                )
                await self.crud.store_balance_log(
                    unit, backend_balance, keyset_balance, db=self.db, conn=conn
                )

            logger.trace(
                f"Backend balance {backend.__class__.__name__}: {unit.str(backend_balance)}"
            )
            logger.trace(f"Unit balance {unit.name}: {unit.str(keyset_balance)}")

            await asyncio.sleep(settings.mint_balance_check_interval_seconds)
