import asyncio
from typing import Mapping

from loguru import logger

from ..core.base import Method, Unit
from ..core.db import Database
from ..lightning.base import LightningBackend
from ..mint.crud import LedgerCrud
from .events.events import LedgerEventManager
from .protocols import SupportsBackends, SupportsDb, SupportsEvents


class LedgerTasks(SupportsDb, SupportsBackends, SupportsEvents):
    backends: Mapping[Method, Mapping[Unit, LightningBackend]] = {}
    db: Database
    crud: LedgerCrud
    events: LedgerEventManager

    async def dispatch_listeners(self) -> None:
        for method, unitbackends in self.backends.items():
            for unit, backend in unitbackends.items():
                logger.debug(
                    f"Dispatching backend invoice listener for {method} {unit} {backend.__class__.__name__}"
                )
                asyncio.create_task(self.invoice_listener(backend))

    async def invoice_listener(self, backend: LightningBackend) -> None:
        try:
            async for checking_id in backend.paid_invoices_stream():
                await self.invoice_callback_dispatcher(checking_id)
        except Exception as e:
            logger.error(f"Error in invoice listener: {e}")

    async def invoice_callback_dispatcher(self, checking_id: str) -> None:
        logger.debug(f"Invoice callback dispatcher: {checking_id}")
        # TODO: Explicitly check for the quote payment state before setting it as paid
        # db read, quote.paid = True, db write should be refactored and moved to ledger.py
        quote = await self.crud.get_mint_quote(checking_id=checking_id, db=self.db)
        if not quote:
            logger.error(f"Quote not found for {checking_id}")
            return
        # set the quote as paid
        if not quote.paid:
            quote.paid = True
            await self.crud.update_mint_quote(quote=quote, db=self.db)
        logger.trace(f"Quote {quote} set as paid and ")
        await self.events.submit(quote)
