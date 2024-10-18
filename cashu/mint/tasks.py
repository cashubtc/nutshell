import asyncio
from typing import List, Mapping

from loguru import logger

from ..core.base import Method, MintQuoteState, Unit
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

    async def dispatch_listeners(self) -> List[asyncio.Task]:
        tasks = []
        for method, unitbackends in self.backends.items():
            for unit, backend in unitbackends.items():
                logger.debug(
                    f"Dispatching backend invoice listener for {method} {unit} {backend.__class__.__name__}"
                )
                tasks.append(asyncio.create_task(self.invoice_listener(backend)))
        return tasks

    async def invoice_listener(self, backend: LightningBackend) -> None:
        if backend.supports_incoming_payment_stream:
            while True:
                try:
                    async for checking_id in backend.paid_invoices_stream():
                        await self.invoice_callback_dispatcher(checking_id)
                except Exception as e:
                    logger.error(f"Error in invoice listener: {e}")
                    logger.info("Restarting invoice listener...")
                    await asyncio.sleep(1)

    async def invoice_callback_dispatcher(self, checking_id: str) -> None:
        logger.debug(f"Invoice callback dispatcher: {checking_id}")
        async with self.db.get_connection(
            lock_table="mint_quotes",
            lock_select_statement=f"checking_id='{checking_id}'",
            lock_timeout=5,
        ) as conn:
            quote = await self.crud.get_mint_quote(
                checking_id=checking_id, db=self.db, conn=conn
            )
            if not quote:
                logger.error(f"Quote not found for {checking_id}")
                return

            logger.trace(
                f"Invoice callback dispatcher: quote {quote} trying to set as {MintQuoteState.paid}"
            )
            # set the quote as paid
            if quote.unpaid:
                quote.state = MintQuoteState.paid
                await self.crud.update_mint_quote(quote=quote, db=self.db, conn=conn)
                logger.trace(
                    f"Quote {quote.quote} with {MintQuoteState.unpaid} set as {quote.state.value}"
                )

        await self.events.submit(quote)
