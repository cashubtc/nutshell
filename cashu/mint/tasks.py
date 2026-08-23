import asyncio
import time
from typing import Any, List, Union

from loguru import logger

from ..core.base import Method, MintQuoteState, Unit
from ..core.settings import settings
from ..payment import payment_method_registry
from .protocols import SupportsBackends, SupportsDb, SupportsEvents


class LedgerTasks(SupportsDb, SupportsBackends, SupportsEvents):
    async def dispatch_listeners(self) -> List[asyncio.Task]:
        tasks = []
        for method, unitbackends in self.backends.items():
            for unit, backend in unitbackends.items():
                logger.debug(
                    f"Dispatching backend invoice listener for {method} {unit} {backend.__class__.__name__}"
                )
                tasks.append(
                    asyncio.create_task(self.invoice_listener(method, unit, backend))
                )
        return tasks

    async def invoice_listener(
        self, method: Union[Method, str], unit: Unit, backend: Any
    ) -> None:
        method_name = method.name if isinstance(method, Method) else method
        plugin = payment_method_registry.get(method_name)
        if plugin.supports_incoming_payment_stream(backend):
            retry_delay = settings.mint_retry_exponential_backoff_base_delay
            max_retry_delay = settings.mint_retry_exponential_backoff_max_delay

            while True:
                try:
                    # Reset retry delay on successful connection to backend stream
                    retry_delay = settings.mint_retry_exponential_backoff_base_delay
                    async for checking_id in plugin.incoming_payment_stream(backend):
                        await self.invoice_callback_dispatcher(
                            checking_id, method_name, unit
                        )
                except Exception as e:
                    logger.error(f"Error in invoice listener: {e}")
                    logger.info(
                        f"Restarting invoice listener in {retry_delay} seconds..."
                    )
                    await asyncio.sleep(retry_delay)

                    # Exponential backoff
                    retry_delay = min(retry_delay * 2, max_retry_delay)

    async def invoice_callback_dispatcher(
        self,
        checking_id: str,
        method: str = Method.bolt11.name,
        unit: Unit | None = None,
    ) -> None:
        logger.debug(f"Invoice callback dispatcher: {checking_id}")
        async with self.db.get_connection(
            lock_table="mint_quotes",
            lock_select_statement="checking_id = :checking_id",
            lock_parameters={"checking_id": checking_id},
            lock_timeout=5,
        ) as conn:
            quote = await self.crud.get_mint_quote(
                checking_id=checking_id,
                method=method,
                db=self.db,
                conn=conn,
            )
            if not quote:
                logger.error(f"Quote not found for {checking_id}")
                return
            if unit is not None and quote.unit != unit.name:
                logger.error(
                    f"Quote unit mismatch for {method}:{checking_id}: {quote.unit}"
                )
                return

            logger.trace(
                f"Invoice callback dispatcher: quote {quote} trying to set as {MintQuoteState.paid}"
            )
            # set the quote as paid
            if quote.unpaid:
                quote.state = MintQuoteState.paid
                quote.paid_time = int(time.time())
                quote.updated_at = int(time.time())
                await self.crud.update_mint_quote(quote=quote, db=self.db, conn=conn)
                logger.trace(
                    f"Quote {quote.quote} with {MintQuoteState.unpaid} set as {quote.state.value}"
                )

        await self.events.submit(quote)
