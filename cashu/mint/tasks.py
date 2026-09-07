import asyncio
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
            # A CDK processor can expose several methods through one endpoint.
            # Its event stream is shared, so any of our per-method listeners may
            # receive the event. Resolve such events by their stable processor
            # identifier and let get_mint_quote verify payment using the quote's
            # actual backend below.
            if not quote:
                quote = await self.crud.get_mint_quote(
                    checking_id=checking_id,
                    db=self.db,
                    conn=conn,
                )
            if not quote:
                logger.error(f"Quote not found for {checking_id}")
                return
            if quote.method != method or (unit is not None and quote.unit != unit.name):
                logger.debug(
                    f"Routing processor event for {method}:{unit.name if unit else '*'} "
                    f"to quote backend {quote.method}:{quote.unit}"
                )

            logger.trace(
                f"Invoice callback dispatcher: quote {quote} trying to set as {MintQuoteState.paid}"
            )
        # Fetch the cumulative paid amount through the normal quote refresh path.
        # Reusable methods may emit more than one event for the same checking ID.
        await self.get_mint_quote(  # type: ignore[attr-defined]
            quote.quote, force_backend_check=True
        )
