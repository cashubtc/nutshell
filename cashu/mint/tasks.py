import asyncio
from typing import List

from loguru import logger

from ..core.base import MintQuoteState
from ..core.gcs import GCSFilter
from ..core.settings import settings
from ..lightning.base import LightningBackend
from .protocols import SupportsBackends, SupportsDb, SupportsEvents, SupportsKeysets


class LedgerTasks(SupportsKeysets, SupportsDb, SupportsBackends, SupportsEvents):
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

    # TODO: marker for keysets with updates so that
    # we avoid recomputing identical filters.
    async def recompute_gcs(self) -> None:
        while True:
            try:
                logger.debug("[GCS Task] Recompute GCS task is awake.")
                async with self.db.get_connection() as conn:
                    for keyset in self.keysets.keys():
                        logger.debug(f"[GCS Task] Recomputing spent ecash GCS for keyset {keyset}")
                        Ys = await self.crud.get_Ys_by_keyset(keyset_id=keyset, db=self.db, conn=conn)
                        res = await self.crud.get_filter(keyset_id=keyset, db=self.db, conn=conn, which="SPENT")
                        
                        ys_bytes = [bytes.fromhex(y) for y in Ys]
                        new_filter = GCSFilter.create(
                            items=ys_bytes,
                            p=settings.mint_gcs_remainder_bitlength,
                            m=settings.mint_gcs_false_positive_rate,
                        )
                        if not res:
                            await self.crud.store_filter(
                                keyset_id=keyset,
                                gcs_filter=new_filter,
                                db=self.db,
                                conn=conn,
                                which="SPENT",
                            )
                        else:
                            await self.crud.update_filter(
                                keyset_id=keyset,
                                gcs_filter=new_filter,
                                db=self.db,
                                conn=conn,
                                which="SPENT",
                            )

                        logger.info(f"[GCS task]: Successfully recomputed spent filter for {keyset}")

                        Bs = await self.crud.get_blinded_messages_by_keyset_id(keyset_id=keyset, db=self.db, conn=conn)
                        res = await self.crud.get_filter(keyset_id=keyset, db=self.db, conn=conn, which="ISSUED")
                        bs_bytes = [bytes.fromhex(b_) for b_ in Bs]
                        new_filter = GCSFilter.create(
                            items=bs_bytes,
                            p=settings.mint_gcs_remainder_bitlength,
                            m=settings.mint_gcs_false_positive_rate,
                        )

                        if not res:
                            await self.crud.store_filter(
                                keyset_id=keyset,
                                gcs_filter=new_filter,
                                db=self.db,
                                conn=conn,
                                which="ISSUED",
                            )
                        else:
                            await self.crud.update_filter(
                                keyset_id=keyset,
                                gcs_filter=new_filter,
                                db=self.db,
                                conn=conn,
                                which="ISSUED",
                            )

                        logger.info(f"[GCS task]: Successfully recomputed issued filter for {keyset}")
            except Exception as e:
                logger.error(f"[GCS task]: {str(e)}")
            # Sleep for `gcs_recompute_timeout` amount of seconds
            await asyncio.sleep(settings.mint_gcs_recompute_timeout)
