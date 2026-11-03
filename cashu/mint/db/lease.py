"""Renew one melt executor's lease while its asynchronous work runs."""

import asyncio
from contextlib import asynccontextmanager, suppress
from typing import AsyncIterator

from loguru import logger

from ...core.base import MeltQuote
from ...core.errors import TransactionError
from ...core.settings import settings
from .write import DbWriteHelper


@asynccontextmanager
async def maintain_melt_lease(
    db_write: DbWriteHelper, quote: MeltQuote
) -> AsyncIterator[None]:
    if not await db_write.renew_melt_quote_lease(quote):
        raise TransactionError("Melt execution lease lost.")
    owner = asyncio.current_task()
    assert owner is not None
    lease_lost = False
    loop = asyncio.get_running_loop()
    deadline = loop.time() + settings.mint_melt_execution_timeout_seconds

    async def renew() -> None:
        nonlocal lease_lost
        try:
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    return
                await asyncio.sleep(
                    min(settings.mint_melt_lease_seconds / 4, remaining)
                )
                # Cancellation of backend work can take time. Never keep its
                # lease alive past the execution budget while waiting for it.
                if loop.time() >= deadline:
                    return
                if not await db_write.renew_melt_quote_lease(quote):
                    current = await db_write.crud.get_melt_quote(
                        quote_id=quote.quote, db=db_write.db
                    )
                    # A terminal transition clears the lease before its caller returns.
                    if (
                        current
                        and current.attempt == quote.attempt
                        and not current.pending
                        and not current.melt_lock
                    ):
                        return
                    break
        except Exception as exc:
            logger.warning(f"Could not renew melt lease {quote.quote}: {exc}")
        lease_lost = True
        owner.cancel()

    heartbeat = asyncio.create_task(renew())
    try:
        yield
    except asyncio.CancelledError:
        if lease_lost:
            raise TransactionError("Melt execution lease lost.") from None
        raise
    finally:
        heartbeat.cancel()
        with suppress(asyncio.CancelledError):
            await heartbeat
