import asyncio
from functools import partial, wraps

from cashu.core.settings import LIGHTNING_FEE_PERCENT, LIGHTNING_RESERVE_FEE_MIN


def async_wrap(func):
    @wraps(func)
    async def run(*args, loop=None, executor=None, **kwargs):
        if loop is None:
            loop = asyncio.get_event_loop()
        partial_func = partial(func, *args, **kwargs)
        return await loop.run_in_executor(executor, partial_func)

    return run


def async_unwrap(to_await):
    async_response = []

    async def run_and_capture_result():
        r = await to_await
        async_response.append(r)

    loop = asyncio.get_event_loop()
    coroutine = run_and_capture_result()
    loop.run_until_complete(coroutine)
    return async_response[0]


def fee_reserve(amount_msat: int, internal=False) -> int:
    """Function for calculating the Lightning fee reserve"""
    if internal:
        return 0
    return max(
        int(LIGHTNING_RESERVE_FEE_MIN), int(amount_msat * LIGHTNING_FEE_PERCENT / 100.0)
    )
