import asyncio
import math
from functools import partial, wraps
from typing import List

from ..core.base import BlindedSignature, Proof
from ..core.settings import settings


def sum_proofs(proofs: List[Proof]):
    return sum([p.amount for p in proofs])


def sum_promises(promises: List[BlindedSignature]):
    return sum([p.amount for p in promises])


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


def fee_reserve(amount_msat: int) -> int:
    """Function for calculating the Lightning fee reserve"""
    return max(
        int(settings.lightning_reserve_fee_min),
        int(amount_msat * settings.lightning_fee_percent / 100.0),
    )


def calculate_number_of_blank_outputs(fee_reserve_sat: int):
    """Calculates the number of blank outputs used for returning overpaid fees.

    The formula ensures that any overpaid fees can be represented by the blank outputs,
    see NUT-08 for details.
    """
    assert fee_reserve_sat >= 0, "Fee reserve can't be negative."
    if fee_reserve_sat == 0:
        return 0
    return max(math.ceil(math.log2(fee_reserve_sat)), 1)
