"""Compare legacy NUT-13 and efficient recovery disclosure and request costs.

Run with:

    poetry run python benchmarks/benchmark_recovery.py
"""

import argparse
import asyncio
import time
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class RecoveryMetrics:
    restore_calls: int = 0
    state_calls: int = 0
    blinded_messages: int = 0
    unique_blinded_messages: set[int] = field(default_factory=set)
    proofs_checked: int = 0
    unique_proofs_checked: set[int] = field(default_factory=set)
    signatures_returned: int = 0
    elapsed_ms: float = 0.0

    @property
    def network_calls(self) -> int:
        return self.restore_calls + self.state_calls


class InstrumentedMint:
    """In-memory NUT-09/NUT-07 endpoint that records wallet disclosure."""

    def __init__(self, issued: set[int], unspent: set[int]):
        self.issued = issued
        self.unspent = unspent
        self.metrics = RecoveryMetrics()

    async def restore(self, counters: Iterable[int]) -> list[int]:
        requested = list(counters)
        self.metrics.restore_calls += 1
        self.metrics.blinded_messages += len(requested)
        self.metrics.unique_blinded_messages.update(requested)
        restored = [counter for counter in requested if counter in self.issued]
        self.metrics.signatures_returned += len(restored)
        return restored

    async def check_state(self, proofs: Iterable[int]) -> list[int]:
        proofs = list(proofs)
        self.metrics.state_calls += 1
        self.metrics.proofs_checked += len(proofs)
        self.metrics.unique_proofs_checked.update(proofs)
        return [proof for proof in proofs if proof in self.unspent]


async def legacy_recovery(
    mint: InstrumentedMint, batch_size: int, empty_batches: int
) -> list[int]:
    """Model Nutshell's forward NUT-13 batch scan."""
    recovered: list[int] = []
    counter = 0
    consecutive_empty = 0
    while consecutive_empty < empty_batches:
        restored = await mint.restore(range(counter, counter + batch_size))
        counter += batch_size
        if not restored:
            consecutive_empty += 1
            continue
        spendable = await mint.check_state(restored)
        recovered.extend(spendable)
    return recovered


async def efficient_recovery(
    mint: InstrumentedMint, batch_size: int, d_gap: int
) -> list[int]:
    """Model Nutshell's windowed binary search and dynamic-gap recovery."""
    max_counter = 2**32 - 1
    first_window = await mint.restore(range(0, batch_size))
    if not first_window:
        raise RuntimeError("efficient search cannot establish its initial window")

    lo, hi = 0, max_counter // batch_size
    while lo < hi:
        midpoint_window = (lo + hi + 1) // 2
        start = midpoint_window * batch_size
        end = min(start + batch_size, max_counter + 1)
        if await mint.restore(range(start, end)):
            lo = midpoint_window
        else:
            hi = midpoint_window - 1

    terminal_start = lo * batch_size
    terminal_end = min(terminal_start + batch_size, max_counter + 1)
    terminal = await mint.restore(range(terminal_start, terminal_end))
    if not terminal:
        raise RuntimeError("terminal recovery window is empty")
    last_issued = terminal[-1]
    restored = await mint.restore(range(max(0, last_issued - d_gap), last_issued + 1))
    return await mint.check_state(restored)


async def run_once(
    method: str,
    last_issued: int,
    d_gap: int,
    batch_size: int,
    empty_batches: int,
    gap_every: int,
) -> RecoveryMetrics:
    issued = set(range(last_issued + 1))
    if gap_every:
        issued.difference_update(range(gap_every, last_issued + 1, gap_every))
    unspent_start = max(0, last_issued - d_gap)
    unspent = {counter for counter in issued if counter >= unspent_start}
    mint = InstrumentedMint(issued, unspent)

    started = time.perf_counter()
    if method == "legacy":
        await legacy_recovery(mint, batch_size, empty_batches)
    else:
        await efficient_recovery(mint, batch_size, d_gap)
    mint.metrics.elapsed_ms = (time.perf_counter() - started) * 1000
    return mint.metrics


def print_results(rows: list[tuple[str, int, int, RecoveryMetrics]]) -> None:
    headers = (
        "method",
        "T",
        "d_gap",
        "calls",
        "restore",
        "state",
        "blind msgs",
        "unique blind",
        "proofs",
        "unique proofs",
        "signatures",
        "elapsed ms",
    )
    print(" | ".join(headers))
    print(" | ".join("---" for _ in headers))
    for method, last_issued, d_gap, metrics in rows:
        print(
            " | ".join(
                [
                    method,
                    str(last_issued),
                    str(d_gap),
                    str(metrics.network_calls),
                    str(metrics.restore_calls),
                    str(metrics.state_calls),
                    str(metrics.blinded_messages),
                    str(len(metrics.unique_blinded_messages)),
                    str(metrics.proofs_checked),
                    str(len(metrics.unique_proofs_checked)),
                    str(metrics.signatures_returned),
                    f"{metrics.elapsed_ms:.3f}",
                ]
            )
        )


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--histories", default="100,1000,10000,100000")
    parser.add_argument("--d-gap", type=int, default=100)
    parser.add_argument("--batch-size", type=int, default=25)
    parser.add_argument("--empty-batches", type=int, default=2)
    parser.add_argument(
        "--gap-every",
        type=int,
        default=137,
        help="omit every Nth issued counter; 0 disables synthetic gaps",
    )
    args = parser.parse_args()

    rows = []
    for last_issued in [int(value) for value in args.histories.split(",")]:
        d_gap = min(args.d_gap, last_issued)
        for method in ("legacy", "efficient"):
            metrics = await run_once(
                method,
                last_issued,
                d_gap,
                args.batch_size,
                args.empty_batches,
                args.gap_every,
            )
            rows.append((method, last_issued, d_gap, metrics))
    print_results(rows)


if __name__ == "__main__":
    asyncio.run(main())
