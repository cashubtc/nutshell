import pytest

from benchmarks.benchmark_recovery import run_once


@pytest.mark.asyncio
async def test_efficient_recovery_reduces_calls_and_disclosure():
    legacy = await run_once("legacy", 10_000, 100, 25, 2, 137)
    efficient = await run_once("efficient", 10_000, 100, 25, 2, 137)

    assert efficient.network_calls < legacy.network_calls
    assert efficient.blinded_messages < legacy.blinded_messages
    assert efficient.proofs_checked < legacy.proofs_checked


@pytest.mark.asyncio
async def test_benchmark_counts_duplicate_binary_probes():
    efficient = await run_once("efficient", 1_000, 100, 25, 2, 137)

    assert efficient.blinded_messages > len(efficient.unique_blinded_messages)
    assert efficient.proofs_checked == len(efficient.unique_proofs_checked)
