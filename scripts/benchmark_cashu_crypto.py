"""Benchmark Cashu secp256k1 DHKE against BLS12-381 DHKE.

Run with:

    poetry run python scripts/benchmark_cashu_crypto.py

The benchmark intentionally avoids adding dependencies such as pytest-benchmark so it
can run in the existing development environment.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import os
import platform
import statistics
import string
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from cashu.core.crypto import b_dhke as secp_dhke
from cashu.core.crypto import bls_dhke
from cashu.core.crypto.bls import PrivateKey as BlsPrivateKey
from cashu.core.crypto.bls import PublicKey as BlsPublicKey
from cashu.core.crypto.secp import PrivateKey as SecpPrivateKey
from cashu.core.crypto.secp import PublicKey as SecpPublicKey

BenchmarkFunc = Callable[[], object]
BenchmarkOperation = Callable[["PreparedBenchmarkCase"], object]
BenchmarkPredicate = Callable[["PreparedBenchmarkCase"], bool]
BlsAffinePoint = tuple[int, int] | None

BLS_FIELD_MODULUS = int(
    "1a0111ea397fe69a4b1ba7b6434bacd7"
    "64774b84f38512bf6730d2a0f6b0f624"
    "1eabfffeb153ffffb9feffffffffaaab",
    16,
)
BLS_G1_B = 4
BLS_G1_COFACTOR = int("396c8c005555e1568c00aaab0000aaab", 16)
BLS_TRY_AND_INCREMENT_DOMAIN_SEPARATOR = b"BLS12_381_TryAndIncrement_Cashu_"


@dataclass(frozen=True)
class Benchmark:
    name: str
    secp: BenchmarkFunc
    bls: BenchmarkFunc
    operations_per_round: int = 1


@dataclass(frozen=True)
class Measurement:
    rounds: int
    mean_us: float
    stdev_us: float
    min_us: float


@dataclass(frozen=True)
class BenchmarkInput:
    secret: str
    a_scalar: int
    r_scalar: int
    nonce_scalar: int


@dataclass(frozen=True)
class PreparedBenchmarkCase:
    secret: str
    secret_bytes: bytes
    nonce_scalar: int
    secp_a: SecpPrivateKey
    secp_A: SecpPublicKey
    secp_r: SecpPrivateKey
    secp_B: SecpPublicKey
    secp_C_: SecpPublicKey
    secp_e: SecpPrivateKey
    secp_s: SecpPrivateKey
    secp_C: SecpPublicKey
    bls_a: BlsPrivateKey
    bls_A: BlsPublicKey
    bls_r: BlsPrivateKey
    bls_B: BlsPublicKey
    bls_C_: BlsPublicKey
    bls_C: BlsPublicKey
    bls_try_B: BlsPublicKey
    bls_try_C_: BlsPublicKey
    bls_try_C: BlsPublicKey


@dataclass(frozen=True)
class SecpProof:
    secret: str
    r: SecpPrivateKey
    C: SecpPublicKey
    e: SecpPrivateKey
    s: SecpPrivateKey


@dataclass(frozen=True)
class BlsProof:
    secret: str
    C: BlsPublicKey


def scalar_bytes(value: int) -> bytes:
    if value <= 0:
        raise ValueError("private key scalar must be positive")
    return value.to_bytes(32, "big")


def default_benchmark_inputs() -> list[BenchmarkInput]:
    return [
        BenchmarkInput(
            secret="cashu-crypto-benchmark",
            a_scalar=2,
            r_scalar=3,
            nonce_scalar=5,
        )
    ]


def hypothesis_benchmark_inputs(example_count: int) -> list[BenchmarkInput]:
    try:
        from hypothesis import HealthCheck, Phase, given
        from hypothesis import settings as hypothesis_settings
        from hypothesis import strategies as st
    except ImportError as exc:
        raise RuntimeError(
            "Hypothesis is required for --hypothesis-examples; run poetry install."
        ) from exc

    cases: list[BenchmarkInput] = []
    ascii_secret = st.text(
        alphabet=string.ascii_letters + string.digits + "-_:.",
        min_size=1,
        max_size=64,
    )
    scalar = st.integers(min_value=1, max_value=2**31 - 1)

    @given(secret=ascii_secret, a_scalar=scalar, r_scalar=scalar, nonce_scalar=scalar)
    @hypothesis_settings(
        database=None,
        deadline=None,
        derandomize=True,
        max_examples=example_count,
        phases=[Phase.generate],
        suppress_health_check=[HealthCheck.too_slow],
    )
    def collect_case(
        secret: str, a_scalar: int, r_scalar: int, nonce_scalar: int
    ) -> None:
        cases.append(
            BenchmarkInput(
                secret=secret,
                a_scalar=a_scalar,
                r_scalar=r_scalar,
                nonce_scalar=nonce_scalar,
            )
        )

    collect_case()
    return cases


def build_input_corpus(hypothesis_examples: int) -> list[BenchmarkInput]:
    if hypothesis_examples:
        return hypothesis_benchmark_inputs(hypothesis_examples)
    return default_benchmark_inputs()


def bls_field_inverse(value: int) -> int:
    return pow(value, BLS_FIELD_MODULUS - 2, BLS_FIELD_MODULUS)


def bls_point_add(left: BlsAffinePoint, right: BlsAffinePoint) -> BlsAffinePoint:
    if left is None:
        return right
    if right is None:
        return left

    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % BLS_FIELD_MODULUS == 0:
        return None

    if left == right:
        if y1 == 0:
            return None
        slope = (3 * x1 * x1) * bls_field_inverse(2 * y1) % BLS_FIELD_MODULUS
    else:
        slope = (y2 - y1) * bls_field_inverse(x2 - x1) % BLS_FIELD_MODULUS

    x3 = (slope * slope - x1 - x2) % BLS_FIELD_MODULUS
    y3 = (slope * (x1 - x3) - y1) % BLS_FIELD_MODULUS
    return x3, y3


def bls_point_multiply(point: BlsAffinePoint, scalar: int) -> BlsAffinePoint:
    result: BlsAffinePoint = None
    addend = point

    while scalar:
        if scalar & 1:
            result = bls_point_add(result, addend)
        addend = bls_point_add(addend, addend)
        scalar >>= 1

    return result


def bls_field_sqrt(value: int) -> int | None:
    root = pow(value, (BLS_FIELD_MODULUS + 1) // 4, BLS_FIELD_MODULUS)
    if root * root % BLS_FIELD_MODULUS != value:
        return None
    return root


def compress_bls_g1_point(point: BlsAffinePoint) -> bytes:
    if point is None:
        raise ValueError("cannot compress point at infinity")

    x, y = point
    compressed = bytearray(x.to_bytes(48, "big"))
    compressed[0] |= 0x80
    if y > BLS_FIELD_MODULUS - 1 - y:
        compressed[0] |= 0x20
    return bytes(compressed)


def try_increment_bls_hash_to_curve(message: bytes) -> BlsPublicKey:
    """Benchmark-only BLS try-and-increment hash-to-curve experiment."""
    msg_to_hash = hashlib.sha256(
        BLS_TRY_AND_INCREMENT_DOMAIN_SEPARATOR + message
    ).digest()

    for counter in range(2**16):
        candidate = bytearray(
            hashlib.sha384(msg_to_hash + counter.to_bytes(4, "little")).digest()
        )
        candidate[0] &= 0x1F
        x = int.from_bytes(candidate, "big")
        if x >= BLS_FIELD_MODULUS:
            continue

        y = bls_field_sqrt((x * x * x + BLS_G1_B) % BLS_FIELD_MODULUS)
        if y is None:
            continue

        point = bls_point_multiply((x, y), BLS_G1_COFACTOR)
        if point is None:
            continue

        return BlsPublicKey(compress_bls_g1_point(point), group="G1")

    raise ValueError("No valid BLS G1 point found")


def try_increment_bls_keyed_verification(
    a: BlsPrivateKey, C: BlsPublicKey, secret_msg: str
) -> bool:
    Y = try_increment_bls_hash_to_curve(secret_msg.encode("utf-8"))
    return C == Y * a


def deterministic_secp_step2(
    B_: SecpPublicKey, a: SecpPrivateKey, nonce: bytes
) -> tuple[SecpPublicKey, SecpPrivateKey, SecpPrivateKey]:
    C_: SecpPublicKey = B_ * a  # type: ignore[operator]
    e, s = secp_dhke.step2_bob_dleq(B_, a, nonce)
    return C_, e, s


def prepare_secp_proof(
    secret: str, a: SecpPrivateKey, r_scalar: int, nonce_scalar: int
) -> SecpProof:
    r = SecpPrivateKey(scalar_bytes(r_scalar))
    B_, _ = secp_dhke.step1_alice(secret, r)
    C_, e, s = deterministic_secp_step2(B_, a, scalar_bytes(nonce_scalar))
    A = a.public_key
    C = secp_dhke.step3_alice(C_, r, A)

    if not secp_dhke.verify(a, C, secret):
        raise AssertionError("secp proof failed mint verification")
    if not secp_dhke.carol_verify_dleq(secret, r, C, e, s, A):
        raise AssertionError("secp proof failed DLEQ verification")

    return SecpProof(secret=secret, r=r, C=C, e=e, s=s)


def prepare_bls_proof(secret: str, a: BlsPrivateKey, r_scalar: int) -> BlsProof:
    if r_scalar <= 0:
        raise ValueError("private key scalar must be positive")

    r = BlsPrivateKey(scalar=r_scalar)
    B_, _ = bls_dhke.step1_alice(secret, r)
    C_, _, _ = bls_dhke.step2_bob(B_, a)
    A = a.public_key
    C = bls_dhke.step3_alice(C_, r, A)

    if not bls_dhke.keyed_verification(a, C, secret):
        raise AssertionError("BLS proof failed mint verification")
    if not bls_dhke.pairing_verification(A, C, secret):
        raise AssertionError("BLS proof failed pairing verification")

    return BlsProof(secret=secret, C=C)


def prepare_benchmark_case(case: BenchmarkInput) -> PreparedBenchmarkCase:
    secp_a = SecpPrivateKey(scalar_bytes(case.a_scalar))
    secp_A = secp_a.public_key
    secp_r = SecpPrivateKey(scalar_bytes(case.r_scalar))
    secp_B, _ = secp_dhke.step1_alice(case.secret, secp_r)
    secp_C_, secp_e, secp_s = deterministic_secp_step2(
        secp_B, secp_a, scalar_bytes(case.nonce_scalar)
    )
    secp_C = secp_dhke.step3_alice(secp_C_, secp_r, secp_A)

    bls_a = BlsPrivateKey(scalar=case.a_scalar)
    bls_A = bls_a.public_key
    bls_r = BlsPrivateKey(scalar=case.r_scalar)
    bls_B, _ = bls_dhke.step1_alice(case.secret, bls_r)
    bls_C_, _, _ = bls_dhke.step2_bob(bls_B, bls_a)
    bls_C = bls_dhke.step3_alice(bls_C_, bls_r, bls_A)

    bls_try_Y = try_increment_bls_hash_to_curve(case.secret.encode("utf-8"))
    bls_try_B: BlsPublicKey = bls_try_Y * bls_r
    bls_try_C_, _, _ = bls_dhke.step2_bob(bls_try_B, bls_a)
    bls_try_C = bls_dhke.step3_alice(bls_try_C_, bls_r, bls_A)

    if not secp_dhke.verify(secp_a, secp_C, case.secret):
        raise AssertionError("prepared secp proof failed mint verification")
    if not secp_dhke.carol_verify_dleq(
        case.secret, secp_r, secp_C, secp_e, secp_s, secp_A
    ):
        raise AssertionError("prepared secp proof failed DLEQ verification")
    if not bls_dhke.keyed_verification(bls_a, bls_C, case.secret):
        raise AssertionError("prepared BLS proof failed mint verification")
    if not bls_dhke.pairing_verification(bls_A, bls_C, case.secret):
        raise AssertionError("prepared BLS proof failed pairing verification")
    if not try_increment_bls_keyed_verification(bls_a, bls_try_C, case.secret):
        raise AssertionError("prepared try-increment BLS proof failed verification")

    return PreparedBenchmarkCase(
        secret=case.secret,
        secret_bytes=case.secret.encode("utf-8"),
        nonce_scalar=case.nonce_scalar,
        secp_a=secp_a,
        secp_A=secp_A,
        secp_r=secp_r,
        secp_B=secp_B,
        secp_C_=secp_C_,
        secp_e=secp_e,
        secp_s=secp_s,
        secp_C=secp_C,
        bls_a=bls_a,
        bls_A=bls_A,
        bls_r=bls_r,
        bls_B=bls_B,
        bls_C_=bls_C_,
        bls_C=bls_C,
        bls_try_B=bls_try_B,
        bls_try_C_=bls_try_C_,
        bls_try_C=bls_try_C,
    )


def run_for_cases(
    cases: Sequence[PreparedBenchmarkCase], operation: BenchmarkOperation
) -> BenchmarkFunc:
    if len(cases) == 1:
        case = cases[0]

        def run_one() -> object:
            return operation(case)

        return run_one

    def run() -> object:
        result: object = None
        for case in cases:
            result = operation(case)
        return result

    return run


def all_for_cases(
    cases: Sequence[PreparedBenchmarkCase], operation: BenchmarkPredicate
) -> BenchmarkFunc:
    if len(cases) == 1:
        case = cases[0]

        def run_one() -> bool:
            return operation(case)

        return run_one

    def run() -> bool:
        return all(operation(case) for case in cases)

    return run


def time_rounds(func: BenchmarkFunc, rounds: int) -> float:
    result: object = None
    start = time.perf_counter_ns()
    for _ in range(rounds):
        result = func()
    elapsed_ns = time.perf_counter_ns() - start

    if result is False:
        raise AssertionError("benchmark callable returned False")

    return elapsed_ns / 1_000


def calibrate_rounds(
    func: BenchmarkFunc, target_seconds: float, min_rounds: int, max_rounds: int
) -> int:
    rounds = min_rounds
    target_us = target_seconds * 1_000_000

    while True:
        elapsed_us = time_rounds(func, rounds)
        if elapsed_us >= target_us or rounds >= max_rounds:
            return rounds

        scale = max(2, int(target_us / max(elapsed_us, 1)))
        rounds = min(max_rounds, rounds * min(scale, 10))


def measure(
    func: BenchmarkFunc,
    target_seconds: float,
    repeat: int,
    min_rounds: int,
    max_rounds: int,
    operations_per_round: int,
) -> Measurement:
    if operations_per_round <= 0:
        raise ValueError("operations_per_round must be positive")

    rounds = calibrate_rounds(func, target_seconds, min_rounds, max_rounds)
    samples = [
        time_rounds(func, rounds) / (rounds * operations_per_round)
        for _ in range(repeat)
    ]

    return Measurement(
        rounds=rounds,
        mean_us=statistics.mean(samples),
        stdev_us=statistics.stdev(samples) if len(samples) > 1 else 0.0,
        min_us=min(samples),
    )


def build_benchmarks(inputs: Sequence[BenchmarkInput], batch_size: int) -> Sequence[Benchmark]:
    if not inputs:
        raise ValueError("at least one benchmark input is required")

    cases = [prepare_benchmark_case(case) for case in inputs]
    case_count = len(cases)

    batch_seed = inputs[0]
    secp_a = SecpPrivateKey(scalar_bytes(batch_seed.a_scalar))
    secp_A = secp_a.public_key
    bls_a = BlsPrivateKey(scalar=batch_seed.a_scalar)
    bls_A = bls_a.public_key

    secp_proofs = [
        prepare_secp_proof(
            secret=f"{inputs[i % len(inputs)].secret}-batch-{i}",
            a=secp_a,
            r_scalar=inputs[i % len(inputs)].r_scalar + i + 1,
            nonce_scalar=inputs[i % len(inputs)].nonce_scalar + i + 1,
        )
        for i in range(batch_size)
    ]
    bls_proofs = [
        prepare_bls_proof(
            secret=f"{inputs[i % len(inputs)].secret}-batch-{i}",
            a=bls_a,
            r_scalar=inputs[i % len(inputs)].r_scalar + i + 1,
        )
        for i in range(batch_size)
    ]
    bls_K2s = [bls_A for _ in bls_proofs]
    bls_Cs = [proof.C for proof in bls_proofs]
    bls_secrets = [proof.secret for proof in bls_proofs]

    def secp_batch_wallet_verify() -> bool:
        return all(
            secp_dhke.carol_verify_dleq(
                proof.secret, proof.r, proof.C, proof.e, proof.s, secp_A
            )
            for proof in secp_proofs
        )

    def bls_batch_wallet_verify() -> bool:
        return bls_dhke.batch_pairing_verification(bls_K2s, bls_Cs, bls_secrets)

    return [
        Benchmark(
            name="hash_to_curve",
            secp=run_for_cases(
                cases, lambda case: secp_dhke.hash_to_curve(case.secret_bytes)
            ),
            bls=run_for_cases(
                cases, lambda case: bls_dhke.hash_to_curve(case.secret_bytes)
            ),
            operations_per_round=case_count,
        ),
        Benchmark(
            name="step1_alice blind",
            secp=run_for_cases(
                cases, lambda case: secp_dhke.step1_alice(case.secret, case.secp_r)
            ),
            bls=run_for_cases(
                cases, lambda case: bls_dhke.step1_alice(case.secret, case.bls_r)
            ),
            operations_per_round=case_count,
        ),
        Benchmark(
            name="step2_bob blind-sign",
            secp=run_for_cases(
                cases,
                lambda case: deterministic_secp_step2(
                    case.secp_B, case.secp_a, scalar_bytes(case.nonce_scalar)
                ),
            ),
            bls=run_for_cases(
                cases, lambda case: bls_dhke.step2_bob(case.bls_B, case.bls_a)
            ),
            operations_per_round=case_count,
        ),
        Benchmark(
            name="step3_alice unblind",
            secp=run_for_cases(
                cases,
                lambda case: secp_dhke.step3_alice(
                    case.secp_C_, case.secp_r, case.secp_A
                ),
            ),
            bls=run_for_cases(
                cases,
                lambda case: bls_dhke.step3_alice(
                    case.bls_C_, case.bls_r, case.bls_A
                ),
            ),
            operations_per_round=case_count,
        ),
        Benchmark(
            name="mint verify proof",
            secp=all_for_cases(
                cases, lambda case: secp_dhke.verify(case.secp_a, case.secp_C, case.secret)
            ),
            bls=all_for_cases(
                cases,
                lambda case: bls_dhke.keyed_verification(
                    case.bls_a, case.bls_C, case.secret
                ),
            ),
            operations_per_round=case_count,
        ),
        Benchmark(
            name="wallet verify proof",
            secp=all_for_cases(
                cases,
                lambda case: secp_dhke.carol_verify_dleq(
                    case.secret,
                    case.secp_r,
                    case.secp_C,
                    case.secp_e,
                    case.secp_s,
                    case.secp_A,
                ),
            ),
            bls=all_for_cases(
                cases,
                lambda case: bls_dhke.pairing_verification(
                    case.bls_A, case.bls_C, case.secret
                ),
            ),
            operations_per_round=case_count,
        ),
        Benchmark(
            name=f"wallet verify batch[{batch_size}]",
            secp=secp_batch_wallet_verify,
            bls=bls_batch_wallet_verify,
        ),
    ]


def cpu_model() -> str:
    cpuinfo = Path("/proc/cpuinfo")
    try:
        for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith(("model name", "Hardware", "Processor")):
                _, model = line.split(":", 1)
                model = model.strip()
                if model:
                    return model
    except OSError:
        pass

    return platform.processor() or "unknown"


def hardware_description() -> str:
    cpu_count = os.cpu_count()
    cpu_count_text = f", {cpu_count} logical CPUs" if cpu_count else ""
    return f"{cpu_model()}{cpu_count_text}"


def print_results(
    results: Sequence[tuple[str, Measurement, Measurement]],
    target_seconds: float,
    repeat: int,
    input_description: str,
) -> None:
    print("Cashu crypto benchmark: secp256k1 DHKE vs BLS12-381 DHKE")
    print(f"Python: {sys.version.split()[0]} ({platform.platform()})")
    print(f"Architecture: {platform.machine() or 'unknown'}")
    print(f"Hardware: {hardware_description()}")
    print(f"Timing: {repeat} samples after calibration, target {target_seconds:.2f}s/sample")
    print(f"Input corpus: {input_description}")
    print("Slowdown is BLS mean / secp mean. Values above 1.0x mean BLS is slower.")
    print()
    print(
        f"{'operation':<28} {'secp us/op':>12} {'BLS us/op':>12} "
        f"{'slowdown':>10} {'secp rounds':>12} {'BLS rounds':>11}"
    )
    print("-" * 91)

    for name, secp, bls in results:
        slowdown = bls.mean_us / secp.mean_us
        print(
            f"{name:<28} {secp.mean_us:12.2f} {bls.mean_us:12.2f} "
            f"{slowdown:9.2f}x {secp.rounds:12d} {bls.rounds:11d}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark BLS Cashu crypto against secp Cashu crypto."
    )
    parser.add_argument(
        "--target-seconds",
        type=float,
        default=0.20,
        help="calibration target duration per sample for each operation",
    )
    parser.add_argument(
        "--repeat", type=int, default=5, help="number of samples per operation"
    )
    parser.add_argument(
        "--min-rounds",
        type=int,
        default=1,
        help="minimum calls per timing sample",
    )
    parser.add_argument(
        "--max-rounds",
        type=int,
        default=1_000_000,
        help="maximum calls per timing sample",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=64,
        help="number of proofs in the batch wallet verification benchmark",
    )
    parser.add_argument(
        "--hypothesis-examples",
        type=int,
        default=0,
        help="number of Hypothesis-generated input examples to benchmark",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.target_seconds <= 0:
        raise ValueError("--target-seconds must be positive")
    if args.repeat <= 0:
        raise ValueError("--repeat must be positive")
    if args.min_rounds <= 0 or args.max_rounds < args.min_rounds:
        raise ValueError("round limits must be positive and ordered")
    if args.batch_size <= 0:
        raise ValueError("--batch-size must be positive")
    if args.hypothesis_examples < 0:
        raise ValueError("--hypothesis-examples must not be negative")

    benchmark_inputs = build_input_corpus(args.hypothesis_examples)
    input_description = (
        f"{len(benchmark_inputs)} Hypothesis-generated examples (generation not timed)"
        if args.hypothesis_examples
        else "1 fixed deterministic example"
    )
    benchmarks = build_benchmarks(benchmark_inputs, args.batch_size)
    results: list[tuple[str, Measurement, Measurement]] = []

    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        for benchmark in benchmarks:
            secp = measure(
                benchmark.secp,
                target_seconds=args.target_seconds,
                repeat=args.repeat,
                min_rounds=args.min_rounds,
                max_rounds=args.max_rounds,
                operations_per_round=benchmark.operations_per_round,
            )
            bls = measure(
                benchmark.bls,
                target_seconds=args.target_seconds,
                repeat=args.repeat,
                min_rounds=args.min_rounds,
                max_rounds=args.max_rounds,
                operations_per_round=benchmark.operations_per_round,
            )
            results.append((benchmark.name, secp, bls))
    finally:
        if gc_was_enabled:
            gc.enable()

    print_results(results, args.target_seconds, args.repeat, input_description)


if __name__ == "__main__":
    main()
