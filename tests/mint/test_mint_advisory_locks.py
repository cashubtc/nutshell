import asyncio
import os
import sys
from pathlib import Path

import pytest
import pytest_asyncio

from cashu.core.base import Proof
from cashu.core.db import COCKROACH, POSTGRES, SQLITE, Database, LockOptions
from cashu.core.errors import ProofsAlreadySpentError, ProofsArePendingError
from cashu.mint.db.locks import ProofLockOptions

Y_A = "02" + "ab" * 32
Y_B = "03" + "cd" * 32


def database(backend=POSTGRES, schema=None):
    db = object.__new__(Database)
    db.type = backend
    db.schema = schema
    return db


def test_proof_lock_keys_are_stable_ordered_and_unique():
    locks = ProofLockOptions(Ys=[Y_A, Y_B, Y_A]).resolve(database())
    assert locks == ProofLockOptions(Ys=[Y_B, Y_A]).resolve(database())
    assert locks == ProofLockOptions(Ys=[Y_A.upper(), Y_B.upper()]).resolve(database())
    keys = [lock.advisory_key for lock in locks]
    assert len(set(keys)) == 2
    assert keys == sorted(keys)
    assert all(-(2**63) <= key < 2**63 for key in keys)
    assert all(lock.select_statement is None for lock in locks)


def test_proof_lock_namespaces_are_isolated():
    lock = ProofLockOptions(Ys=[Y_A])
    assert lock.resolve(database()) != lock.resolve(database(schema="auth"))


@pytest.mark.parametrize("backend", [SQLITE, COCKROACH])
def test_proof_locks_keep_other_backend_fallbacks(backend):
    assert ProofLockOptions(Ys=[Y_A, Y_B]).resolve(database(backend)) == [
        LockOptions(table="proofs_pending", timeout=1)
    ]


@pytest.mark.parametrize("backend", [POSTGRES, SQLITE, COCKROACH])
def test_empty_proofs_do_not_request_locks(backend):
    assert ProofLockOptions(Ys=[]).resolve(database(backend)) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("entrypoint", ["connect", "get_connection", "reuse"])
@pytest.mark.parametrize("matching_backend", [False, True])
async def test_backend_restrictions_apply_to_lock_variants(
    ledger, monkeypatch, entrypoint, matching_backend
):
    acquired = []
    acquire_lock = ledger.db._acquire_lock

    async def record_lock(conn, lock):
        acquired.append(lock)
        await acquire_lock(conn, lock)

    monkeypatch.setattr(ledger.db, "_acquire_lock", record_lock)
    locks = [
        ProofLockOptions(
            Ys=[Y_A, Y_B],
            only_on=ledger.db.type if matching_backend else "OTHER_BACKEND",
        )
    ]
    if entrypoint == "reuse":
        async with ledger.db.get_connection() as conn:
            async with ledger.db.get_connection(conn, locks=locks) as reused:
                assert reused is conn
                await reused.fetchone("SELECT 1")
    else:
        async with getattr(ledger.db, entrypoint)(locks=locks) as conn:
            await conn.fetchone("SELECT 1")

    if not matching_backend:
        assert acquired == []
    elif ledger.db.type == POSTGRES:
        assert len(acquired) == 2
        assert all(lock.advisory_key is not None for lock in acquired)
    else:
        assert acquired == [LockOptions(table="proofs_pending", timeout=1)]


@pytest.mark.asyncio
async def test_resolved_proof_locks_follow_quote_locks(postgres_ledger, monkeypatch):
    db = postgres_ledger.db
    acquired = []
    acquire_lock = db._acquire_lock

    async def record_lock(conn, lock):
        acquired.append(lock)
        await acquire_lock(conn, lock)

    monkeypatch.setattr(db, "_acquire_lock", record_lock)
    async with db.get_connection(
        locks=[ProofLockOptions(Ys=[Y_B, Y_A]), LockOptions(table="melt_quotes")]
    ) as conn:
        async with db.get_connection(conn, locks=[ProofLockOptions(Ys=[Y_A, Y_B])]):
            assert len(conn._advisory_locks_acquired) == 2
    assert [lock.table for lock in acquired[:3]] == [
        "melt_quotes",
        "proofs_pending",
        "proofs_pending",
    ]
    assert acquired[1].advisory_key < acquired[2].advisory_key


@pytest.mark.parametrize("key", [-(2**63) - 1, 2**63])
def test_advisory_lock_key_must_fit_bigint(key):
    with pytest.raises(ValueError, match="64-bit"):
        LockOptions(table="proofs_pending", advisory_key=key)


@pytest.mark.parametrize("key", [True, False, 1.0, 1.5, "1"])
def test_advisory_lock_key_must_be_an_integer(key):
    with pytest.raises(TypeError, match="must be an integer"):
        LockOptions(table="proofs_pending", advisory_key=key)


@pytest.mark.parametrize("key", [-(2**63), 0, 2**63 - 1])
def test_advisory_lock_key_accepts_bigint_boundaries(key):
    assert LockOptions(table="proofs_pending", advisory_key=key).advisory_key == key


def test_advisory_and_row_locks_are_separate_options():
    with pytest.raises(ValueError, match="select rows"):
        LockOptions(table="proofs_pending", advisory_key=1, select_statement="y = :y")


@pytest_asyncio.fixture
async def postgres_ledger(ledger):
    if ledger.db.type != POSTGRES:
        pytest.skip("Requires PostgreSQL advisory locks")
    return ledger


def proof(ledger, secret):
    return Proof(
        id=ledger.keyset.id,
        amount=8,
        secret=secret,
        C=ledger.keyset.public_keys[8].format().hex(),
    )


async def fund(ledger, amount=16):
    await ledger.crud.bump_keyset_balance(
        db=ledger.db, keyset=ledger.keyset, amount=amount
    )


@pytest.mark.asyncio
async def test_disjoint_proof_reservations_do_not_wait_for_another_lock(
    postgres_ledger,
):
    ledger = postgres_ledger
    first = proof(ledger, "first-proof-lock")
    second = proof(ledger, "second-proof-lock")
    await fund(ledger)
    async with ledger.db.get_connection(locks=[ProofLockOptions(Ys=[first.Y])]):
        await asyncio.wait_for(
            ledger.db_write._verify_spent_proofs_and_set_pending(
                [second], ledger.keysets
            ),
            2,
        )
        pending = await ledger.crud.get_proofs_pending(Ys=[second.Y], db=ledger.db)
        assert len(pending) == 1


@pytest.mark.asyncio
async def test_concurrent_reservation_of_one_proof_has_one_owner(postgres_ledger):
    ledger = postgres_ledger
    p = proof(ledger, "one-owner")
    await fund(ledger)
    results = await asyncio.gather(
        ledger.db_write._verify_spent_proofs_and_set_pending([p], ledger.keysets),
        ledger.db_write._verify_spent_proofs_and_set_pending([p], ledger.keysets),
        return_exceptions=True,
    )
    assert results.count(None) == 1
    assert sum(isinstance(result, ProofsArePendingError) for result in results) == 1
    assert len(await ledger.crud.get_proofs_pending(Ys=[p.Y], db=ledger.db)) == 1
    balance, _ = await ledger.crud.get_balance(ledger.keyset, ledger.db)
    assert balance.amount == 8


@pytest.mark.asyncio
@pytest.mark.parametrize("spend", [False, True])
async def test_reservation_coordinates_with_completion(postgres_ledger, spend):
    ledger = postgres_ledger
    p = proof(ledger, "completed-proof")
    await fund(ledger)
    await ledger.db_write._verify_spent_proofs_and_set_pending([p], ledger.keysets)
    task = None
    try:
        async with ledger.db.get_connection() as conn:
            if spend:
                await ledger.db_write.finalize_pending_proofs(
                    [p], ledger.keysets, conn=conn
                )
            else:
                await ledger.db_write._unset_proofs_pending(
                    [p], ledger.keysets, spent=False, conn=conn
                )
            task = asyncio.create_task(
                ledger.db_write._verify_spent_proofs_and_set_pending(
                    [p], ledger.keysets
                )
            )
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(task), 0.05)
        if spend:
            with pytest.raises(ProofsAlreadySpentError):
                await asyncio.wait_for(task, 2)
        else:
            await asyncio.wait_for(task, 2)
        balance, _ = await ledger.crud.get_balance(ledger.keyset, ledger.db)
        assert balance.amount == 8
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_partial_lock_acquisition_rolls_back_on_timeout(postgres_ledger):
    ledger = postgres_ledger
    locks = ProofLockOptions(Ys=[Y_A, Y_B], timeout=0.1).resolve(ledger.db)
    async with ledger.db.get_connection(locks=[locks[1]]):
        with pytest.raises(Exception, match="failed to acquire database locks"):
            async with ledger.db.get_connection(locks=locks):
                pytest.fail("conflicting lock was acquired")
        async with ledger.db.get_connection(locks=[locks[0]]):
            pass
    async with ledger.db.get_connection(locks=locks):
        pass


@pytest.mark.asyncio
@pytest.mark.parametrize("exit_mode", ["commit", "rollback", "cancel"])
async def test_advisory_locks_end_with_transaction(postgres_ledger, exit_mode):
    ledger = postgres_ledger
    acquired = asyncio.Event()
    release = asyncio.Event()
    locks = [ProofLockOptions(Ys=[Y_A], timeout=0.1)]

    async def hold_lock():
        async with ledger.db.get_connection(locks=locks):
            acquired.set()
            await release.wait()
            if exit_mode == "rollback":
                raise RuntimeError("roll back transaction")

    holder = asyncio.create_task(hold_lock())
    try:
        await asyncio.wait_for(acquired.wait(), 2)
        with pytest.raises(Exception, match="failed to acquire database locks"):
            async with ledger.db.get_connection(locks=locks):
                pytest.fail("conflicting lock was acquired")
        if exit_mode == "cancel":
            holder.cancel()
        else:
            release.set()
        await asyncio.gather(holder, return_exceptions=True)
        async with ledger.db.get_connection(locks=locks):
            pass
    finally:
        holder.cancel()
        await asyncio.gather(holder, return_exceptions=True)


@pytest.mark.asyncio
async def test_opposite_proof_order_completes_without_deadlock(postgres_ledger):
    ledger = postgres_ledger

    async def hold(Ys):
        async with ledger.db.get_connection(locks=[ProofLockOptions(Ys=Ys)]):
            await asyncio.sleep(0.05)

    await asyncio.wait_for(asyncio.gather(hold([Y_A, Y_B]), hold([Y_B, Y_A])), 2)


@pytest.mark.asyncio
async def test_another_process_uses_the_same_lock_key(postgres_ledger):
    ledger = postgres_ledger
    script = """
import asyncio
import os
from cashu.core.db import Database
from cashu.mint.db.locks import ProofLockOptions

async def main():
    db = Database('mint', os.environ['PROOF_LOCK_TEST_DATABASE'])
    try:
        lock = ProofLockOptions(Ys=[os.environ['PROOF_LOCK_TEST_Y']]).resolve(db)[0]
        async with db.get_connection() as conn:
            row = await conn.fetchone(
                'SELECT pg_try_advisory_xact_lock(:key) AS locked',
                {'key': lock.advisory_key},
            )
            print(row['locked'])
    finally:
        await db.engine.dispose()

asyncio.run(main())
"""
    env = {
        **os.environ,
        "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
        "PYTHONHASHSEED": "123",
        "PROOF_LOCK_TEST_DATABASE": ledger.db.db_location,
        "PROOF_LOCK_TEST_Y": Y_A,
    }
    async with ledger.db.get_connection(locks=[ProofLockOptions(Ys=[Y_A])]):
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            script,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), 10)
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
        assert process.returncode == 0, stderr.decode()
        assert stdout.decode().strip() == "False"
