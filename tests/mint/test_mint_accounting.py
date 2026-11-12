import asyncio

import pytest
from sqlalchemy import event

from cashu.core.base import BlindedMessage, Proof, Unit
from cashu.core.crypto.b_dhke import step1_alice
from cashu.core.db import POSTGRES, Connection, Database
from cashu.core.settings import settings
from cashu.mint import migrations
from cashu.mint.auth import migrations as auth_migrations
from cashu.mint.crud import LedgerCrudSqlite


async def stored_totals(ledger):
    row = await ledger.db.fetchone(
        "SELECT balance, fees_paid FROM keysets WHERE id = :id",
        {"id": ledger.keyset.id},
    )
    return row["balance"], row["fees_paid"]


async def live_totals(ledger):
    balance, fees = await ledger.crud.get_balance(ledger.keyset, ledger.db)
    return balance.amount, fees.amount


async def credit(ledger, amount, conn=None):
    await ledger.crud.bump_keyset_balance(
        db=ledger.db, keyset=ledger.keyset, amount=amount, conn=conn
    )


@pytest.mark.asyncio
async def test_accounting_batches_preserve_live_reads(ledger):
    for amount in (4, 8, -2):
        await credit(ledger, amount)
    await ledger.crud.bump_keyset_fees_paid(
        db=ledger.db, keyset=ledger.keyset, amount=3
    )
    assert await stored_totals(ledger) == (0, 0)
    assert await live_totals(ledger) == (10, 3)
    keyset = (await ledger.crud.get_keyset(db=ledger.db, id=ledger.keyset.id))[0]
    assert (keyset.balance, keyset.fees_paid) == (10, 3)

    for _ in range(2):
        assert (
            await ledger.crud.flush_keyset_accounting(db=ledger.db, batch_size=2) == 2
        )
        assert await live_totals(ledger) == (10, 3)
    assert await stored_totals(ledger) == (10, 3)
    assert await ledger.crud.flush_keyset_accounting(db=ledger.db) == 0
    assert await stored_totals(ledger) == (10, 3)


@pytest.mark.asyncio
async def test_accounting_changes_roll_back_with_operation(ledger):
    with pytest.raises(RuntimeError, match="operation failed"):
        async with ledger.db.get_connection() as conn:
            await credit(ledger, 8, conn)
            assert (await ledger.crud.get_balance(ledger.keyset, ledger.db, conn))[
                0
            ].amount == 8
            raise RuntimeError("operation failed")
    assert await live_totals(ledger) == (0, 0)
    assert await ledger.crud.flush_keyset_accounting(db=ledger.db) == 0


@pytest.mark.asyncio
async def test_accounting_aggregation_failure_is_retryable(ledger, monkeypatch):
    await credit(ledger, 8)
    execute = Connection.execute

    async def fail_delete(conn, query, values={}):
        if "DELETE FROM" in query and "keyset_accounting" in query:
            raise RuntimeError("aggregation failed")
        return await execute(conn, query, values)

    with monkeypatch.context() as patch:
        patch.setattr(Connection, "execute", fail_delete)
        with pytest.raises(RuntimeError, match="aggregation failed"):
            await ledger.crud.flush_keyset_accounting(db=ledger.db)
    assert await stored_totals(ledger) == (0, 0)
    assert await live_totals(ledger) == (8, 0)
    assert await ledger.crud.flush_keyset_accounting(db=ledger.db) == 1
    assert await stored_totals(ledger) == (8, 0)


@pytest.mark.asyncio
async def test_accounting_survives_restart_and_multiple_workers(ledger):
    for _ in range(12):
        await credit(ledger, 2)
    second_db = Database(ledger.db.name, ledger.db.db_location)
    second_crud = LedgerCrudSqlite()
    try:
        counts = await asyncio.gather(
            ledger.crud.flush_keyset_accounting(db=ledger.db, batch_size=6),
            second_crud.flush_keyset_accounting(db=second_db, batch_size=6),
        )
        assert sum(counts) == 12
        assert await stored_totals(ledger) == (24, 0)
        assert await live_totals(ledger) == (24, 0)
        assert await second_crud.flush_keyset_accounting(db=second_db) == 0
    finally:
        await second_db.engine.dispose()


@pytest.mark.asyncio
async def test_accounting_reads_are_consistent_during_aggregation(ledger, monkeypatch):
    await credit(ledger, 8)
    updated = asyncio.Event()
    release = asyncio.Event()
    execute = Connection.execute

    async def pause_after_update(conn, query, values={}):
        result = await execute(conn, query, values)
        if "UPDATE" in query and "SET balance" in query:
            updated.set()
            await release.wait()
        return result

    monkeypatch.setattr(Connection, "execute", pause_after_update)
    worker = asyncio.create_task(ledger.crud.flush_keyset_accounting(db=ledger.db))
    try:
        await asyncio.wait_for(updated.wait(), 5)
        assert await asyncio.wait_for(live_totals(ledger), 5) == (8, 0)
    finally:
        release.set()
        await asyncio.wait_for(worker, 5)
    assert await stored_totals(ledger) == (8, 0)
    assert await live_totals(ledger) == (8, 0)


@pytest.mark.asyncio
async def test_accounting_worker_handles_late_commits(ledger):
    if ledger.db.type != POSTGRES:
        pytest.skip("Concurrent writers require PostgreSQL")
    async with ledger.db.get_connection() as conn:
        await credit(ledger, 8, conn)
        assert await ledger.crud.flush_keyset_accounting(db=ledger.db) == 0
    assert await ledger.crud.flush_keyset_accounting(db=ledger.db) == 1
    assert await stored_totals(ledger) == (8, 0)


@pytest.mark.asyncio
async def test_transactions_do_not_lock_or_update_keyset_totals(ledger):
    if ledger.db.type != POSTGRES:
        pytest.skip("Row locks require PostgreSQL")
    async with ledger.db.get_connection() as conn:
        await conn.execute(
            "SELECT id FROM keysets WHERE id = :id FOR UPDATE",
            {"id": ledger.keyset.id},
        )
        await asyncio.wait_for(credit(ledger, 8), 2)
        assert await asyncio.wait_for(
            ledger.crud.try_debit_keyset_balance(
                db=ledger.db, keyset=ledger.keyset, amount=8
            ),
            2,
        )
    assert await stored_totals(ledger) == (0, 0)
    assert await live_totals(ledger) == (0, 0)


@pytest.mark.asyncio
async def test_issuance_and_restore_before_worker_runs(ledger):
    outputs = [
        BlindedMessage(
            id=ledger.keyset.id,
            amount=amount,
            B_=step1_alice(f"accounting-output-{amount}")[0].format().hex(),
        )
        for amount in (1, 2, 4)
    ]
    await ledger._store_blinded_messages(outputs)
    assert await live_totals(ledger) == (0, 0)
    statements = []

    def record_sql(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(ledger.db.engine.sync_engine, "before_cursor_execute", record_sql)
    try:
        signatures = await ledger._sign_blinded_messages(outputs)
    finally:
        event.remove(ledger.db.engine.sync_engine, "before_cursor_execute", record_sql)
    assert not any("UPDATE keysets" in query for query in statements)
    assert await stored_totals(ledger) == (0, 0)
    assert await live_totals(ledger) == (7, 0)
    assert len((await ledger.restore(outputs))[1]) == len(signatures)
    assert await ledger.crud.flush_keyset_accounting(db=ledger.db) == 1
    assert await stored_totals(ledger) == (7, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("spend", [False, True])
async def test_pending_accounting_and_fees(ledger, spend):
    await credit(ledger, 16)
    proofs = [
        Proof(
            id=ledger.keyset.id,
            amount=8,
            secret=f"accounting-input-{i}",
            C=ledger.keyset.public_keys[8].format().hex(),
        )
        for i in range(2)
    ]
    await ledger.db_write._verify_spent_proofs_and_set_pending(proofs, ledger.keysets)
    assert await live_totals(ledger) == (0, 0)
    await ledger.crud.flush_keyset_accounting(db=ledger.db)
    assert await stored_totals(ledger) == (0, 0)
    if spend:
        await ledger.db_write.finalize_pending_proofs(
            proofs, ledger.keysets, keyset_fees={ledger.keyset.id: 2}
        )
        expected = (0, 2)
    else:
        await ledger.db_write._unset_proofs_pending(proofs, ledger.keysets, spent=False)
        expected = (16, 0)
    assert await live_totals(ledger) == expected
    await ledger.crud.flush_keyset_accounting(db=ledger.db)
    assert await stored_totals(ledger) == expected


@pytest.mark.asyncio
async def test_accounting_worker_drains_backlog_and_stops(ledger, monkeypatch):
    for _ in range(3):
        await credit(ledger, 1)
    monkeypatch.setattr(settings, "mint_keyset_accounting_batch_size", 1)
    monkeypatch.setattr(settings, "mint_keyset_accounting_interval_seconds", 3600)
    drained = asyncio.Event()
    flush = ledger.crud.flush_keyset_accounting

    async def record_flush(**kwargs):
        count = await flush(**kwargs)
        if count == 0:
            drained.set()
        return count

    monkeypatch.setattr(ledger.crud, "flush_keyset_accounting", record_flush)
    ledger.start_keyset_accounting()
    worker = ledger.regular_tasks[-1]
    await asyncio.wait_for(drained.wait(), 5)
    assert await stored_totals(ledger) == (3, 0)
    await ledger.shutdown_ledger()
    assert worker.cancelled()


@pytest.mark.asyncio
async def test_accounting_worker_retries_after_failure(ledger, monkeypatch):
    await credit(ledger, 8)
    monkeypatch.setattr(settings, "mint_keyset_accounting_interval_seconds", 0.01)
    flushed = asyncio.Event()
    flush = ledger.crud.flush_keyset_accounting
    attempts = 0

    async def fail_once(**kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("temporary accounting failure")
        count = await flush(**kwargs)
        flushed.set()
        return count

    monkeypatch.setattr(ledger.crud, "flush_keyset_accounting", fail_once)
    ledger.start_keyset_accounting()
    try:
        await asyncio.wait_for(flushed.wait(), 5)
        assert attempts >= 2
        assert await stored_totals(ledger) == (8, 0)
    finally:
        await ledger.shutdown_ledger()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "migration",
    [
        migrations.m043_add_keyset_accounting_journal,
        auth_migrations.m006_add_keyset_accounting_journal,
    ],
)
async def test_accounting_migration_preserves_existing_totals(tmp_path, migration):
    db = Database("mint", str(tmp_path))
    try:
        await db.execute(
            "CREATE TABLE keysets (id TEXT PRIMARY KEY, balance BIGINT, fees_paid BIGINT)"
        )
        await db.execute("INSERT INTO keysets VALUES ('legacy', 123, 7)")
        await migration(db)
        row = await db.fetchone("SELECT * FROM keyset_accounting_totals")
        assert dict(row) == {"id": "legacy", "balance": 123, "fees_paid": 7}
        assert await db.fetchall("SELECT * FROM keyset_accounting") == []
    finally:
        await db.engine.dispose()


@pytest.mark.asyncio
async def test_accounting_keeps_units_separate(ledger):
    usd_keyset = next(k for k in ledger.keysets.values() if k.unit == Unit.usd)
    await credit(ledger, 8)
    await ledger.crud.bump_keyset_balance(db=ledger.db, keyset=usd_keyset, amount=3)
    await ledger.crud.flush_keyset_accounting(db=ledger.db)
    assert await live_totals(ledger) == (8, 0)
    balance, _ = await ledger.crud.get_balance(usd_keyset, ledger.db)
    assert balance.unit == Unit.usd
    assert balance.amount == 3


@pytest.mark.asyncio
async def test_accounting_aggregates_large_totals(ledger):
    amount = 2**32
    await credit(ledger, amount)
    await ledger.crud.bump_keyset_fees_paid(
        db=ledger.db, keyset=ledger.keyset, amount=amount
    )
    assert await live_totals(ledger) == (amount, amount)
    await ledger.crud.flush_keyset_accounting(db=ledger.db)
    assert await stored_totals(ledger) == (amount, amount)
