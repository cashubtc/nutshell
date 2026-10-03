import pytest

from cashu.core.base import Proof
from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.mint import migrations
from cashu.mint.crud import LedgerCrudSqlite
from cashu.mint.db.read import DbReadHelper

POINT = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cleanup",
    [
        migrations.m029_remove_overlong_witness_values,
        migrations.m030_remove_overlong_witness_values,
        migrations.m040_repeat_witness_cleanup,
        None,
    ],
)
async def test_witness_cleanup_checks_complete_character_length(tmp_path, cleanup):
    db = Database("mint", str(tmp_path))
    crud = LedgerCrudSqlite()
    witnesses = [
        "\0" + "x" * 1025,
        "x" * 1025 + "\0",
        "x" * 600 + "\0" + "y" * 600,
        "😀" * 1025,
        "\0" + "x" * 4096,
        "short\0witness",
        "é" * 1024,
        "😀" * 1024,
        "x" * 1024,
        None,
    ]
    try:
        await migrate_databases(db, migrations)
        spent = []
        pending = []
        for index, witness in enumerate(witnesses):
            spent_proof = Proof(
                id="00deadbeefdeadbe",
                amount=1,
                C=POINT,
                secret=f"legacy-spent-{index}",
                witness=witness,
            )
            pending_proof = Proof(
                id="00deadbeefdeadbe",
                amount=1,
                C=POINT,
                secret=f"legacy-pending-{index}",
                witness=witness,
            )
            await crud.invalidate_proof(db=db, proof=spent_proof)
            await crud.set_proof_pending(db=db, proof=pending_proof)
            spent.append(spent_proof)
            pending.append(pending_proof)

        if cleanup is None:
            # Model a database that has already run the old cleanup migrations.
            await db.execute("UPDATE dbversions SET version = 39 WHERE db = 'mint'")
            await migrate_databases(db, migrations)
            version = await db.fetchone(
                "SELECT version FROM dbversions WHERE db = 'mint'"
            )
            assert version["version"] == 40
        else:
            await cleanup(db)
            # Cleanup is idempotent, including retained Unicode/NUL values.
            await cleanup(db)

        reader = DbReadHelper(db=db, crud=crud)
        states = await reader.get_proofs_states([p.Y for p in spent])
        for proof, state in zip(spent, states):
            expected = (
                None
                if proof.witness is not None and len(proof.witness) > 1024
                else proof.witness
            )
            assert state.spent
            assert state.witness == expected
        for proof in pending:
            expected = (
                None
                if proof.witness is not None and len(proof.witness) > 1024
                else proof.witness
            )
            row = await db.fetchone(
                "SELECT witness FROM proofs_pending WHERE y = :y", {"y": proof.Y}
            )
            assert row["witness"] == expected
    finally:
        await db.engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("table", ["proofs_used", "proofs_pending"])
async def test_witness_cleanup_continues_past_retained_unicode_batch(tmp_path, table):
    db = Database("mint", str(tmp_path))
    try:
        await migrate_databases(db, migrations)
        async with db.connect() as conn:
            # These values pass the byte prefilter but fit the character limit.
            for index in range(1000):
                await conn.execute(
                    f"INSERT INTO {table} (amount, id, c, secret, y, witness) VALUES (1, 'kid', :c, :secret, :y, :witness)",
                    {
                        "c": POINT,
                        "secret": "shared-secret",
                        "y": f"y-{index:04}",
                        "witness": "😀" * 400,
                    },
                )
            await conn.execute(
                f"INSERT INTO {table} (amount, id, c, secret, y, witness) VALUES (1, 'kid', :c, 'shared-secret', 'y-long', :witness)",
                {"c": POINT, "witness": "\0" + "x" * 1025},
            )

        await migrations.m040_repeat_witness_cleanup(db)

        row = await db.fetchone(f"SELECT witness FROM {table} WHERE y = 'y-long'")
        assert row["witness"] is None
        retained = await db.fetchone(
            f"SELECT COUNT(*) AS count FROM {table} WHERE witness IS NOT NULL"
        )
        assert retained["count"] == 1000
    finally:
        await db.engine.dispose()
