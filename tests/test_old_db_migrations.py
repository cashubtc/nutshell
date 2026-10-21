"""Migrate dummy mint and wallet rows from an old schema version."""

import re

import pytest

from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.core.settings import settings
from cashu.mint import migrations as mint_migrations
from cashu.wallet import migrations as wallet_migrations

_MIGRATION_NAME = re.compile(r"^m(\d\d\d)_")

# Mint v7 is the last schema before quote tables. Proofs, promises, invoices,
# and keysets already exist, including the keyset id column.
OLD_MINT_VERSION = 7
OLD_WALLET_VERSION = 1

MINT_KEYSET_ID = "00oldmintkeyset01"
MINT_SECRET = "old-mint-spent-secret"
MINT_PROMISE_B = "02" + "11" * 32
MINT_PROMISE_C = "03" + "cd" * 32
MINT_INVOICE_ID = "old-invoice-1"
WALLET_SECRET = "old-wallet-secret"
WALLET_SPENT_SECRET = "old-wallet-spent-secret"


def latest_migration_version(module) -> int:
    versions = [
        int(match.group(1))
        for name in module.__dict__
        if (match := _MIGRATION_NAME.match(name))
    ]
    return max(versions)


async def apply_migrations_through(db: Database, module, version: int) -> None:
    async with db.connect() as conn:
        await module.m000_create_migrations_table(conn)
    for name, func in module.__dict__.items():
        match = _MIGRATION_NAME.match(name)
        if match is None:
            continue
        number = int(match.group(1))
        if number == 0 or number > version:
            continue
        await func(db)
    db_name = module.__name__.split(".")[-2]
    async with db.connect() as conn:
        await conn.execute(
            "INSERT INTO"
            f" {db.table_with_schema('dbversions')} (db, version)"
            " VALUES (:db, :version)",
            {"db": db_name, "version": version},
        )


async def read_version(db: Database, db_name: str) -> int:
    async with db.connect() as conn:
        row = await conn.fetchone(
            f"SELECT version FROM {db.table_with_schema('dbversions')} WHERE db = :db",
            {"db": db_name},
        )
    assert row is not None
    return int(row["version"])


def use_local_test_settings() -> None:
    settings.db_backup_path = None
    settings.mint_private_key = "TEST_PRIVATE_KEY"
    settings.mint_seed_decryption_key = ""
    settings.max_order = 4


@pytest.mark.asyncio
async def test_mint_migrates_dummy_data_from_old_schema(tmp_path):
    use_local_test_settings()
    db = Database("mint", str(tmp_path / "old-mint"))
    try:
        await apply_migrations_through(db, mint_migrations, OLD_MINT_VERSION)
        async with db.connect() as conn:
            await conn.execute(
                "INSERT INTO proofs_used (amount, c, secret, id)"
                " VALUES (:amount, :c, :secret, :id)",
                {
                    "amount": 8,
                    "c": "02" + "ab" * 32,
                    "secret": MINT_SECRET,
                    "id": MINT_KEYSET_ID,
                },
            )
            await conn.execute(
                "INSERT INTO promises (amount, b_, c_, id)"
                " VALUES (:amount, :b_, :c_, :id)",
                {
                    "amount": 16,
                    "b_": MINT_PROMISE_B,
                    "c_": MINT_PROMISE_C,
                    "id": MINT_KEYSET_ID,
                },
            )
            await conn.execute(
                "INSERT INTO invoices"
                " (amount, bolt11, id, issued, payment_hash)"
                " VALUES (:amount, :bolt11, :id, :issued, :payment_hash)",
                {
                    "amount": 100,
                    "bolt11": "lnbc1dummyoldinvoice",
                    "id": MINT_INVOICE_ID,
                    "issued": False,
                    "payment_hash": "old-payment-hash",
                },
            )
            await conn.execute(
                "INSERT INTO keysets"
                " (id, derivation_path, valid_from, valid_to,"
                " first_seen, active, version)"
                " VALUES (:id, :derivation_path, :valid_from, :valid_to,"
                " :first_seen, :active, :version)",
                {
                    "id": MINT_KEYSET_ID,
                    "derivation_path": "m/0'/0'/0'",
                    "valid_from": "1700000000",
                    "valid_to": "1700000000",
                    "first_seen": "1700000000",
                    "active": True,
                    "version": "0.13.0",
                },
            )
        assert await read_version(db, "mint") == OLD_MINT_VERSION

        await migrate_databases(db, mint_migrations)

        assert await read_version(db, "mint") == latest_migration_version(
            mint_migrations
        )
        async with db.connect() as conn:
            proof = await conn.fetchone(
                "SELECT amount, secret, y FROM proofs_used WHERE secret = :secret",
                {"secret": MINT_SECRET},
            )
            promise = await conn.fetchone(
                "SELECT amount, b_, c_ FROM promises WHERE b_ = :b_",
                {"b_": MINT_PROMISE_B},
            )
            quote = await conn.fetchone(
                "SELECT amount, request, unit, checking_id"
                " FROM mint_quotes WHERE quote = :quote",
                {"quote": MINT_INVOICE_ID},
            )
            keyset = await conn.fetchone(
                "SELECT id FROM keysets WHERE id = :id",
                {"id": MINT_KEYSET_ID},
            )
        assert proof is not None
        assert proof["amount"] == 8
        assert proof["secret"] == MINT_SECRET
        assert proof["y"]
        assert promise is not None
        assert promise["amount"] == 16
        assert promise["b_"] == MINT_PROMISE_B
        assert promise["c_"] == MINT_PROMISE_C
        assert quote is not None
        assert quote["amount"] == 100
        assert quote["request"] == "lnbc1dummyoldinvoice"
        assert quote["unit"] == "sat"
        assert quote["checking_id"] == "old-payment-hash"
        assert keyset is not None
        assert keyset["id"] == MINT_KEYSET_ID
    finally:
        await db.engine.dispose()


@pytest.mark.asyncio
async def test_wallet_migrates_dummy_data_from_old_schema(tmp_path):
    use_local_test_settings()
    db = Database("wallet", str(tmp_path / "old-wallet"))
    try:
        await apply_migrations_through(db, wallet_migrations, OLD_WALLET_VERSION)
        async with db.connect() as conn:
            await conn.execute(
                "INSERT INTO proofs (amount, C, secret) VALUES (:amount, :c, :secret)",
                {
                    "amount": 4,
                    "c": "02" + "ef" * 32,
                    "secret": WALLET_SECRET,
                },
            )
            await conn.execute(
                "INSERT INTO proofs_used (amount, C, secret)"
                " VALUES (:amount, :c, :secret)",
                {
                    "amount": 2,
                    "c": "02" + "ab" * 32,
                    "secret": WALLET_SPENT_SECRET,
                },
            )
        assert await read_version(db, "wallet") == OLD_WALLET_VERSION

        await migrate_databases(db, wallet_migrations)

        assert await read_version(db, "wallet") == latest_migration_version(
            wallet_migrations
        )
        async with db.connect() as conn:
            proof = await conn.fetchone(
                "SELECT amount, secret FROM proofs WHERE secret = :secret",
                {"secret": WALLET_SECRET},
            )
            spent = await conn.fetchone(
                "SELECT amount, secret FROM proofs_used WHERE secret = :secret",
                {"secret": WALLET_SPENT_SECRET},
            )
        assert proof is not None
        assert proof["amount"] == 4
        assert spent is not None
        assert spent["amount"] == 2
    finally:
        await db.engine.dispose()
