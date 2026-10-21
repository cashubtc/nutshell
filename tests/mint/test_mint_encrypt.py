import asyncio

import pytest
from click.testing import CliRunner

from cashu.core.crypto.aes import AESCipher
from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.core.settings import settings
from cashu.mint import migrations as mint_migrations
from cashu.mint.encrypt import cli
from tests.mint.test_mint_init import DECRYPTON_KEY, ENCRYPTED_SEED, SEED
from tests.mint.test_mint_mnemonic import MNEMONIC


async def insert_plaintext_keyset(db: Database):
    await migrate_databases(db, mint_migrations)
    async with db.connect() as conn:
        await conn.execute(
            f"""
            INSERT INTO {db.table_with_schema("keysets")} (id, seed, encrypted_seed)
            VALUES ('ks_plaintext', :seed, NULL)
            """,
            {"seed": SEED},
        )
    await db.engine.dispose()


async def get_keyset(db: Database):
    async with db.connect() as conn:
        row = await conn.fetchone(
            f"SELECT seed, encrypted_seed, seed_encryption_method FROM {db.table_with_schema('keysets')} WHERE id = 'ks_plaintext'"
        )
    await db.engine.dispose()
    return row


@pytest.mark.parametrize(
    "mint_private_key,mint_mnemonic",
    [(SEED, None), (ENCRYPTED_SEED, None), (None, MNEMONIC)],
    ids=["plaintext", "encrypted", "mnemonic"],
)
def test_migrate_encrypts_plaintext_seeds(
    tmp_path, monkeypatch, mint_private_key, mint_mnemonic
):
    db_path = str(tmp_path / "mint")
    monkeypatch.setattr(settings, "mint_database", db_path)
    monkeypatch.setattr(settings, "mint_seed_decryption_key", DECRYPTON_KEY)
    monkeypatch.setattr(settings, "mint_private_key", mint_private_key)
    monkeypatch.setattr(settings, "mint_mnemonic", mint_mnemonic)
    asyncio.run(insert_plaintext_keyset(Database("mint", db_path)))

    runner = CliRunner()
    result = runner.invoke(cli, ["migrate", "--no-dry-run"], input="y\n")
    assert result.exception is None
    assert "Migration complete." in result.output

    row = asyncio.run(get_keyset(Database("mint", db_path)))
    assert row["seed"] == ""
    assert row["seed_encryption_method"] == "aes"
    assert AESCipher(DECRYPTON_KEY).decrypt(row["encrypted_seed"]) == SEED
