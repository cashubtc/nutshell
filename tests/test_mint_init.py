from typing import List

import pytest

from cashu.core.base import Proof
from cashu.core.crypto.aes import AESCipher
from cashu.core.db import Database
from cashu.core.settings import settings
from cashu.mint.crud import LedgerCrudSqlite
from cashu.mint.ledger import Ledger

SEED = "TEST_PRIVATE_KEY"
DERIVATION_PATH = "m/0'/0'/0'"
DECRYPTON_KEY = "testdecryptionkey"
ENCRYPTED_SEED = "U2FsdGVkX1_7UU_-nVBMBWDy_9yDu4KeYb7MH8cJTYQGD4RWl82PALH8j-HKzTrI"


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        assert exc.args[0] == msg, Exception(
            f"Expected error: {msg}, got: {exc.args[0]}"
        )


def assert_amt(proofs: List[Proof], expected: int):
    """Assert amounts the proofs contain."""
    assert [p.amount for p in proofs] == expected


@pytest.mark.asyncio
async def test_init_keysets_with_duplicates(ledger: Ledger):
    ledger.keysets = {}
    await ledger.init_keysets(duplicate_keysets=True)
    assert len(ledger.keysets) == 2


@pytest.mark.asyncio
async def test_init_keysets_with_duplicates_via_settings(ledger: Ledger):
    ledger.keysets = {}
    settings.mint_duplicate_keysets = True
    await ledger.init_keysets()
    assert len(ledger.keysets) == 2


@pytest.mark.asyncio
async def test_init_keysets_without_duplicates(ledger: Ledger):
    ledger.keysets = {}
    await ledger.init_keysets(duplicate_keysets=False)
    assert len(ledger.keysets) == 1


@pytest.mark.asyncio
async def test_init_keysets_without_duplicates_via_settings(ledger: Ledger):
    ledger.keysets = {}
    settings.mint_duplicate_keysets = False
    await ledger.init_keysets()
    assert len(ledger.keysets) == 1


@pytest.mark.asyncio
async def test_ledger_encrypt():
    aes = AESCipher(DECRYPTON_KEY)
    encrypted = aes.encrypt(SEED.encode())
    assert aes.decrypt(encrypted) == SEED


@pytest.mark.asyncio
async def test_ledger_decrypt():
    aes = AESCipher(DECRYPTON_KEY)
    assert aes.decrypt(ENCRYPTED_SEED) == SEED


@pytest.mark.asyncio
async def test_decrypt_seed():
    ledger = Ledger(
        db=Database("mint", settings.mint_database),
        seed=SEED,
        seed_decryption_key=None,
        derivation_path=DERIVATION_PATH,
        backends={},
        crud=LedgerCrudSqlite(),
    )
    await ledger.init_keysets()
    assert ledger.keyset.seed == SEED
    private_key_1 = (
        ledger.keysets[list(ledger.keysets.keys())[0]].private_keys[1].serialize()
    )
    assert (
        private_key_1
        == "8300050453f08e6ead1296bb864e905bd46761beed22b81110fae0751d84604d"
    )
    pubkeys = ledger.keysets[list(ledger.keysets.keys())[0]].public_keys
    assert pubkeys
    assert (
        pubkeys[1].serialize().hex()
        == "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
    )

    ledger_encrypted = Ledger(
        db=Database("mint", settings.mint_database),
        seed=ENCRYPTED_SEED,
        seed_decryption_key=DECRYPTON_KEY,
        derivation_path=DERIVATION_PATH,
        backends={},
        crud=LedgerCrudSqlite(),
    )
    await ledger_encrypted.init_keysets()
    assert ledger_encrypted.keyset.seed == SEED
    private_key_1 = (
        ledger_encrypted.keysets[list(ledger_encrypted.keysets.keys())[0]]
        .private_keys[1]
        .serialize()
    )
    assert (
        private_key_1
        == "8300050453f08e6ead1296bb864e905bd46761beed22b81110fae0751d84604d"
    )
    pubkeys_encrypted = ledger_encrypted.keysets[
        list(ledger_encrypted.keysets.keys())[0]
    ].public_keys
    assert pubkeys_encrypted
    assert (
        pubkeys_encrypted[1].serialize().hex()
        == "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
    )
