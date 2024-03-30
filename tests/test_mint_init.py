from typing import List

import pytest

from cashu.core.base import MeltQuote, Proof, SpentState
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


async def create_pending_melts(ledger: Ledger) -> Proof:
    quote_id = "test1"
    await ledger.crud.store_melt_quote(
        quote=MeltQuote(
            quote=quote_id,
            method="bolt11",
            request="asdasd",
            checking_id="checking_id",
            unit="sat",
            paid=False,
            amount=100,
            fee_reserve=1,
        ),
        db=ledger.db,
    )
    pending_proof = Proof(amount=123, C="asdasd", secret="asdasd", id=quote_id)
    await ledger.crud.set_proof_pending(
        db=ledger.db,
        proof=pending_proof,
        quote_id=quote_id,
    )
    # expect that no pending tokens are in db anymore
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert melt_quotes
    return pending_proof


@pytest.mark.asyncio
async def test_startup_pending_quote_success(ledger: Ledger):
    pending_proof = await create_pending_melts(ledger)
    states = await ledger.check_proofs_state([pending_proof.Y])
    assert states[0].state == SpentState.pending
    settings.fakewallet_payment_state = True
    # run startup routinge
    await ledger.startup_ledger()

    # expect that no pending tokens are in db anymore
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert not melt_quotes

    # expect that proofs are spent
    states = await ledger.check_proofs_state([pending_proof.Y])
    assert states[0].state == SpentState.spent


@pytest.mark.asyncio
async def test_startup_pending_quote_failure(ledger: Ledger):
    pending_proof = await create_pending_melts(ledger)
    states = await ledger.check_proofs_state([pending_proof.Y])
    assert states[0].state == SpentState.pending
    settings.fakewallet_payment_state = False
    # run startup routinge
    await ledger.startup_ledger()

    # expect that no pending tokens are in db anymore
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert not melt_quotes

    # expect that proofs are unspent
    states = await ledger.check_proofs_state([pending_proof.Y])
    assert states[0].state == SpentState.unspent


@pytest.mark.asyncio
async def test_startup_pending_quote_pending(ledger: Ledger):
    pending_proof = await create_pending_melts(ledger)
    states = await ledger.check_proofs_state([pending_proof.Y])
    assert states[0].state == SpentState.pending
    settings.fakewallet_payment_state = None
    # run startup routinge
    await ledger.startup_ledger()

    # expect that melt quote is still pending
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert melt_quotes

    # expect that proofs are unspent
    states = await ledger.check_proofs_state([pending_proof.Y])
    assert states[0].state == SpentState.pending
