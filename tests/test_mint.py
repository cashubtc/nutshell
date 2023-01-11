from typing import List

import pytest
import pytest_asyncio

from cashu.core.base import BlindedMessage, Proof
from cashu.core.migrations import migrate_databases

SERVER_ENDPOINT = "http://localhost:3338"

import os

from cashu.core.db import Database
from cashu.core.settings import MAX_ORDER
from cashu.mint import migrations
from cashu.mint.ledger import Ledger


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


async def start_mint_init(ledger):
    await migrate_databases(ledger.db, migrations)
    await ledger.load_used_proofs()
    await ledger.init_keysets()


@pytest_asyncio.fixture(scope="function")
async def ledger():
    db_file = "data/mint/test.sqlite3"
    if os.path.exists(db_file):
        os.remove(db_file)
    ledger = Ledger(
        db=Database("test", "data/mint"),
        seed="TEST_PRIVATE_KEY",
        derivation_path="0/0/0/0",
        lightning=None,
    )
    await start_mint_init(ledger)
    yield ledger


@pytest.mark.asyncio
async def test_keysets(ledger: Ledger):
    assert len(ledger.keysets.keysets)
    assert len(ledger.keysets.get_ids())
    assert ledger.keyset.id == "XQM1wwtQbOXE"


@pytest.mark.asyncio
async def test_get_keyset(ledger: Ledger):
    keyset = ledger.get_keyset()
    assert type(keyset) == dict
    assert len(keyset) == MAX_ORDER


@pytest.mark.asyncio
async def test_mint(ledger: Ledger):
    blinded_messages_mock = [
        BlindedMessage(
            amount=8,
            B_="02634a2c2b34bec9e8a4aba4361f6bf202d7fa2365379b0840afe249a7a9d71239",
        )
    ]
    promises = await ledger.mint(blinded_messages_mock)
    assert len(promises)
    assert promises[0].amount == 8
    assert (
        promises[0].C_
        == "032dfadd74bb3abba8170ecbae5401507e384eafd312defda94148fa37314c0ef0"
    )


@pytest.mark.asyncio
async def test_mint_invalid_blinded_message(ledger: Ledger):
    blinded_messages_mock_invalid_key = [
        BlindedMessage(
            amount=8,
            B_="02634a2c2b34bec9e8a4aba4361f6bff02d7fa2365379b0840afe249a7a9d71237",
        )
    ]
    await assert_err(
        ledger.mint(blinded_messages_mock_invalid_key), "invalid public key"
    )


@pytest.mark.asyncio
async def test_generate_promises(ledger: Ledger):
    blinded_messages_mock = [
        BlindedMessage(
            amount=8,
            B_="02634a2c2b34bec9e8a4aba4361f6bf202d7fa2365379b0840afe249a7a9d71239",
        )
    ]
    promises = await ledger._generate_promises(blinded_messages_mock)
    assert (
        promises[0].C_
        == "032dfadd74bb3abba8170ecbae5401507e384eafd312defda94148fa37314c0ef0"
    )
