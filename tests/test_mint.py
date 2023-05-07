from typing import List

import pytest

from cashu.core.base import BlindedMessage, Proof
from cashu.core.migrations import migrate_databases

SERVER_ENDPOINT = "http://localhost:3338"

from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from tests.conftest import ledger


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
async def test_pubkeys(ledger: Ledger):
    assert ledger.keyset.public_keys
    assert (
        ledger.keyset.public_keys[1].serialize().hex()
        == "03190ebc0c3e2726a5349904f572a2853ea021b0128b269b8b6906501d262edaa8"
    )
    assert (
        ledger.keyset.public_keys[2 ** (settings.max_order - 1)].serialize().hex()
        == "032dc008b88b85fdc2301a499bfaaef774c191a6307d8c9434838fc2eaa2e48d51"
    )


@pytest.mark.asyncio
async def test_privatekeys(ledger: Ledger):
    assert ledger.keyset.private_keys
    assert (
        ledger.keyset.private_keys[1].serialize()
        == "67de62e1bf8b5ccf88dbad6768b7d13fa0f41433b0a89caf915039505f2e00a7"
    )
    assert (
        ledger.keyset.private_keys[2 ** (settings.max_order - 1)].serialize()
        == "3b1340c703b02028a11025302d2d9e68d2a6dd721ab1a2770f0942d15eacb8d0"
    )


@pytest.mark.asyncio
async def test_keysets(ledger: Ledger):
    assert len(ledger.keysets.keysets)
    assert len(ledger.keysets.get_ids())
    assert ledger.keyset.id == "1cCNIAZ2X/w1"


@pytest.mark.asyncio
async def test_get_keyset(ledger: Ledger):
    keyset = ledger.get_keyset()
    assert type(keyset) == dict
    assert len(keyset) == settings.max_order


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
        == "037074c4f53e326ee14ed67125f387d160e0e729351471b69ad41f7d5d21071e15"
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
        == "037074c4f53e326ee14ed67125f387d160e0e729351471b69ad41f7d5d21071e15"
    )
