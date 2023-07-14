import asyncio
import secrets
from typing import List

import pytest
import pytest_asyncio

from cashu.core.base import Proof, Secret, SecretKind, Tags
from cashu.core.crypto.secp import PrivateKey, PublicKey
from cashu.core.helpers import async_unwrap, sum_proofs
from cashu.core.migrations import migrate_databases
from cashu.core.settings import settings
from cashu.wallet import migrations
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from cashu.wallet.wallet import Wallet as Wallet2
from tests.conftest import SERVER_ENDPOINT, mint


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        if str(exc.args[0]) != msg:
            raise Exception(f"Expected error: {msg}, got: {exc.args[0]}")
        return
    raise Exception(f"Expected error: {msg}, got no error")


def assert_amt(proofs: List[Proof], expected: int):
    """Assert amounts the proofs contain."""
    assert [p.amount for p in proofs] == expected


@pytest_asyncio.fixture(scope="function")
async def wallet1(mint):
    wallet1 = Wallet1(SERVER_ENDPOINT, "data/wallet1", "wallet1")
    await migrate_databases(wallet1.db, migrations)
    await wallet1.load_mint()
    wallet1.status()
    yield wallet1


@pytest_asyncio.fixture(scope="function")
async def wallet2(mint):
    wallet2 = Wallet2(SERVER_ENDPOINT, "data/wallet2", "wallet2")
    await migrate_databases(wallet2.db, migrations)
    await wallet2.load_mint()
    wallet2.status()
    yield wallet2


@pytest.mark.asyncio
async def test_get_keys(wallet1: Wallet):
    assert wallet1.keys.public_keys
    assert len(wallet1.keys.public_keys) == settings.max_order
    keyset = await wallet1._get_keys(wallet1.url)
    assert keyset.id is not None
    assert type(keyset.id) == str
    assert len(keyset.id) > 0


@pytest.mark.asyncio
async def test_get_keyset(wallet1: Wallet):
    assert wallet1.keys.public_keys
    assert len(wallet1.keys.public_keys) == settings.max_order
    # let's get the keys first so we can get a keyset ID that we use later
    keys1 = await wallet1._get_keys(wallet1.url)
    # gets the keys of a specific keyset
    assert keys1.id is not None
    assert keys1.public_keys is not None
    keys2 = await wallet1._get_keys_of_keyset(wallet1.url, keys1.id)
    assert keys2.public_keys is not None
    assert len(keys1.public_keys) == len(keys2.public_keys)


@pytest.mark.asyncio
async def test_get_info(wallet1: Wallet):
    info = await wallet1._get_info(wallet1.url)
    assert info.name


@pytest.mark.asyncio
async def test_get_nonexistent_keyset(wallet1: Wallet):
    await assert_err(
        wallet1._get_keys_of_keyset(wallet1.url, "nonexistent"),
        "Mint Error: keyset does not exist",
    )


@pytest.mark.asyncio
async def test_get_keyset_ids(wallet1: Wallet):
    keyset = await wallet1._get_keyset_ids(wallet1.url)
    assert type(keyset) == list
    assert len(keyset) > 0
    assert keyset[-1] == wallet1.keyset_id


@pytest.mark.asyncio
async def test_mint(wallet1: Wallet):
    await wallet1.mint(64)
    assert wallet1.balance == 64


@pytest.mark.asyncio
async def test_mint_amounts(wallet1: Wallet):
    """Mint predefined amounts"""
    amts = [1, 1, 1, 2, 2, 4, 16]
    await wallet1.mint(amount=sum(amts), split=amts)
    assert wallet1.balance == 27
    assert wallet1.proof_amounts == amts


@pytest.mark.asyncio
async def test_mint_amounts_wrong_sum(wallet1: Wallet):
    """Mint predefined amounts"""
    amts = [1, 1, 1, 2, 2, 4, 16]
    await assert_err(
        wallet1.mint(amount=sum(amts) + 1, split=amts),
        "split must sum to amount",
    )


@pytest.mark.asyncio
async def test_mint_amounts_wrong_order(wallet1: Wallet):
    """Mint amount that is not part in 2^n"""
    amts = [1, 2, 3]
    await assert_err(
        wallet1.mint(amount=sum(amts), split=[1, 2, 3]),
        f"Can only mint amounts with 2^n up to {2**settings.max_order}.",
    )


@pytest.mark.asyncio
async def test_split(wallet1: Wallet):
    await wallet1.mint(64)
    p1, p2 = await wallet1.split(wallet1.proofs, 20)
    assert wallet1.balance == 64
    assert sum_proofs(p1) == 44
    assert [p.amount for p in p1] == [4, 8, 32]
    assert sum_proofs(p2) == 20
    assert [p.amount for p in p2] == [4, 16]
    assert all([p.id == wallet1.keyset_id for p in p1])
    assert all([p.id == wallet1.keyset_id for p in p2])


@pytest.mark.asyncio
async def test_split_to_send(wallet1: Wallet):
    await wallet1.mint(64)
    keep_proofs, spendable_proofs = await wallet1.split_to_send(
        wallet1.proofs, 32, set_reserved=True
    )
    get_spendable = await wallet1._select_proofs_to_send(wallet1.proofs, 32)
    assert keep_proofs == get_spendable

    assert sum_proofs(spendable_proofs) == 32
    assert wallet1.balance == 64
    assert wallet1.available_balance == 32


@pytest.mark.asyncio
async def test_split_more_than_balance(wallet1: Wallet):
    await wallet1.mint(64)
    await assert_err(
        wallet1.split(wallet1.proofs, 128),
        "Mint Error: inputs do not have same amount as outputs",
    )
    assert wallet1.balance == 64


@pytest.mark.asyncio
async def test_split_to_send_more_than_balance(wallet1: Wallet):
    await wallet1.mint(64)
    await assert_err(
        wallet1.split_to_send(wallet1.proofs, 128, set_reserved=True),
        "balance too low.",
    )
    assert wallet1.balance == 64
    assert wallet1.available_balance == 64


@pytest.mark.asyncio
async def test_double_spend(wallet1: Wallet):
    doublespend = await wallet1.mint(64)
    await wallet1.split(wallet1.proofs, 20)
    await assert_err(
        wallet1.split(doublespend, 20),
        f"Mint Error: tokens already spent. Secret: {doublespend[0]['secret']}",
    )
    assert wallet1.balance == 64
    assert wallet1.available_balance == 64


@pytest.mark.asyncio
async def test_duplicate_proofs_double_spent(wallet1: Wallet):
    doublespend = await wallet1.mint(64)
    await assert_err(
        wallet1.split(wallet1.proofs + doublespend, 20),
        "Mint Error: proofs already pending.",
    )
    assert wallet1.balance == 64
    assert wallet1.available_balance == 64


@pytest.mark.asyncio
async def test_send_and_redeem(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    _, spendable_proofs = await wallet1.split_to_send(  # type: ignore
        wallet1.proofs, 32, set_reserved=True
    )
    await wallet2.redeem(spendable_proofs)
    assert wallet2.balance == 32

    assert wallet1.balance == 64
    assert wallet1.available_balance == 32
    await wallet1.invalidate(spendable_proofs)
    assert wallet1.balance == 32
    assert wallet1.available_balance == 32


@pytest.mark.asyncio
async def test_invalidate_unspent_proofs(wallet1: Wallet):
    """Try to invalidate proofs that have not been spent yet. Should not work!"""
    await wallet1.mint(64)
    await wallet1.invalidate(wallet1.proofs)
    assert wallet1.balance == 64


@pytest.mark.asyncio
async def test_invalidate_unspent_proofs_without_checking(wallet1: Wallet):
    """Try to invalidate proofs that have not been spent yet but force no check."""
    await wallet1.mint(64)
    await wallet1.invalidate(wallet1.proofs, check_spendable=False)
    assert wallet1.balance == 0


@pytest.mark.asyncio
async def test_split_invalid_amount(wallet1: Wallet):
    await wallet1.mint(64)
    await assert_err(
        wallet1.split(wallet1.proofs, -1),
        "amount must be positive.",
    )


@pytest.mark.asyncio
async def test_create_p2pk_pubkey(wallet1: Wallet):
    await wallet1.mint(64)
    pubkey = await wallet1.create_p2pk_pubkey()
    PublicKey(bytes.fromhex(pubkey), raw=True)


@pytest.mark.asyncio
async def test_p2pk(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(pubkey_wallet2)  # sender side
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    await wallet2.redeem(send_proofs)


@pytest.mark.asyncio
async def test_p2pk_receive_with_wrong_private_key(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # receiver side
    # sender side
    secret_lock = await wallet1.create_p2pk_lock(pubkey_wallet2)  # sender side
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # receiver side: wrong private key
    wallet1.private_key = PrivateKey()  # wrong private key
    await assert_err(wallet1.redeem(send_proofs), "Mint Error: p2pk signature invalid.")


@pytest.mark.asyncio
async def test_p2pk_short_timelock_receive_with_wrong_private_key(
    wallet1: Wallet, wallet2: Wallet
):
    await wallet1.mint(64)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # receiver side
    # sender side
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, timelock=4
    )  # sender side
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # receiver side: wrong private key
    wallet1.private_key = PrivateKey()  # wrong private key
    await assert_err(wallet1.redeem(send_proofs), "Mint Error: p2pk signature invalid.")
    await asyncio.sleep(6)
    await wallet1.redeem(send_proofs)


@pytest.mark.asyncio
async def test_p2pk_timelock_with_refund_pubkey(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # receiver side
    # sender side
    garbage_pubkey = PrivateKey().pubkey
    assert garbage_pubkey
    secret_lock = await wallet1.create_p2pk_lock(
        garbage_pubkey.serialize().hex(),  # create lock to unspendable pubkey
        timelock=4,  # timelock
        tags=Tags(__root__=[["refund", pubkey_wallet2]]),  # refund pubkey
    )  # sender side
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # receiver side: can't redeem since we used a garbage pubkey
    await assert_err(wallet2.redeem(send_proofs), "Mint Error: p2pk signature invalid.")
    await asyncio.sleep(6)
    # we can now redeem because of the refund timelock
    await wallet2.redeem(send_proofs)


@pytest.mark.asyncio
async def test_p2pk_timelock_with_wrong_refund_pubkey(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # receiver side
    # sender side
    garbage_pubkey = PrivateKey().pubkey
    garbage_pubkey_2 = PrivateKey().pubkey
    assert garbage_pubkey
    assert garbage_pubkey_2
    secret_lock = await wallet1.create_p2pk_lock(
        garbage_pubkey.serialize().hex(),  # create lock to unspendable pubkey
        timelock=4,  # timelock
        tags=Tags(
            __root__=[["refund", garbage_pubkey_2.serialize().hex()]]
        ),  # refund pubkey
    )  # sender side
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # receiver side: can't redeem since we used a garbage pubkey
    await assert_err(wallet2.redeem(send_proofs), "Mint Error: p2pk signature invalid.")
    await asyncio.sleep(6)
    # we still can't redeem it because we used garbage_pubkey_2 as a refund pubkey
    await assert_err(wallet2.redeem(send_proofs), "Mint Error: p2pk signature invalid.")


@pytest.mark.asyncio
async def test_p2sh(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    _ = await wallet1.create_p2sh_address_and_store()  # receiver side
    _, send_proofs = await wallet1.split_to_send(wallet1.proofs, 8)  # sender side

    frst_proofs, scnd_proofs = await wallet2.redeem(send_proofs)  # receiver side
    assert len(frst_proofs) == 0
    assert len(scnd_proofs) == 1
    assert sum_proofs(scnd_proofs) == 8
    assert wallet2.balance == 8


@pytest.mark.asyncio
async def test_p2sh_receive_with_wrong_wallet(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    wallet1_address = await wallet1.create_p2sh_address_and_store()  # receiver side
    secret_lock = await wallet1.create_p2sh_lock(wallet1_address)  # sender side
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock
    )  # sender side
    await assert_err(wallet2.redeem(send_proofs), "lock not found.")  # wrong receiver


@pytest.mark.asyncio
async def test_token_state(wallet1: Wallet):
    await wallet1.mint(64)
    assert wallet1.balance == 64
    resp = await wallet1.check_proof_state(wallet1.proofs)
    assert resp.dict()["spendable"]
    assert resp.dict()["pending"]
