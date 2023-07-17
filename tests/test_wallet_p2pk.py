import asyncio
import copy
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
    wallet1 = Wallet1(SERVER_ENDPOINT, "data/wallet_p2pk_1", "wallet1")
    await migrate_databases(wallet1.db, migrations)
    await wallet1.load_mint()
    wallet1.status()
    yield wallet1


@pytest_asyncio.fixture(scope="function")
async def wallet2(mint):
    wallet2 = Wallet2(SERVER_ENDPOINT, "data/wallet_p2pk_2", "wallet2")
    await migrate_databases(wallet2.db, migrations)
    wallet2.private_key = PrivateKey(secrets.token_bytes(32), raw=True)
    await wallet2.load_mint()
    wallet2.status()
    yield wallet2


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
    await assert_err(
        wallet1.redeem(send_proofs),
        "Mint Error: no valid signature provided for input.",
    )


@pytest.mark.asyncio
async def test_p2pk_short_locktime_receive_with_wrong_private_key(
    wallet1: Wallet, wallet2: Wallet
):
    await wallet1.mint(64)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # receiver side
    # sender side
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, locktime_seconds=4
    )  # sender side
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # receiver side: wrong private key
    wallet1.private_key = PrivateKey()  # wrong private key
    await assert_err(
        wallet1.redeem(send_proofs),
        "Mint Error: no valid signature provided for input.",
    )
    await asyncio.sleep(6)
    await wallet1.redeem(send_proofs)


@pytest.mark.asyncio
async def test_p2pk_locktime_with_refund_pubkey(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # receiver side
    # sender side
    garbage_pubkey = PrivateKey().pubkey
    assert garbage_pubkey
    secret_lock = await wallet1.create_p2pk_lock(
        garbage_pubkey.serialize().hex(),  # create lock to unspendable pubkey
        locktime_seconds=4,  # locktime
        tags=Tags(refund=pubkey_wallet2),  # refund pubkey
    )  # sender side
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    send_proofs_copy = copy.deepcopy(send_proofs)
    # receiver side: can't redeem since we used a garbage pubkey
    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: no valid signature provided for input.",
    )
    await asyncio.sleep(6)
    # we can now redeem because of the refund locktime
    await wallet2.redeem(send_proofs_copy)


@pytest.mark.asyncio
async def test_p2pk_locktime_with_wrong_refund_pubkey(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # receiver side
    # sender side
    garbage_pubkey = PrivateKey().pubkey
    garbage_pubkey_2 = PrivateKey().pubkey
    assert garbage_pubkey
    assert garbage_pubkey_2
    secret_lock = await wallet1.create_p2pk_lock(
        garbage_pubkey.serialize().hex(),  # create lock to unspendable pubkey
        locktime_seconds=4,  # locktime
        tags=Tags(refund=garbage_pubkey_2.serialize().hex()),  # refund pubkey
    )  # sender side
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    send_proofs_copy = copy.deepcopy(send_proofs)
    # receiver side: can't redeem since we used a garbage pubkey
    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: no valid signature provided for input.",
    )
    await asyncio.sleep(6)
    # we still can't redeem it because we used garbage_pubkey_2 as a refund pubkey
    await assert_err(
        wallet2.redeem(send_proofs_copy),
        "Mint Error: no valid signature provided for input.",
    )


@pytest.mark.asyncio
async def test_p2pk_multisig_2_of_2(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    assert pubkey_wallet1 != pubkey_wallet2
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=Tags(pubkey=pubkey_wallet1), n_sigs=2
    )

    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # add signatures of wallet2
    send_proofs = await wallet1.add_p2pk_witnesses_to_proofs(send_proofs)
    # here we add the signatures of wallet1
    await wallet2.redeem(send_proofs)


@pytest.mark.asyncio
async def test_p2pk_multisig_duplicate_signature(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    assert pubkey_wallet1 != pubkey_wallet2
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=Tags(pubkey=pubkey_wallet1), n_sigs=2
    )

    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # add signatures of wallet2
    send_proofs = await wallet2.add_p2pk_witnesses_to_proofs(send_proofs)
    # here we add the signatures of wallet1
    await assert_err(
        wallet2.redeem(send_proofs), "Mint Error: p2pk signatures must be unique."
    )


@pytest.mark.asyncio
async def test_p2pk_multisig_quorum_not_met_1_of_2(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    assert pubkey_wallet1 != pubkey_wallet2
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=Tags(pubkey=pubkey_wallet1), n_sigs=2
    )
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: not enough signatures provided: 1 < 2.",
    )


@pytest.mark.asyncio
async def test_p2pk_multisig_quorum_not_met_2_of_3(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    assert pubkey_wallet1 != pubkey_wallet2
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=Tags(pubkey=pubkey_wallet1), n_sigs=3
    )

    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # add signatures of wallet1
    send_proofs = await wallet1.add_p2pk_witnesses_to_proofs(send_proofs)
    # here we add the signatures of wallet2
    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: not enough signatures provided: 2 < 3.",
    )


@pytest.mark.asyncio
async def test_p2pk_multisig_with_duplicate_publickey(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=Tags(pubkey=pubkey_wallet2), n_sigs=2
    )
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    await assert_err(wallet2.redeem(send_proofs), "Mint Error: pubkeys must be unique.")


@pytest.mark.asyncio
async def test_p2pk_multisig_with_wrong_first_private_key(
    wallet1: Wallet, wallet2: Wallet
):
    await wallet1.mint(64)
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    wrong_pubklic_key = PrivateKey().pubkey
    assert wrong_pubklic_key
    wrong_public_key_hex = wrong_pubklic_key.serialize().hex()

    assert wrong_public_key_hex != pubkey_wallet2

    # p2pk test
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=Tags(pubkey=wrong_public_key_hex), n_sigs=2
    )
    _, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )
    # add signatures of wallet1
    send_proofs = await wallet1.add_p2pk_witnesses_to_proofs(send_proofs)
    await assert_err(
        wallet2.redeem(send_proofs), "Mint Error: signature threshold not met. 1 < 2."
    )
