import asyncio
import hashlib
import secrets
from typing import List

import pytest
import pytest_asyncio

from cashu.core.base import Proof
from cashu.core.crypto.secp import PrivateKey
from cashu.core.htlc import HTLCSecret
from cashu.core.migrations import migrate_databases
from cashu.wallet import migrations
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from cashu.wallet.wallet import Wallet as Wallet2
from tests.conftest import SERVER_ENDPOINT


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        if msg not in str(exc.args[0]):
            raise Exception(f"Expected error: {msg}, got: {exc.args[0]}")
        return
    raise Exception(f"Expected error: {msg}, got no error")


def assert_amt(proofs: List[Proof], expected: int):
    """Assert amounts the proofs contain."""
    assert [p.amount for p in proofs] == expected


@pytest_asyncio.fixture(scope="function")
async def wallet1(mint):
    wallet1 = await Wallet1.with_db(
        SERVER_ENDPOINT, "test_data/wallet_p2pk_1", "wallet1"
    )
    await migrate_databases(wallet1.db, migrations)
    await wallet1.load_mint()
    wallet1.status()
    yield wallet1


@pytest_asyncio.fixture(scope="function")
async def wallet2(mint):
    wallet2 = await Wallet2.with_db(
        SERVER_ENDPOINT, "test_data/wallet_p2pk_2", "wallet2"
    )
    await migrate_databases(wallet2.db, migrations)
    wallet2.private_key = PrivateKey(secrets.token_bytes(32), raw=True)
    await wallet2.load_mint()
    wallet2.status()
    yield wallet2


@pytest.mark.asyncio
async def test_create_htlc_secret(wallet1: Wallet):
    await wallet1.mint(64)
    preimage = "00000000000000000000000000000000"
    preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(preimage=preimage)
    assert secret.data == preimage_hash


@pytest.mark.asyncio
async def test_htlc_split(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    preimage = "00000000000000000000000000000000"
    preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(preimage=preimage)
    # p2pk test
    _, send_proofs = await wallet1.split_to_send(wallet1.proofs, 8, secret_lock=secret)
    for p in send_proofs:
        assert HTLCSecret.deserialize(p.secret).data == preimage_hash


@pytest.mark.asyncio
async def test_htlc_redeem_with_preimage(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    preimage = "00000000000000000000000000000000"
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(preimage=preimage)
    # p2pk test
    _, send_proofs = await wallet1.split_to_send(wallet1.proofs, 8, secret_lock=secret)
    for p in send_proofs:
        p.htlcpreimage = preimage
    await wallet2.redeem(send_proofs)


@pytest.mark.asyncio
async def test_htlc_redeem_with_wrong_preimage(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    preimage = "00000000000000000000000000000000"
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(preimage=preimage[:-1] + "1")
    # p2pk test
    _, send_proofs = await wallet1.split_to_send(wallet1.proofs, 8, secret_lock=secret)
    for p in send_proofs:
        p.htlcpreimage = preimage
    await assert_err(
        wallet2.redeem(send_proofs), "Mint Error: HTLC preimage does not match"
    )


@pytest.mark.asyncio
async def test_htlc_redeem_with_no_signature(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    preimage = "00000000000000000000000000000000"
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=preimage, hacklock_pubkey=pubkey_wallet1
    )
    # p2pk test
    _, send_proofs = await wallet1.split_to_send(wallet1.proofs, 8, secret_lock=secret)
    for p in send_proofs:
        p.htlcpreimage = preimage
    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: HTLC no hash lock signatures provided.",
    )


@pytest.mark.asyncio
async def test_htlc_redeem_with_wrong_signature(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    preimage = "00000000000000000000000000000000"
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=preimage, hacklock_pubkey=pubkey_wallet1
    )
    # p2pk test
    _, send_proofs = await wallet1.split_to_send(wallet1.proofs, 8, secret_lock=secret)

    signatures = await wallet1.sign_p2pk_proofs(send_proofs)
    for p, s in zip(send_proofs, signatures):
        p.htlcpreimage = preimage
        p.htlcsignature = s[:-1] + "1"  # wrong signature

    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: HTLC hash lock signatures did not match.",
    )


@pytest.mark.asyncio
async def test_htlc_redeem_with_correct_signature(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    preimage = "00000000000000000000000000000000"
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=preimage, hacklock_pubkey=pubkey_wallet1
    )
    # p2pk test
    _, send_proofs = await wallet1.split_to_send(wallet1.proofs, 8, secret_lock=secret)

    signatures = await wallet1.sign_p2pk_proofs(send_proofs)
    for p, s in zip(send_proofs, signatures):
        p.htlcpreimage = preimage
        p.htlcsignature = s

    await wallet2.redeem(send_proofs)


@pytest.mark.asyncio
async def test_htlc_redeem_hashlock_wrong_signature_timelock_correct_signature(
    wallet1: Wallet, wallet2: Wallet
):
    await wallet1.mint(64)
    preimage = "00000000000000000000000000000000"
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=preimage,
        hacklock_pubkey=pubkey_wallet2,
        locktime_seconds=5,
        locktime_pubkey=pubkey_wallet1,
    )
    # p2pk test
    _, send_proofs = await wallet1.split_to_send(wallet1.proofs, 8, secret_lock=secret)

    signatures = await wallet1.sign_p2pk_proofs(send_proofs)
    for p, s in zip(send_proofs, signatures):
        p.htlcpreimage = preimage
        p.htlcsignature = s

    # should error because we used wallet2 signatures for the hash lock
    await assert_err(
        wallet1.redeem(send_proofs),
        "Mint Error: HTLC hash lock signatures did not match.",
    )

    await asyncio.sleep(5)
    # should succeed since lock time has passed and we provided wallet1 signature for timelock
    await wallet1.redeem(send_proofs)


@pytest.mark.asyncio
async def test_htlc_redeem_hashlock_wrong_signature_timelock_wrong_signature(
    wallet1: Wallet, wallet2: Wallet
):
    await wallet1.mint(64)
    preimage = "00000000000000000000000000000000"
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=preimage,
        hacklock_pubkey=pubkey_wallet2,
        locktime_seconds=5,
        locktime_pubkey=pubkey_wallet1,
    )
    # p2pk test
    _, send_proofs = await wallet1.split_to_send(wallet1.proofs, 8, secret_lock=secret)

    signatures = await wallet1.sign_p2pk_proofs(send_proofs)
    for p, s in zip(send_proofs, signatures):
        p.htlcpreimage = preimage
        p.htlcsignature = s[:-1] + "1"  # wrong signature

    # should error because we used wallet2 signatures for the hash lock
    await assert_err(
        wallet1.redeem(send_proofs),
        "Mint Error: HTLC hash lock signatures did not match.",
    )

    await asyncio.sleep(5)
    # should fail since lock time has passed and we provided a wrong signature for timelock
    await assert_err(
        wallet1.redeem(send_proofs),
        "Mint Error: HTLC refund signatures did not match.",
    )
