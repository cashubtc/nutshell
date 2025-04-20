import asyncio
import hashlib
import secrets
from typing import List

import pytest
import pytest_asyncio

from cashu.core.base import HTLCWitness, Proof
from cashu.core.crypto.secp import PrivateKey
from cashu.core.htlc import HTLCSecret
from cashu.core.migrations import migrate_databases
from cashu.wallet import migrations
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from cashu.wallet.wallet import Wallet as Wallet2
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import pay_if_regtest


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
async def wallet1():
    wallet1 = await Wallet1.with_db(
        SERVER_ENDPOINT, "test_data/wallet_p2pk_1", "wallet1"
    )
    await migrate_databases(wallet1.db, migrations)
    await wallet1.load_mint()
    yield wallet1


@pytest_asyncio.fixture(scope="function")
async def wallet2():
    wallet2 = await Wallet2.with_db(
        SERVER_ENDPOINT, "test_data/wallet_p2pk_2", "wallet2"
    )
    await migrate_databases(wallet2.db, migrations)
    wallet2.private_key = PrivateKey(secrets.token_bytes(32), raw=True)
    await wallet2.load_mint()
    yield wallet2


@pytest.mark.asyncio
async def test_create_htlc_secret(wallet1: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    preimage = "00000000000000000000000000000000"
    preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(preimage=preimage)
    assert secret.data == preimage_hash


@pytest.mark.asyncio
async def test_htlc_split(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    preimage = "00000000000000000000000000000000"
    preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(preimage=preimage)
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 8, secret_lock=secret)
    for p in send_proofs:
        assert HTLCSecret.deserialize(p.secret).data == preimage_hash


@pytest.mark.asyncio
async def test_htlc_redeem_with_preimage(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    preimage = "00000000000000000000000000000000"
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(preimage=preimage)
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 8, secret_lock=secret)
    for p in send_proofs:
        p.witness = HTLCWitness(preimage=preimage).json()
    await wallet2.redeem(send_proofs)


@pytest.mark.asyncio
async def test_htlc_redeem_with_wrong_preimage(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    preimage = "00000000000000000000000000000000"
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=f"{preimage[:-5]}11111"
    )  # wrong preimage
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 8, secret_lock=secret)
    for p in send_proofs:
        p.witness = HTLCWitness(preimage=preimage).json()
    await assert_err(
        wallet2.redeem(send_proofs), "Mint Error: HTLC preimage does not match"
    )


@pytest.mark.asyncio
async def test_htlc_redeem_with_no_signature(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    preimage = "00000000000000000000000000000000"
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=preimage, hashlock_pubkeys=[pubkey_wallet1]
    )
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 8, secret_lock=secret)
    for p in send_proofs:
        p.witness = HTLCWitness(preimage=preimage).json()
    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: no signatures in proof.",
    )


@pytest.mark.asyncio
async def test_htlc_redeem_with_wrong_signature(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    preimage = "00000000000000000000000000000000"
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=preimage, hashlock_pubkeys=[pubkey_wallet1]
    )
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 8, secret_lock=secret)
    signatures = wallet1.signatures_proofs_sig_inputs(send_proofs)
    for p, s in zip(send_proofs, signatures):
        p.witness = HTLCWitness(
            preimage=preimage, signatures=[f"{s[:-5]}11111"]
        ).json()  # wrong signature

    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: signature threshold not met",
    )


@pytest.mark.asyncio
async def test_htlc_redeem_with_correct_signature(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    preimage = "00000000000000000000000000000000"
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=preimage, hashlock_pubkeys=[pubkey_wallet1]
    )
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 8, secret_lock=secret)

    signatures = wallet1.signatures_proofs_sig_inputs(send_proofs)
    for p, s in zip(send_proofs, signatures):
        p.witness = HTLCWitness(preimage=preimage, signatures=[s]).json()

    await wallet2.redeem(send_proofs)


@pytest.mark.asyncio
async def test_htlc_redeem_with_2_of_1_signatures(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    preimage = "00000000000000000000000000000000"
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=preimage,
        hashlock_pubkeys=[pubkey_wallet1, pubkey_wallet2],
        hashlock_n_sigs=1,
    )
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 8, secret_lock=secret)

    signatures1 = wallet1.signatures_proofs_sig_inputs(send_proofs)
    signatures2 = wallet2.signatures_proofs_sig_inputs(send_proofs)
    for p, s1, s2 in zip(send_proofs, signatures1, signatures2):
        p.witness = HTLCWitness(preimage=preimage, signatures=[s1, s2]).json()

    await wallet2.redeem(send_proofs)


@pytest.mark.asyncio
async def test_htlc_redeem_with_2_of_2_signatures(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    preimage = "00000000000000000000000000000000"
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=preimage,
        hashlock_pubkeys=[pubkey_wallet1, pubkey_wallet2],
        hashlock_n_sigs=2,
    )
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 8, secret_lock=secret)

    signatures1 = wallet1.signatures_proofs_sig_inputs(send_proofs)
    signatures2 = wallet2.signatures_proofs_sig_inputs(send_proofs)
    for p, s1, s2 in zip(send_proofs, signatures1, signatures2):
        p.witness = HTLCWitness(preimage=preimage, signatures=[s1, s2]).json()

    await wallet2.redeem(send_proofs)


@pytest.mark.asyncio
async def test_htlc_redeem_with_2_of_2_signatures_with_duplicate_pubkeys(
    wallet1: Wallet, wallet2: Wallet
):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    preimage = "00000000000000000000000000000000"
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = pubkey_wallet1
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=preimage,
        hashlock_pubkeys=[pubkey_wallet1, pubkey_wallet2],
        hashlock_n_sigs=2,
    )
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 8, secret_lock=secret)

    signatures1 = wallet1.signatures_proofs_sig_inputs(send_proofs)
    signatures2 = wallet2.signatures_proofs_sig_inputs(send_proofs)
    for p, s1, s2 in zip(send_proofs, signatures1, signatures2):
        p.witness = HTLCWitness(preimage=preimage, signatures=[s1, s2]).json()

    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: pubkeys must be unique.",
    )


@pytest.mark.asyncio
async def test_htlc_redeem_with_3_of_3_signatures_but_only_2_provided(
    wallet1: Wallet, wallet2: Wallet
):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    preimage = "00000000000000000000000000000000"
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=preimage,
        hashlock_pubkeys=[pubkey_wallet1, pubkey_wallet2],
        hashlock_n_sigs=3,
    )
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 8, secret_lock=secret)

    signatures1 = wallet1.signatures_proofs_sig_inputs(send_proofs)
    signatures2 = wallet2.signatures_proofs_sig_inputs(send_proofs)
    for p, s1, s2 in zip(send_proofs, signatures1, signatures2):
        p.witness = HTLCWitness(preimage=preimage, signatures=[s1, s2]).json()

    await assert_err(
        wallet2.redeem(send_proofs),
        "Mint Error: not enough pubkeys (2) or signatures (2) present for n_sigs (3).",
    )


@pytest.mark.asyncio
async def test_htlc_redeem_with_2_of_3_signatures_with_2_valid_and_1_invalid_provided(
    wallet1: Wallet, wallet2: Wallet
):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    preimage = "00000000000000000000000000000000"
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    privatekey_wallet3 = PrivateKey(secrets.token_bytes(32), raw=True)
    assert privatekey_wallet3.pubkey
    pubkey_wallet3 = privatekey_wallet3.pubkey.serialize().hex()

    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=preimage,
        hashlock_pubkeys=[pubkey_wallet1, pubkey_wallet2, pubkey_wallet3],
        hashlock_n_sigs=2,
    )
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 8, secret_lock=secret)

    signatures1 = wallet1.signatures_proofs_sig_inputs(send_proofs)
    signatures2 = wallet2.signatures_proofs_sig_inputs(send_proofs)
    signatures3 = [f"{s[:-5]}11111" for s in signatures1]  # wrong signature
    for p, s1, s2, s3 in zip(send_proofs, signatures1, signatures2, signatures3):
        p.witness = HTLCWitness(preimage=preimage, signatures=[s1, s2, s3]).json()

    await wallet2.redeem(send_proofs)


@pytest.mark.asyncio
async def test_htlc_redeem_with_3_of_3_signatures_with_2_valid_and_1_invalid_provided(
    wallet1: Wallet, wallet2: Wallet
):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    preimage = "00000000000000000000000000000000"
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    privatekey_wallet3 = PrivateKey(secrets.token_bytes(32), raw=True)
    assert privatekey_wallet3.pubkey
    pubkey_wallet3 = privatekey_wallet3.pubkey.serialize().hex()

    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=preimage,
        hashlock_pubkeys=[pubkey_wallet1, pubkey_wallet2, pubkey_wallet3],
        hashlock_n_sigs=3,
    )
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 8, secret_lock=secret)

    signatures1 = wallet1.signatures_proofs_sig_inputs(send_proofs)
    signatures2 = wallet2.signatures_proofs_sig_inputs(send_proofs)
    signatures3 = [f"{s[:-5]}11111" for s in signatures1]  # wrong signature
    for p, s1, s2, s3 in zip(send_proofs, signatures1, signatures2, signatures3):
        p.witness = HTLCWitness(preimage=preimage, signatures=[s1, s2, s3]).json()

    await assert_err(
        wallet2.redeem(send_proofs), "Mint Error: signature threshold not met. 2 < 3."
    )


@pytest.mark.asyncio
async def test_htlc_redeem_hashlock_wrong_signature_timelock_correct_signature(
    wallet1: Wallet, wallet2: Wallet
):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    preimage = "00000000000000000000000000000000"
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=preimage,
        hashlock_pubkeys=[pubkey_wallet2],
        locktime_seconds=2,
        locktime_pubkeys=[pubkey_wallet1],
    )
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 8, secret_lock=secret)

    signatures = wallet1.signatures_proofs_sig_inputs(send_proofs)
    for p, s in zip(send_proofs, signatures):
        p.witness = HTLCWitness(preimage=preimage, signatures=[s]).json()

    # should error because we used wallet2 signatures for the hash lock
    await assert_err(
        wallet1.redeem(send_proofs),
        "Mint Error: signature threshold not met",
    )

    await asyncio.sleep(2)
    # should succeed since lock time has passed and we provided wallet1 signature for timelock
    await wallet1.redeem(send_proofs)


@pytest.mark.asyncio
async def test_htlc_redeem_hashlock_wrong_signature_timelock_wrong_signature(
    wallet1: Wallet, wallet2: Wallet
):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    preimage = "00000000000000000000000000000000"
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=preimage,
        hashlock_pubkeys=[pubkey_wallet2],
        locktime_seconds=2,
        locktime_pubkeys=[pubkey_wallet1, pubkey_wallet2],
        locktime_n_sigs=2,
    )
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 8, secret_lock=secret)

    signatures = wallet1.signatures_proofs_sig_inputs(send_proofs)
    for p, s in zip(send_proofs, signatures):
        p.witness = HTLCWitness(
            preimage=preimage, signatures=[f"{s[:-5]}11111"]
        ).json()  # wrong signature

    # should error because we used wallet2 signatures for the hash lock
    await assert_err(
        wallet1.redeem(send_proofs),
        "Mint Error: signature threshold not met. 0 < 1.",
    )

    await asyncio.sleep(2)
    # should fail since lock time has passed and we provided not enough signatures for the timelock locktime_n_sigs
    await assert_err(
        wallet1.redeem(send_proofs),
        "Mint Error: signature threshold not met. 1 < 2.",
    )


@pytest.mark.asyncio
async def test_htlc_redeem_timelock_2_of_2_signatures(wallet1: Wallet, wallet2: Wallet):
    """Testing the 2-of-2 timelock (refund) signature case."""
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    preimage = "00000000000000000000000000000000"
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    # preimage_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    secret = await wallet1.create_htlc_lock(
        preimage=preimage,
        hashlock_pubkeys=[pubkey_wallet2],
        locktime_seconds=2,
        locktime_pubkeys=[pubkey_wallet1, pubkey_wallet2],
        locktime_n_sigs=2,
    )
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 8, secret_lock=secret)
    send_proofs_copy = send_proofs.copy()

    signatures = wallet1.signatures_proofs_sig_inputs(send_proofs)
    for p, s in zip(send_proofs, signatures):
        p.witness = HTLCWitness(preimage=preimage, signatures=[s]).json()

    # should error because we used wallet2 signatures for the hash lock
    await assert_err(
        wallet1.redeem(send_proofs),
        "Mint Error: signature threshold not met. 0 < 1.",
    )

    await asyncio.sleep(2)
    # locktime has passed

    # should fail. lock time has passed but we provided only wallet1 signature for timelock, we need 2 though
    await assert_err(
        wallet1.redeem(send_proofs),
        "Mint Error: not enough pubkeys (2) or signatures (1) present for n_sigs (2).",
    )

    # let's add the second signature
    send_proofs_copy = wallet2.sign_p2pk_sig_inputs(send_proofs_copy)

    # now we can redeem it
    await wallet1.redeem(send_proofs_copy)
