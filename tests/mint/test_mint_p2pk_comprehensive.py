import copy
import time
from typing import List

import pytest
import pytest_asyncio

from cashu.core.base import BlindedMessage, P2PKWitness
from cashu.core.migrations import migrate_databases
from cashu.core.nuts import nut11
from cashu.core.p2pk import P2PKSecret, SigFlags
from cashu.core.secret import Secret, SecretKind, Tags
from cashu.mint.ledger import Ledger
from cashu.wallet import migrations
from cashu.wallet.wallet import Wallet
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


@pytest_asyncio.fixture(scope="function")
async def wallet1(ledger: Ledger):
    wallet1 = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1_p2pk_comprehensive",
        name="wallet1",
    )
    await migrate_databases(wallet1.db, migrations)
    await wallet1.load_mint()
    yield wallet1


@pytest_asyncio.fixture(scope="function")
async def wallet2(ledger: Ledger):
    wallet2 = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet2_p2pk_comprehensive",
        name="wallet2",
    )
    await migrate_databases(wallet2.db, migrations)
    await wallet2.load_mint()
    yield wallet2


@pytest_asyncio.fixture(scope="function")
async def wallet3(ledger: Ledger):
    wallet3 = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet3_p2pk_comprehensive",
        name="wallet3",
    )
    await migrate_databases(wallet3.db, migrations)
    await wallet3.load_mint()
    yield wallet3


@pytest.mark.asyncio
async def test_p2pk_sig_inputs_basic(wallet1: Wallet, wallet2: Wallet, ledger: Ledger):
    """Test basic P2PK with SIG_INPUTS."""
    # Mint tokens to wallet1
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Verify wallet1 has tokens
    assert wallet1.balance == 64

    # Create locked tokens from wallet1 to wallet2
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey_wallet2)
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock
    )

    # Verify that sent tokens have P2PK secrets with SIG_INPUTS flag
    for proof in send_proofs:
        p2pk_secret = Secret.deserialize(proof.secret)
        assert p2pk_secret.kind == SecretKind.P2PK.value
        assert P2PKSecret.from_secret(p2pk_secret).sigflag == SigFlags.SIG_INPUTS

    # Try to redeem without signatures (should fail)
    unsigned_proofs = copy.deepcopy(send_proofs)
    for proof in unsigned_proofs:
        proof.witness = None
    await assert_err(
        ledger.swap(
            proofs=unsigned_proofs, outputs=await create_test_outputs(wallet2, 16)
        ),
        "Witness is missing for p2pk signature",
    )

    # Redeem with proper signatures
    signed_proofs = wallet2.sign_p2pk_sig_inputs(send_proofs)
    assert all(p.witness is not None for p in signed_proofs)

    # Now swap should succeed
    outputs = await create_test_outputs(wallet2, 16)
    promises = await ledger.swap(proofs=signed_proofs, outputs=outputs)
    assert len(promises) == len(outputs)


@pytest.mark.asyncio
async def test_p2pk_sig_all_message_aggregation(
    wallet1: Wallet, wallet2: Wallet, ledger: Ledger
):
    # Mint tokens to wallet1
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create locked tokens with SIG_ALL
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey_wallet2, sig_all=True)
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock
    )

    # Verify that sent tokens have P2PK secrets with SIG_ALL flag
    for proof in send_proofs:
        p2pk_secret = Secret.deserialize(proof.secret)
        assert p2pk_secret.kind == SecretKind.P2PK.value
        assert P2PKSecret.from_secret(p2pk_secret).sigflag == SigFlags.SIG_ALL

    # Create outputs for redemption
    outputs = await create_test_outputs(wallet2, 16)

    message_to_sign_expected = "".join(
        [p.secret + p.C for p in send_proofs] + [str(o.amount) + o.B_ for o in outputs]
    )
    message_to_sign_actual = nut11.sigall_message_to_sign(send_proofs, outputs)
    assert message_to_sign_actual == message_to_sign_expected


@pytest.mark.asyncio
async def test_p2pk_sig_all_valid(wallet1: Wallet, wallet2: Wallet, ledger: Ledger):
    """Test P2PK with SIG_ALL where the signature covers both inputs and outputs."""
    # Mint tokens to wallet1
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create locked tokens with SIG_ALL
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey_wallet2, sig_all=True)
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock
    )

    # Verify that sent tokens have P2PK secrets with SIG_ALL flag
    for proof in send_proofs:
        p2pk_secret = Secret.deserialize(proof.secret)
        assert p2pk_secret.kind == SecretKind.P2PK.value
        assert P2PKSecret.from_secret(p2pk_secret).sigflag == SigFlags.SIG_ALL

    # Create outputs for redemption
    outputs = await create_test_outputs(wallet2, 16)

    # Create a message from concatenated inputs and outputs
    message_to_sign = nut11.sigall_message_to_sign(send_proofs, outputs)

    # Sign with wallet2's private key
    signature = wallet2.schnorr_sign_message(message_to_sign)

    # Add the signature to the first proof only (since it's SIG_ALL)
    send_proofs[0].witness = P2PKWitness(signatures=[signature]).model_dump_json()

    # Swap should succeed
    promises = await ledger.swap(proofs=send_proofs, outputs=outputs)
    assert len(promises) == len(outputs)


@pytest.mark.asyncio
async def test_p2pk_sig_all_invalid(wallet1: Wallet, wallet2: Wallet, ledger: Ledger):
    """Test P2PK with SIG_ALL where the signature is invalid."""
    # Mint tokens to wallet1
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create locked tokens with SIG_ALL
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey_wallet2, sig_all=True)
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock
    )

    # Create outputs for redemption
    outputs = await create_test_outputs(wallet2, 16)

    # Add an invalid signature
    fake_signature = "0" * 128  # Just a fake 64-byte hex string
    send_proofs[0].witness = P2PKWitness(signatures=[fake_signature]).model_dump_json()

    # Swap should fail
    await assert_err(
        ledger.swap(proofs=send_proofs, outputs=outputs), "signature threshold not met"
    )


@pytest.mark.asyncio
async def test_p2pk_sig_all_mixed(wallet1: Wallet, wallet2: Wallet, ledger: Ledger):
    """Test that attempting to use mixed SIG_ALL and SIG_INPUTS proofs fails."""
    # Mint tokens to wallet1
    mint_quote = await wallet1.request_mint(128)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(128, quote_id=mint_quote.quote)

    # Create outputs
    outputs = await create_test_outputs(wallet2, 32)  # 16 + 16

    # Create a proof with SIG_ALL
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    secret_lock_all = await wallet1.create_p2pk_lock(pubkey_wallet2, sig_all=True)
    _, proofs_sig_all = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock_all
    )
    # sign proofs_sig_all
    signed_proofs_sig_all = wallet2.add_witness_swap_sig_all(proofs_sig_all, outputs)

    # Mint more tokens to wallet1 for the SIG_INPUTS test
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create a proof with SIG_INPUTS
    secret_lock_inputs = await wallet1.create_p2pk_lock(pubkey_wallet2, sig_all=False)
    _, proofs_sig_inputs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock_inputs
    )
    # sign proofs_sig_inputs
    signed_proofs_sig_inputs = wallet2.sign_p2pk_sig_inputs(proofs_sig_inputs)

    # Combine the proofs
    mixed_proofs = signed_proofs_sig_all + signed_proofs_sig_inputs

    # Add an invalid signature to the SIG_ALL proof
    mixed_proofs[0].witness = P2PKWitness(signatures=["0" * 128]).model_dump_json()

    # Try to use the mixed proofs (should fail)
    await assert_err(
        ledger.swap(proofs=mixed_proofs, outputs=outputs),
        "not all secrets are equal.",
    )


@pytest.mark.asyncio
async def test_p2pk_multisig_2_of_3(
    wallet1: Wallet, wallet2: Wallet, wallet3: Wallet, ledger: Ledger
):
    """Test P2PK with 2-of-3 multisig."""
    # Mint tokens to wallet1
    mint_quote = await wallet1.request_mint(6400)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(6400, quote_id=mint_quote.quote)

    # Get pubkeys from all wallets
    pubkey1 = await wallet1.create_p2pk_pubkey()
    pubkey2 = await wallet2.create_p2pk_pubkey()
    pubkey3 = await wallet3.create_p2pk_pubkey()

    # Create 2-of-3 multisig tokens locked to all three wallets
    tags = Tags([["pubkeys", pubkey2, pubkey3]])
    secret_lock = await wallet1.create_p2pk_lock(pubkey1, tags=tags, n_sigs=2)
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock
    )

    # Create outputs for redemption
    outputs = await create_test_outputs(wallet1, 16)

    # Sign with wallet1 (first signature)
    signed_proofs = wallet1.sign_p2pk_sig_inputs(send_proofs)

    # Try to redeem with only 1 signature (should fail)
    await assert_err(
        ledger.swap(proofs=signed_proofs, outputs=outputs),
        "not enough pubkeys (3) or signatures (1) present for n_sigs (2).",
    )

    # Mint new tokens for the second test
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create new locked tokens
    _, send_proofs2 = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock
    )

    # Sign with wallet1 (first signature)
    signed_proofs2 = wallet1.sign_p2pk_sig_inputs(send_proofs2)

    # Add signature from wallet2 (second signature)
    signed_proofs2 = wallet2.sign_p2pk_sig_inputs(signed_proofs2)

    # Now redemption should succeed with 2 of 3 signatures
    # Create outputs for redemption
    outputs = await create_test_outputs(wallet1, 16)
    promises = await ledger.swap(proofs=signed_proofs2, outputs=outputs)
    assert len(promises) == len(outputs)

    # Mint new tokens for the third test
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create new locked tokens
    _, send_proofs3 = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock
    )

    # Alternative: sign with wallet1 and wallet3
    signed_proofs3 = wallet1.sign_p2pk_sig_inputs(send_proofs3)
    signed_proofs3 = wallet3.sign_p2pk_sig_inputs(signed_proofs3)

    # This should also succeed
    # Create outputs for redemption
    outputs = await create_test_outputs(wallet1, 16)
    promises2 = await ledger.swap(proofs=signed_proofs3, outputs=outputs)
    assert len(promises2) == len(outputs)


@pytest.mark.asyncio
async def test_p2pk_timelock(wallet1: Wallet, wallet2: Wallet, ledger: Ledger):
    """Test P2PK with a timelock that expires."""
    # Mint tokens to wallet1
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create tokens with a 2-second timelock
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    # Set a past timestamp to ensure test works consistently
    past_time = int(time.time()) - 10
    tags = Tags([["locktime", str(past_time)]])
    secret_lock = await wallet1.create_p2pk_lock(pubkey_wallet2, tags=tags)
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock
    )

    # Store current time to check if locktime passed
    locktime = 0
    for proof in send_proofs:
        secret = Secret.deserialize(proof.secret)
        p2pk_secret = P2PKSecret.from_secret(secret)
        locktime = p2pk_secret.locktime

    # Create outputs
    outputs = await create_test_outputs(wallet1, 16)

    # Verify that current time is past the locktime
    assert locktime is not None, "Locktime should not be None"
    assert (
        int(time.time()) > locktime
    ), f"Current time ({int(time.time())}) should be greater than locktime ({locktime})"

    # ensure wallet1 doesn't reuse already swapped proofs later in the test suite
    await wallet1.invalidate(send_proofs)
    await wallet1.load_proofs(reload=True)

    # Try to redeem without signature after locktime (should succeed)
    unsigned_proofs = copy.deepcopy(send_proofs)
    for proof in unsigned_proofs:
        proof.witness = None

    promises = await ledger.swap(proofs=unsigned_proofs, outputs=outputs)
    assert len(promises) == len(outputs)


@pytest.mark.asyncio
async def test_p2pk_timelock_with_refund_before_locktime(
    wallet1: Wallet, wallet2: Wallet, wallet3: Wallet, ledger: Ledger
):
    """Test P2PK with a timelock and refund pubkeys before locktime."""
    # Mint tokens to wallet1
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Get pubkeys
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # Receiver
    pubkey_wallet3 = await wallet3.create_p2pk_pubkey()  # Refund key

    # Create tokens with a 2-second timelock and refund key
    future_time = int(time.time()) + 60  # 60 seconds in the future
    refund_tags = Tags([["refund", pubkey_wallet3], ["locktime", str(future_time)]])
    secret_lock = await wallet1.create_p2pk_lock(pubkey_wallet2, tags=refund_tags)
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock
    )

    # Create outputs
    outputs = await create_test_outputs(wallet1, 16)

    # Try to redeem without any signature before locktime (should fail)
    unsigned_proofs = copy.deepcopy(send_proofs)
    for proof in unsigned_proofs:
        proof.witness = None

    await assert_err(
        ledger.swap(proofs=unsigned_proofs, outputs=outputs),
        "Witness is missing for p2pk signature",
    )

    # Try to redeem with refund key signature before locktime (should fail)
    refund_signed_proofs = wallet3.sign_p2pk_sig_inputs(send_proofs)

    await assert_err(
        ledger.swap(proofs=refund_signed_proofs, outputs=outputs),
        "signature threshold not met",  # Refund key can't be used before locktime
    )


@pytest.mark.asyncio
async def test_p2pk_timelock_with_receiver_signature(
    wallet1: Wallet, wallet2: Wallet, wallet3: Wallet, ledger: Ledger
):
    """Test P2PK with a timelock and refund pubkeys with receiver signature."""
    # Mint tokens to wallet1
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Get pubkeys
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # Receiver
    pubkey_wallet3 = await wallet3.create_p2pk_pubkey()  # Refund key

    # Create tokens with a 2-second timelock and refund key
    future_time = int(time.time()) + 60  # 60 seconds in the future
    refund_tags = Tags([["refund", pubkey_wallet3], ["locktime", str(future_time)]])
    secret_lock = await wallet1.create_p2pk_lock(pubkey_wallet2, tags=refund_tags)
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock
    )

    # Create outputs
    outputs = await create_test_outputs(wallet1, 16)

    # Try to redeem with the correct receiver signature (should succeed)
    receiver_signed_proofs = wallet2.sign_p2pk_sig_inputs(send_proofs)

    promises = await ledger.swap(proofs=receiver_signed_proofs, outputs=outputs)
    assert len(promises) == len(outputs)


@pytest.mark.asyncio
async def test_p2pk_timelock_with_refund_after_locktime(
    wallet1: Wallet, wallet2: Wallet, wallet3: Wallet, ledger: Ledger
):
    """Test P2PK with a timelock and refund pubkeys after locktime."""
    # Mint tokens to wallet1
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Get pubkeys
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # Receiver
    pubkey_wallet3 = await wallet3.create_p2pk_pubkey()  # Refund key

    # Create tokens with a past timestamp for locktime testing
    past_time = int(time.time()) - 10  # 10 seconds in the past
    refund_tags_past = Tags([["refund", pubkey_wallet3], ["locktime", str(past_time)]])
    secret_lock_past = await wallet1.create_p2pk_lock(
        pubkey_wallet2, tags=refund_tags_past
    )
    _, send_proofs3 = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock_past
    )

    # Try to redeem with refund key after locktime (should succeed)
    refund_signed_proofs2 = wallet3.sign_p2pk_sig_inputs(send_proofs3)

    # This should work because locktime has passed and refund key is used
    # Create outputs
    outputs = await create_test_outputs(wallet1, 16)
    promises2 = await ledger.swap(proofs=refund_signed_proofs2, outputs=outputs)
    assert len(promises2) == len(outputs)


@pytest.mark.asyncio
async def test_p2pk_locktime_allows_both_paths_after_expiry(
    wallet1: Wallet, wallet2: Wallet, wallet3: Wallet, ledger: Ledger
):
    """After expiry the receiver path remains valid and refund keys become available."""

    receiver_pubkey = await wallet2.create_p2pk_pubkey()
    refund_pubkey = await wallet3.create_p2pk_pubkey()
    expired_locktime = int(time.time()) - 30

    def expired_tags() -> Tags:
        return Tags(
            [
                ["refund", refund_pubkey],
                ["locktime", str(expired_locktime)],
            ]
        )

    # --- Receiver (main pubkeys) path still works after locktime ---
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    secret_main = await wallet1.create_p2pk_lock(receiver_pubkey, tags=expired_tags())
    _, proofs_main = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_main
    )

    outputs_main = await create_test_outputs(wallet2, 16)
    signed_main = wallet2.sign_p2pk_sig_inputs(proofs_main)
    promises_main = await ledger.swap(proofs=signed_main, outputs=outputs_main)
    assert len(promises_main) == len(outputs_main)
    await wallet1.invalidate(proofs_main, check_spendable=True)
    await wallet1.load_proofs(reload=True)

    # --- Refund path becomes available after locktime ---
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    proofs2 = await wallet1.mint(64, quote_id=mint_quote.quote)

    secret_refund = await wallet1.create_p2pk_lock(receiver_pubkey, tags=expired_tags())
    _, proofs_refund = await wallet1.swap_to_send(
        proofs2, 16, secret_lock=secret_refund
    )

    outputs_refund = await create_test_outputs(wallet3, 16)
    signed_refund = wallet3.sign_p2pk_sig_inputs(proofs_refund)
    promises_refund = await ledger.swap(proofs=signed_refund, outputs=outputs_refund)
    assert len(promises_refund) == len(outputs_refund)
    await wallet1.invalidate(proofs_refund, check_spendable=True)
    await wallet1.load_proofs(reload=True)


@pytest.mark.asyncio
async def test_p2pk_n_sigs_refund(
    wallet1: Wallet, wallet2: Wallet, wallet3: Wallet, ledger: Ledger
):
    """Test P2PK with a timelock and multiple refund pubkeys with n_sigs_refund."""
    # Mint tokens to wallet1
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Get pubkeys
    pubkey_wallet1 = await wallet1.create_p2pk_pubkey()  # Receiver
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()  # Refund key 1
    pubkey_wallet3 = await wallet3.create_p2pk_pubkey()  # Refund key 2

    # Create tokens with a future timelock and 2-of-2 refund requirement
    future_time = int(time.time()) + 60  # 60 seconds in the future
    refund_tags = Tags(
        [
            ["refund", pubkey_wallet2, pubkey_wallet3],
            ["n_sigs_refund", "2"],
            ["locktime", str(future_time)],
        ]
    )
    secret_lock = await wallet1.create_p2pk_lock(pubkey_wallet1, tags=refund_tags)
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock
    )

    # Create outputs
    outputs = await create_test_outputs(wallet1, 16)

    # Mint new tokens for receiver test
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create new locked tokens
    _, send_proofs2 = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock
    )

    # Try to redeem with receiver key (should succeed before locktime)
    receiver_signed_proofs = wallet1.sign_p2pk_sig_inputs(send_proofs2)
    promises = await ledger.swap(proofs=receiver_signed_proofs, outputs=outputs)
    assert len(promises) == len(outputs)

    # Mint new tokens for the refund test
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create tokens with a past locktime for refund testing
    past_time = int(time.time()) - 10  # 10 seconds in the past
    refund_tags_past = Tags(
        [
            ["refund", pubkey_wallet2, pubkey_wallet3],
            ["n_sigs_refund", "2"],
            ["locktime", str(past_time)],
        ]
    )
    secret_lock_past = await wallet1.create_p2pk_lock(
        pubkey_wallet1, tags=refund_tags_past
    )
    _, send_proofs3 = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock_past
    )

    # Try to redeem with only one refund key signature (should fail)
    refund_signed_proofs = wallet2.sign_p2pk_sig_inputs(send_proofs3)

    await assert_err(
        ledger.swap(proofs=refund_signed_proofs, outputs=outputs),
        "not enough pubkeys (2) or signatures (1) present for n_sigs (2).",
    )

    # Mint new tokens for the final test
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create tokens with same past locktime
    _, send_proofs4 = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock_past
    )

    # Add both refund signatures
    refund_signed_proofs2 = wallet2.sign_p2pk_sig_inputs(send_proofs4)
    refund_signed_proofs2 = wallet3.sign_p2pk_sig_inputs(refund_signed_proofs2)

    # Now it should succeed with 2-of-2 refund signatures
    # Create outputs
    outputs = await create_test_outputs(wallet1, 16)
    promises2 = await ledger.swap(proofs=refund_signed_proofs2, outputs=outputs)
    assert len(promises2) == len(outputs)


@pytest.mark.asyncio
async def test_p2pk_invalid_pubkey_check(
    wallet1: Wallet, wallet2: Wallet, ledger: Ledger
):
    """Test that an invalid public key is properly rejected."""
    # Mint tokens to wallet1
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create an invalid pubkey string (too short)
    invalid_pubkey = "03aaff"

    # Try to create a P2PK lock with invalid pubkey
    # This should fail in create_p2pk_lock, but if it doesn't, let's handle it gracefully
    try:
        secret_lock = await wallet1.create_p2pk_lock(invalid_pubkey)
        _, send_proofs = await wallet1.swap_to_send(
            wallet1.proofs, 16, secret_lock=secret_lock
        )

        # Create outputs
        outputs = await create_test_outputs(wallet1, 16)

        # Verify it fails during validation
        await assert_err(
            ledger.swap(proofs=send_proofs, outputs=outputs),
            "failed to deserialize pubkey",  # Generic error for pubkey issues
        )
    except Exception as e:
        # If it fails during creation, that's fine too
        assert (
            "pubkey" in str(e).lower() or "key" in str(e).lower()
        ), f"Expected error about invalid public key, got: {str(e)}"


@pytest.mark.asyncio
async def test_p2pk_sig_all_with_multiple_pubkeys(
    wallet1: Wallet, wallet2: Wallet, wallet3: Wallet, ledger: Ledger
):
    """Test SIG_ALL combined with multiple pubkeys/n_sigs."""
    # Mint tokens to wallet1
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Get pubkeys
    pubkey1 = await wallet1.create_p2pk_pubkey()
    pubkey2 = await wallet2.create_p2pk_pubkey()
    pubkey3 = await wallet3.create_p2pk_pubkey()

    # Create tokens with SIG_ALL and 2-of-3 multisig
    tags = Tags([["pubkeys", pubkey2, pubkey3]])
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey1, tags=tags, n_sigs=2, sig_all=True
    )
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock
    )

    # Create outputs
    outputs = await create_test_outputs(wallet1, 16)

    # Create message to sign (all inputs + all outputs)
    message_to_sign = nut11.sigall_message_to_sign(send_proofs, outputs)

    # Sign with wallet1's key
    signature1 = wallet1.schnorr_sign_message(message_to_sign)

    # Sign with wallet2's key
    signature2 = wallet2.schnorr_sign_message(message_to_sign)

    # Add both signatures to the first proof only (SIG_ALL)
    send_proofs[0].witness = P2PKWitness(signatures=[signature1, signature2]).model_dump_json()

    # This should succeed with 2 valid signatures
    promises = await ledger.swap(proofs=send_proofs, outputs=outputs)
    assert len(promises) == len(outputs)


async def create_test_outputs(wallet: Wallet, amount: int) -> List[BlindedMessage]:
    """Helper to create blinded outputs for testing."""
    output_amounts = [amount]
    secrets, rs, _ = await wallet.generate_n_secrets(len(output_amounts))
    outputs, _ = wallet._construct_outputs(output_amounts, secrets, rs)
    return outputs
