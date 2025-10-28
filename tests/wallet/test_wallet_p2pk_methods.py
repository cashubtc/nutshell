import copy
import hashlib
import secrets

import pytest
import pytest_asyncio

from cashu.core.base import P2PKWitness
from cashu.core.crypto.secp import PrivateKey
from cashu.core.migrations import migrate_databases
from cashu.core.nuts import nut11
from cashu.core.p2pk import P2PKSecret, SigFlags
from cashu.core.secret import SecretKind, Tags
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
async def wallet1():
    wallet1 = await Wallet.with_db(
        SERVER_ENDPOINT, "test_data/wallet_p2pk_methods_1", "wallet1"
    )
    await migrate_databases(wallet1.db, migrations)
    await wallet1.load_mint()
    yield wallet1


@pytest_asyncio.fixture(scope="function")
async def wallet2():
    wallet2 = await Wallet.with_db(
        SERVER_ENDPOINT, "test_data/wallet_p2pk_methods_2", "wallet2"
    )
    await migrate_databases(wallet2.db, migrations)
    wallet2.private_key = PrivateKey(secrets.token_bytes(32), raw=True)
    await wallet2.load_mint()
    yield wallet2


@pytest.mark.asyncio
async def test_create_p2pk_lock_default(wallet1: Wallet):
    """Test creating a P2PK lock with default parameters."""
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey)

    # Verify created lock properties
    assert isinstance(secret_lock, P2PKSecret)
    assert secret_lock.kind == SecretKind.P2PK.value
    assert secret_lock.data == pubkey
    assert secret_lock.locktime is None
    assert secret_lock.sigflag == SigFlags.SIG_INPUTS
    assert secret_lock.n_sigs == 1


@pytest.mark.asyncio
async def test_create_p2pk_lock_with_options(wallet1: Wallet):
    """Test creating a P2PK lock with all options specified."""
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(
        pubkey,
        locktime_seconds=3600,
        sig_all=True,
        n_sigs=2,
        tags=Tags([["custom_tag", "custom_value"]]),
    )

    # Verify created lock properties
    assert isinstance(secret_lock, P2PKSecret)
    assert secret_lock.kind == SecretKind.P2PK.value
    assert secret_lock.data == pubkey
    assert secret_lock.locktime is not None
    assert secret_lock.sigflag == SigFlags.SIG_ALL
    assert secret_lock.n_sigs == 2
    assert secret_lock.tags.get_tag("custom_tag") == "custom_value"


@pytest.mark.asyncio
async def test_signatures_proofs_sig_inputs(wallet1: Wallet):
    """Test signing proofs with the private key."""
    # Mint tokens
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create locked proofs
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey)
    _, proofs = await wallet1.swap_to_send(wallet1.proofs, 32, secret_lock=secret_lock)

    # Test signatures_proofs_sig_inputs
    signatures = wallet1.signatures_proofs_sig_inputs(proofs)

    # Verify signatures were created
    assert len(signatures) == len(proofs)
    assert all(isinstance(sig, str) for sig in signatures)
    assert all(len(sig) == 128 for sig in signatures)  # 64-byte hex signatures

    # Verify the signatures are valid
    for proof, signature in zip(proofs, signatures):
        message = proof.secret.encode("utf-8")
        sig_bytes = bytes.fromhex(signature)
        # Make sure wallet has a pubkey
        assert wallet1.private_key.pubkey is not None
        assert wallet1.private_key.pubkey.schnorr_verify(
            hashlib.sha256(message).digest(), sig_bytes, None, raw=True
        )


@pytest.mark.asyncio
async def test_schnorr_sign_message(wallet1: Wallet):
    """Test signing an arbitrary message."""
    # Define a test message
    message = "test message to sign"

    # Sign the message
    signature = wallet1.schnorr_sign_message(message)

    # Verify signature format
    assert isinstance(signature, str)
    assert len(signature) == 128  # 64-byte hex signature

    # Verify signature is valid
    sig_bytes = bytes.fromhex(signature)
    # Make sure wallet has a pubkey
    assert wallet1.private_key.pubkey is not None
    assert wallet1.private_key.pubkey.schnorr_verify(
        hashlib.sha256(message.encode("utf-8")).digest(), sig_bytes, None, raw=True
    )


@pytest.mark.asyncio
async def test_inputs_require_sigall_detection(wallet1: Wallet):
    """Test detection of SIG_ALL flag in proof inputs."""
    # Mint tokens
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create proofs with SIG_INPUTS
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock_inputs = await wallet1.create_p2pk_lock(pubkey, sig_all=False)
    _, proofs_sig_inputs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock_inputs
    )

    # Create proofs with SIG_ALL
    mint_quote_2 = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote_2.request)
    await wallet1.mint(64, quote_id=mint_quote_2.quote)
    secret_lock_all = await wallet1.create_p2pk_lock(pubkey, sig_all=True)
    _, proofs_sig_all = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock_all
    )

    # Test detection of SIG_ALL
    assert not wallet1._inputs_require_sigall(proofs_sig_inputs)
    assert wallet1._inputs_require_sigall(proofs_sig_all)

    # Test mixed list of proofs
    mixed_proofs = proofs_sig_inputs + proofs_sig_all
    assert wallet1._inputs_require_sigall(mixed_proofs)


@pytest.mark.asyncio
async def test_add_witness_swap_sig_all(wallet1: Wallet):
    """Test adding a witness to the first proof for SIG_ALL."""
    # Mint tokens
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create proofs with SIG_ALL
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey, sig_all=True)
    _, proofs = await wallet1.swap_to_send(wallet1.proofs, 16, secret_lock=secret_lock)

    # Create some outputs
    output_amounts = [16]
    secrets, rs, _ = await wallet1.generate_n_secrets(len(output_amounts))
    outputs, _ = wallet1._construct_outputs(output_amounts, secrets, rs)

    # Add witness
    signed_proofs = wallet1.add_witness_swap_sig_all(proofs, outputs)

    # Verify the first proof has a witness
    assert signed_proofs[0].witness is not None
    witness = P2PKWitness.from_witness(signed_proofs[0].witness)
    assert len(witness.signatures) == 1

    # Verify the signature includes both inputs and outputs
    message_to_sign = nut11.sigall_message_to_sign(proofs, outputs)
    signature = wallet1.schnorr_sign_message(message_to_sign)
    assert witness.signatures[0] == signature


@pytest.mark.asyncio
async def test_sign_proofs_inplace_swap(wallet1: Wallet):
    """Test signing proofs in place for a swap operation."""
    # Mint tokens
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create SIG_ALL proofs
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey, sig_all=True)
    _, proofs = await wallet1.swap_to_send(wallet1.proofs, 16, secret_lock=secret_lock)

    # Create some outputs
    output_amounts = [16]
    secrets, rs, _ = await wallet1.generate_n_secrets(len(output_amounts))
    outputs, _ = wallet1._construct_outputs(output_amounts, secrets, rs)

    # Sign proofs
    signed_proofs = wallet1.sign_proofs_inplace_swap(proofs, outputs)

    # Verify the first proof has a witness with a signature
    assert signed_proofs[0].witness is not None
    witness = P2PKWitness.from_witness(signed_proofs[0].witness)
    assert len(witness.signatures) == 1


@pytest.mark.asyncio
async def test_add_signatures_to_proofs(wallet1: Wallet):
    """Test adding signatures to proofs."""
    # Mint tokens
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create P2PK proofs
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey)
    _, proofs = await wallet1.swap_to_send(wallet1.proofs, 16, secret_lock=secret_lock)

    # Generate signatures
    signatures = wallet1.signatures_proofs_sig_inputs(proofs)

    # Add signatures to proofs
    signed_proofs = wallet1.add_signatures_to_proofs(proofs, signatures)

    # Verify signatures were added to the proofs
    for proof in signed_proofs:
        assert proof.witness is not None
        witness = P2PKWitness.from_witness(proof.witness)
        assert len(witness.signatures) == 1

    # Test adding same signatures to already signed proofs (should not duplicate)
    signed_proofs = wallet1.add_signatures_to_proofs(signed_proofs, signatures)

    # Verify the signatures were not duplicated
    for proof in signed_proofs:
        assert proof.witness
        witness = P2PKWitness.from_witness(proof.witness)
        # Should still have 1 signature because duplicates aren't added
        assert len(witness.signatures) == 1


@pytest.mark.asyncio
async def test_filter_proofs_locked_to_our_pubkey(wallet1: Wallet, wallet2: Wallet):
    """Test filtering proofs locked to our public key."""
    # Mint tokens to wallet1
    mint_quote = await wallet1.request_mint(640)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(640, quote_id=mint_quote.quote)

    # Get pubkeys for both wallets
    pubkey1 = await wallet1.create_p2pk_pubkey()
    pubkey2 = await wallet2.create_p2pk_pubkey()

    # Create proofs locked to wallet1's pubkey
    secret_lock1 = await wallet1.create_p2pk_lock(pubkey1)
    _, proofs1 = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock1
    )

    # Create proofs locked to wallet2's pubkey
    secret_lock2 = await wallet1.create_p2pk_lock(pubkey2)
    _, proofs2 = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock2
    )

    # Create proofs with multiple pubkeys
    secret_lock3 = await wallet1.create_p2pk_lock(
        pubkey1, tags=Tags([["pubkeys", pubkey2]])
    )
    _, proofs3 = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock3
    )

    # Sign the proofs to avoid witness errors
    signed_proofs1 = wallet1.sign_p2pk_sig_inputs(proofs1)
    signed_proofs2 = wallet2.sign_p2pk_sig_inputs(proofs2)
    signed_proofs3 = wallet1.sign_p2pk_sig_inputs(proofs3)
    signed_proofs3 = wallet2.sign_p2pk_sig_inputs(signed_proofs3)

    # Ensure pubkeys are available
    assert wallet1.private_key.pubkey is not None
    assert wallet2.private_key.pubkey is not None

    # Filter using wallet1
    filtered1 = wallet1.filter_proofs_locked_to_our_pubkey(
        signed_proofs1 + signed_proofs2 + signed_proofs3
    )
    # wallet1 should find proofs1 and proofs3
    assert len(filtered1) == len(signed_proofs1) + len(signed_proofs3)

    # Filter using wallet2
    filtered2 = wallet2.filter_proofs_locked_to_our_pubkey(
        signed_proofs1 + signed_proofs2 + signed_proofs3
    )
    # wallet2 should find proofs2 and proofs3
    assert len(filtered2) == len(signed_proofs2) + len(signed_proofs3)


@pytest.mark.asyncio
async def test_sign_p2pk_sig_inputs(wallet1: Wallet):
    """Test signing P2PK SIG_INPUTS proofs."""
    # Mint tokens
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create a mix of P2PK and non-P2PK proofs
    pubkey = await wallet1.create_p2pk_pubkey()

    # Regular proofs (not P2PK)
    _, regular_proofs = await wallet1.swap_to_send(wallet1.proofs, 16)

    # P2PK SIG_INPUTS proofs
    secret_lock_inputs = await wallet1.create_p2pk_lock(pubkey, sig_all=False)
    _, p2pk_input_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock_inputs
    )

    # P2PK SIG_ALL proofs - these won't be signed by sign_p2pk_sig_inputs
    secret_lock_all = await wallet1.create_p2pk_lock(pubkey, sig_all=True)
    _, p2pk_all_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock_all
    )

    # P2PK locked to a different pubkey - these won't be signed
    garbage_pubkey_p = PrivateKey().pubkey
    assert garbage_pubkey_p is not None
    garbage_pubkey = garbage_pubkey_p.serialize().hex()
    secret_lock_other = await wallet1.create_p2pk_lock(garbage_pubkey)
    _, p2pk_other_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock_other
    )

    # Mix all proofs
    mixed_proofs = (
        regular_proofs + p2pk_input_proofs + p2pk_all_proofs + p2pk_other_proofs
    )

    # Sign the mixed proofs
    signed_proofs = wallet1.sign_p2pk_sig_inputs(mixed_proofs)

    # Only P2PK SIG_INPUTS proofs locked to our pubkey should be signed
    assert len(signed_proofs) == len(p2pk_input_proofs)

    # Verify the signatures were added
    for proof in signed_proofs:
        assert proof.witness is not None
        witness = P2PKWitness.from_witness(proof.witness)
        assert len(witness.signatures) == 1


@pytest.mark.asyncio
async def test_add_witnesses_sig_inputs(wallet1: Wallet):
    """Test adding witnesses to P2PK SIG_INPUTS proofs."""
    # Mint tokens
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create a mix of P2PK and non-P2PK proofs
    pubkey = await wallet1.create_p2pk_pubkey()

    # Regular proofs (not P2PK)
    _, regular_proofs = await wallet1.swap_to_send(wallet1.proofs, 16)

    # P2PK SIG_INPUTS proofs
    secret_lock_inputs = await wallet1.create_p2pk_lock(pubkey, sig_all=False)
    _, p2pk_input_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock_inputs
    )

    # Mix all proofs and make a copy for comparison
    mixed_proofs = regular_proofs + p2pk_input_proofs
    mixed_proofs_copy = copy.deepcopy(mixed_proofs)

    # Add witnesses to the proofs
    signed_proofs = wallet1.add_witnesses_sig_inputs(mixed_proofs)

    # Verify that only P2PK proofs have witnesses added
    for i, (orig_proof, signed_proof) in enumerate(
        zip(mixed_proofs_copy, signed_proofs)
    ):
        if i < len(regular_proofs):
            # Regular proofs should be unchanged
            assert signed_proof.witness == orig_proof.witness
        else:
            # P2PK proofs should have witnesses added
            assert signed_proof.witness is not None
            witness = P2PKWitness.from_witness(signed_proof.witness)
            assert len(witness.signatures) == 1


@pytest.mark.asyncio
async def test_edge_cases(wallet1: Wallet, wallet2: Wallet):
    """Test various edge cases for the WalletP2PK methods."""
    # Mint tokens
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Case 1: Empty list of proofs
    assert wallet1.signatures_proofs_sig_inputs([]) == []
    assert wallet1.add_signatures_to_proofs([], []) == []
    assert wallet1.filter_proofs_locked_to_our_pubkey([]) == []
    assert wallet1.sign_p2pk_sig_inputs([]) == []
    assert wallet1.add_witnesses_sig_inputs([]) == []

    # Case 2: Mismatched number of proofs and signatures
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey)
    _, proofs = await wallet1.swap_to_send(wallet1.proofs, 16, secret_lock=secret_lock)
    assert len(proofs) == 1
    # Create fake signatures but we have only one proof - this should fail
    signatures = ["fake_signature1", "fake_signature2"]
    assert len(signatures) != len(proofs)

    # This should raise an assertion error
    with pytest.raises(AssertionError, match="wrong number of signatures"):
        wallet1.add_signatures_to_proofs(proofs, signatures)

    # Case 3: SIG_ALL with proofs locked to different public keys
    assert wallet1.private_key.pubkey is not None
    garbage_pubkey = PrivateKey().pubkey
    assert garbage_pubkey is not None
    secret_lock_other = await wallet1.create_p2pk_lock(
        garbage_pubkey.serialize().hex(), sig_all=True
    )
    _, other_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock_other
    )

    output_amounts = [16]
    secrets, rs, _ = await wallet1.generate_n_secrets(len(output_amounts))
    outputs, _ = wallet1._construct_outputs(output_amounts, secrets, rs)

    # wallet1 shouldn't add signatures because proofs are locked to a different pubkey
    signed_proofs = wallet1.add_witness_swap_sig_all(other_proofs, outputs)
    # Check each proof for None witness
    for proof in signed_proofs:
        assert proof.witness is None
