import pytest
import pytest_asyncio

from cashu.core.base import P2PKWitness
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet as Wallet1
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
    wallet1 = await Wallet1.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1",
        name="wallet1",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest.mark.asyncio
async def test_ledger_inputs_require_sigall_detection(wallet1: Wallet1, ledger: Ledger):
    """Test the ledger function that detects if any inputs require SIG_ALL."""
    # Mint tokens to the wallet
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await ledger.get_mint_quote(mint_quote.quote)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create two proofs: one with SIG_INPUTS and one with SIG_ALL
    pubkey = await wallet1.create_p2pk_pubkey()

    # Create a proof with SIG_INPUTS
    secret_lock_inputs = await wallet1.create_p2pk_lock(pubkey, sig_all=False)
    _, send_proofs_inputs = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock_inputs
    )

    # Create a new mint quote for the second mint operation
    mint_quote_2 = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote_2.request)
    await ledger.get_mint_quote(mint_quote_2.quote)
    await wallet1.mint(64, quote_id=mint_quote_2.quote)

    # Create a proof with SIG_ALL
    secret_lock_all = await wallet1.create_p2pk_lock(pubkey, sig_all=True)
    _, send_proofs_all = await wallet1.swap_to_send(
        wallet1.proofs, 16, secret_lock=secret_lock_all
    )

    # Test that _inputs_require_sigall correctly detects SIG_ALL flag
    assert not ledger._inputs_require_sigall(
        send_proofs_inputs
    ), "Should not detect SIG_ALL"
    assert ledger._inputs_require_sigall(send_proofs_all), "Should detect SIG_ALL"

    # Test with a mixed list of proofs (should detect SIG_ALL if any proof has it)
    mixed_proofs = send_proofs_inputs + send_proofs_all
    assert ledger._inputs_require_sigall(
        mixed_proofs
    ), "Should detect SIG_ALL in mixed list"


@pytest.mark.asyncio
async def test_ledger_verify_p2pk_signature_validation(
    wallet1: Wallet1, ledger: Ledger
):
    """Test the signature validation for P2PK inputs."""
    # Mint tokens to the wallet
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await ledger.get_mint_quote(mint_quote.quote)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create a p2pk lock
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey)

    # Create locked tokens
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 32, secret_lock=secret_lock
    )

    # Sign the tokens
    signed_proofs = wallet1.sign_p2pk_sig_inputs(send_proofs)
    assert len(signed_proofs) > 0, "Should have signed proofs"

    # Verify that a valid witness was added to the proofs
    for proof in signed_proofs:
        assert proof.witness is not None, "Proof should have a witness"
        witness = P2PKWitness.from_witness(proof.witness)
        assert len(witness.signatures) > 0, "Witness should have a signature"

    # Generate outputs for the swap
    output_amounts = [32]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)

    # The swap should succeed because the signatures are valid
    promises = await ledger.swap(proofs=signed_proofs, outputs=outputs)
    assert len(promises) == len(
        outputs
    ), "Should have the same number of promises as outputs"

    # Test for a failure
    # Create a fake witness with an incorrect signature
    fake_signature = "0" * 128  # Just a fake 64-byte hex string
    for proof in send_proofs:
        proof.witness = P2PKWitness(signatures=[fake_signature]).model_dump_json()

    # The swap should fail because the signatures are invalid
    await assert_err(
        ledger.swap(proofs=send_proofs, outputs=outputs),
        "signature threshold not met",
    )


@pytest.mark.asyncio
async def test_ledger_verify_incorrect_signature(wallet1: Wallet1, ledger: Ledger):
    """Test rejection of incorrect signatures for P2PK inputs."""
    # Mint tokens to the wallet
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await ledger.get_mint_quote(mint_quote.quote)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create a p2pk lock
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey)

    # Create locked tokens
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 32, secret_lock=secret_lock
    )

    # Create a fake witness with an incorrect signature
    fake_signature = "0" * 128  # Just a fake 64-byte hex string
    for proof in send_proofs:
        proof.witness = P2PKWitness(signatures=[fake_signature]).model_dump_json()

    # Generate outputs for the swap
    output_amounts = [32]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)

    # The swap should fail because the signatures are invalid
    await assert_err(
        ledger.swap(proofs=send_proofs, outputs=outputs),
        "signature threshold not met",
    )


@pytest.mark.asyncio
async def test_ledger_verify_sigall_validation(wallet1: Wallet1, ledger: Ledger):
    """Test validation of SIG_ALL signature that covers both inputs and outputs."""
    # Mint tokens to the wallet
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await ledger.get_mint_quote(mint_quote.quote)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create a p2pk lock with SIG_ALL
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey, sig_all=True)

    # Create locked tokens
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 32, secret_lock=secret_lock
    )

    # Generate outputs for the swap
    output_amounts = [32]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)

    # Create the message to sign (all inputs + all outputs)
    message_to_sign = "".join([p.secret for p in send_proofs] + [o.B_ for o in outputs])

    # Sign the message with the wallet's private key
    signature = wallet1.schnorr_sign_message(message_to_sign)

    # Add the signature to the first proof only (as required for SIG_ALL)
    send_proofs[0].witness = P2PKWitness(signatures=[signature]).model_dump_json()

    # The swap should succeed because the SIG_ALL signature is valid
    promises = await ledger.swap(proofs=send_proofs, outputs=outputs)
    assert len(promises) == len(
        outputs
    ), "Should have the same number of promises as outputs"


@pytest.mark.asyncio
async def test_ledger_verify_incorrect_sigall_signature(
    wallet1: Wallet1, ledger: Ledger
):
    """Test rejection of incorrect SIG_ALL signatures."""
    # Mint tokens to the wallet
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await ledger.get_mint_quote(mint_quote.quote)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Create a p2pk lock with SIG_ALL
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey, sig_all=True)

    # Create locked tokens
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 32, secret_lock=secret_lock
    )

    # Generate outputs for the swap
    output_amounts = [32]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)

    # Create a fake witness with an incorrect signature
    fake_signature = "0" * 128  # Just a fake 64-byte hex string
    send_proofs[0].witness = P2PKWitness(signatures=[fake_signature]).model_dump_json()

    # The swap should fail because the SIG_ALL signature is invalid
    await assert_err(
        ledger.swap(proofs=send_proofs, outputs=outputs),
        "signature threshold not met",
    )


@pytest.mark.asyncio
async def test_ledger_swap_p2pk_without_signature(wallet1: Wallet1, ledger: Ledger):
    """Test ledger swap with p2pk locked tokens without providing signatures."""
    # Mint tokens to the wallet
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await ledger.get_mint_quote(mint_quote.quote)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    assert wallet1.balance == 64

    # Create a p2pk lock with wallet's own public key
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey)

    # Use swap_to_send to create p2pk locked proofs
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 32, secret_lock=secret_lock
    )

    # Generate outputs for the swap
    output_amounts = [32]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)

    # Attempt to swap WITHOUT adding signatures - this should fail
    await assert_err(
        ledger.swap(proofs=send_proofs, outputs=outputs),
        "Witness is missing for p2pk signature",
    )


@pytest.mark.asyncio
async def test_ledger_swap_p2pk_with_signature(wallet1: Wallet1, ledger: Ledger):
    """Test ledger swap with p2pk locked tokens with proper signatures."""
    # Mint tokens to the wallet
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await ledger.get_mint_quote(mint_quote.quote)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    assert wallet1.balance == 64

    # Create a p2pk lock with wallet's own public key
    pubkey = await wallet1.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey)

    # Use swap_to_send to create p2pk locked proofs
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 32, secret_lock=secret_lock
    )

    # Generate outputs for the swap
    output_amounts = [32]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)

    # Sign the p2pk inputs before sending to the ledger
    signed_proofs = wallet1.sign_p2pk_sig_inputs(send_proofs)

    # Extract signed proofs and put them back in the send_proofs list
    signed_proofs_secrets = [p.secret for p in signed_proofs]
    for p in send_proofs:
        if p.secret in signed_proofs_secrets:
            send_proofs[send_proofs.index(p)] = signed_proofs[
                signed_proofs_secrets.index(p.secret)
            ]

    # Now swap with signatures - this should succeed
    promises = await ledger.swap(proofs=send_proofs, outputs=outputs)

    # Verify the result
    assert len(promises) == len(outputs)
    assert [p.amount for p in promises] == [o.amount for o in outputs]
