import pytest
import pytest_asyncio

from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet as Wallet1
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
async def test_ledger_swap_p2pk_without_signature(wallet1: Wallet1, ledger: Ledger):
    """Test ledger swap with p2pk locked tokens without providing signatures."""
    # Mint tokens to the wallet
    mint_quote = await wallet1.request_mint(64)
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
