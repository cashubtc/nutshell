import os

import pytest
import pytest_asyncio

from cashu.core.base import Proof, TokenV3, TokenV3Token
from cashu.core.settings import settings
from cashu.wallet.helpers import receive, redeem_TokenV3
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import pay_if_regtest


@pytest_asyncio.fixture(scope="function")
async def wallet_sender():
    wallet = await Wallet.with_db(
        SERVER_ENDPOINT, "test_data/wallet_receive_named_sender", name="sender"
    )
    await wallet.load_mint()
    yield wallet


@pytest_asyncio.fixture(scope="function")
async def wallet_bob():
    # Mirrors how the CLI constructs the main wallet: db directory is
    # <cashu_dir>/<wallet_name>, same convention receive_cli/redeem_TokenV3 assume.
    wallet = await Wallet.with_db(
        SERVER_ENDPOINT, os.path.join(settings.cashu_dir, "bob"), name="bob"
    )
    await wallet.load_mint()
    yield wallet


async def _mint_p2pk_locked_proofs_to(
    wallet_sender: Wallet, wallet_receiver: Wallet, amount: int
) -> list[Proof]:
    mint_quote = await wallet_sender.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet_sender.mint(64, quote_id=mint_quote.quote)
    pubkey_receiver = await wallet_receiver.create_p2pk_pubkey()
    secret_lock = await wallet_sender.create_p2pk_lock(pubkey_receiver)
    _, send_proofs = await wallet_sender.swap_to_send(
        wallet_sender.proofs, amount, secret_lock=secret_lock
    )
    return send_proofs


@pytest.mark.asyncio
async def test_receive_p2pk_locked_token_named_wallet_succeeds(
    wallet_sender: Wallet, wallet_bob: Wallet
):
    """Regression test: receiving a P2PK-locked token into a non-default-named
    wallet used to silently open a different (empty) database, generate a
    fresh mnemonic, and submit the proof without a witness, which the mint
    rejected with "Witness is missing for p2pk signature".
    """
    send_proofs = await _mint_p2pk_locked_proofs_to(wallet_sender, wallet_bob, 8)
    token = TokenV3(token=[TokenV3Token(mint=wallet_sender.url, proofs=send_proofs)])

    await receive(wallet_bob, token)

    await wallet_bob.load_proofs(reload=True)
    assert wallet_bob.available_balance.amount == 8


@pytest.mark.asyncio
async def test_redeem_tokenv3_reuses_receivers_private_key(
    wallet_sender: Wallet, wallet_bob: Wallet
):
    """Pins the invariant behind the fix: the throwaway mint_wallet constructed
    inside redeem_TokenV3 must share the receiving wallet's private key (i.e.
    open the same on-disk wallet), not silently create a new identity.
    """
    send_proofs = await _mint_p2pk_locked_proofs_to(wallet_sender, wallet_bob, 8)
    token = TokenV3(token=[TokenV3Token(mint=wallet_sender.url, proofs=send_proofs)])

    mint_wallet = await redeem_TokenV3(wallet_bob, token)

    assert mint_wallet.private_key.to_hex() == wallet_bob.private_key.to_hex()
