import os

import click
import pytest
import pytest_asyncio

from cashu.core.base import Proof, TokenV3, TokenV3Token
from cashu.core.settings import settings
from cashu.wallet.cli.cli_helpers import get_mint_wallet, receive_all_pending
from cashu.wallet.crud import get_reserved_proofs
from cashu.wallet.helpers import receive, redeem_TokenV3
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import pay_if_regtest


@pytest_asyncio.fixture(scope="function")
async def wallet_sender(tmp_path):
    wallet = await Wallet.with_db(
        SERVER_ENDPOINT, str(tmp_path / "sender"), name="sender"
    )
    await wallet.load_mint()
    yield wallet
    await wallet.db.engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def wallet_bob(tmp_path, monkeypatch):
    # Mirrors how the CLI constructs the main wallet: db directory is
    # <cashu_dir>/<wallet_name>, same convention receive_cli/redeem_TokenV3 assume.
    monkeypatch.setattr(settings, "cashu_dir", str(tmp_path))
    wallet = await Wallet.with_db(
        SERVER_ENDPOINT, os.path.join(settings.cashu_dir, "bob"), name="bob"
    )
    await wallet.load_mint()
    yield wallet
    await wallet.db.engine.dispose()


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


@pytest.mark.asyncio
async def test_redeem_tokenv3_custom_db_dir_reuses_receivers_private_key(
    wallet_sender: Wallet, tmp_path
):
    """Pins that the mint_wallet built inside redeem_TokenV3 derives its db
    directory from the receiver wallet's actual db.db_location, not from
    settings.cashu_dir + wallet.name. A wallet created with a custom db
    directory (library/test usage) must still redeem into itself instead of
    opening whatever wallet happens to live under <cashu_dir>/<name>.
    """
    wallet_receiver = await Wallet.with_db(
        SERVER_ENDPOINT, str(tmp_path / "custom"), name="bob"
    )
    await wallet_receiver.load_mint()

    send_proofs = await _mint_p2pk_locked_proofs_to(wallet_sender, wallet_receiver, 8)
    token = TokenV3(token=[TokenV3Token(mint=wallet_sender.url, proofs=send_proofs)])

    mint_wallet = await redeem_TokenV3(wallet_receiver, token)

    assert mint_wallet.private_key.to_hex() == wallet_receiver.private_key.to_hex()


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["wallet", "bob"])
async def test_select_mint_and_receive_pending_reuse_wallet(tmp_path, monkeypatch, name):
    monkeypatch.setattr(settings, "cashu_dir", str(tmp_path / "cli-default"))
    wallet = await Wallet.with_db(SERVER_ENDPOINT, str(tmp_path / "custom"), name=name)
    try:
        await wallet.load_mint()
        quote = await wallet.request_mint(64)
        await pay_if_regtest(quote.request)
        await wallet.mint(64, quote_id=quote.quote)
        await wallet.swap_to_send(wallet.proofs, 8, set_reserved=True)
        assert wallet.available_balance.amount == 56
        ctx = click.Context(
            click.Command("receive"),
            obj={"WALLET": wallet, "HOST": None, "YES": True},
        )

        selected = await get_mint_wallet(ctx)
        assert selected.db.path == wallet.db.path
        assert selected.private_key.to_hex() == wallet.private_key.to_hex()
        await receive_all_pending(ctx, selected)
        received = ctx.obj["WALLET"]

        await wallet.load_proofs(reload=True)
        assert wallet.available_balance.amount == 64
        assert not await get_reserved_proofs(wallet.db)
        assert received.db.path == wallet.db.path
        assert received.private_key.to_hex() == wallet.private_key.to_hex()
        assert not (tmp_path / "cli-default" / name).exists()
        await selected.db.engine.dispose()
        await received.db.engine.dispose()
    finally:
        await wallet.db.engine.dispose()
