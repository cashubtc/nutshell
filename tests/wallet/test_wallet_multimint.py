import socket
import sys
import time
from contextlib import ExitStack
from subprocess import STDOUT, Popen

import httpx
import pytest
import pytest_asyncio

from cashu.core.base import TokenV3, Unit
from cashu.wallet.errors import BalanceTooLowError
from cashu.wallet.helpers import (
    deserialize_token_from_string,
    list_mints,
    receive,
    send,
)
from cashu.wallet.wallet import Wallet

MINT_RUNNER = """
import sys
import uvicorn
from cashu.core.settings import settings

settings.mint_private_key = sys.argv[1]
settings.mint_seed_decryption_key = ""
settings.mint_database = sys.argv[2]
settings.mint_backend_bolt11_sat = "FakeWallet"
settings.mint_backend_bolt11_usd = "FakeWallet"
settings.mint_input_fee_ppk = 0
settings.mint_require_auth = False
settings.mint_rpc_server_enable = False
settings.fakewallet_brr = True
settings.fakewallet_delay_incoming_payment = 0
uvicorn.run("cashu.mint.app:app", host="127.0.0.1", port=int(sys.argv[3]))
"""


@pytest.fixture(scope="module")
def mint(tmp_path_factory):
    """Run two independent FakeWallet mints without changing the shared test mint."""
    directory = tmp_path_factory.mktemp("multimint")
    urls = []
    with ExitStack() as stack:
        for index in range(2):
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            url = f"http://127.0.0.1:{port}"
            log_path = directory / f"mint{index}.log"
            log = stack.enter_context(log_path.open("w"))
            server = stack.enter_context(
                Popen(
                    [
                        sys.executable,
                        "-c",
                        MINT_RUNNER,
                        f"MULTIMINT_TEST_PRIVATE_KEY_{index}",
                        str(directory / f"mint{index}"),
                        str(port),
                    ],
                    stdout=log,
                    stderr=STDOUT,
                )
            )
            stack.callback(server.terminate)
            for _ in range(100):
                try:
                    httpx.get(f"{url}/v1/info").raise_for_status()
                    break
                except httpx.ConnectError:
                    time.sleep(0.1)
            else:
                pytest.fail(f"Mint did not start:\n{log_path.read_text()}")
            urls.append(url)
        yield urls


@pytest_asyncio.fixture
async def wallets(mint, tmp_path):
    wallets = []
    for index, url in enumerate(mint):
        wallet = await Wallet.with_db(url, str(tmp_path / f"wallet{index}"))
        await wallet.load_mint()
        quote = await wallet.request_mint(64)
        await wallet.mint(64, quote_id=quote.quote)
        wallets.append(wallet)
    assert wallets[0].keyset_id != wallets[1].keyset_id
    assert wallets[0].mint_info.pubkey != wallets[1].mint_info.pubkey
    yield wallets
    for wallet in wallets:
        await wallet.db.engine.dispose()


async def transfer(sender: Wallet, recipient: Wallet, amount: int, legacy: bool):
    _, serialized = await send(sender, amount=amount, lock="", legacy=legacy)
    balance = (await sender.balance_per_minturl())[sender.url]
    assert balance["balance"] - balance["available"] == amount
    token = (
        TokenV3.deserialize(serialized)
        if legacy
        else deserialize_token_from_string(serialized)
    )
    assert token.mint == sender.url
    assert token.amount == amount
    if legacy:
        mint_wallet = await receive(recipient, token)
    else:
        # Match the CLI: open the recipient's database at the token's mint.
        mint_wallet = await Wallet.with_db(
            token.mint, recipient.db.db_location, name=recipient.name
        )
        await receive(mint_wallet, token)
    await mint_wallet.db.engine.dispose()
    await sender.invalidate(sender.proofs, check_spendable=True)
    await recipient.load_proofs(reload=True, all_keysets=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy", [False, True], ids=["v4", "v3"])
async def test_exchange_tokens_between_mints(wallets, legacy):
    alice, bob = wallets
    alice_url, bob_url = alice.url, bob.url
    assert await list_mints(alice) == [alice_url]
    assert await list_mints(bob) == [bob_url]

    await transfer(alice, bob, 16, legacy)
    await transfer(bob, alice, 32, legacy)

    for wallet, amounts in [(alice, (48, 32)), (bob, (16, 32))]:
        await wallet.load_proofs(reload=True, all_keysets=True)
        assert wallet.balance.amount == sum(amounts)
        assert await wallet.balance_per_minturl(unit=Unit.sat) == {
            url: {"balance": amount, "available": amount, "unit": "sat"}
            for url, amount in zip((alice_url, bob_url), amounts)
        }
        assert set(await list_mints(wallet)) == {alice_url, bob_url}
        selected, _ = await wallet.select_to_send(wallet.proofs, 8)
        assert {proof.id for proof in selected} == {wallet.keyset_id}
        with pytest.raises(BalanceTooLowError):
            await wallet.select_to_send(wallet.proofs, sum(amounts))

    assert alice.url == alice_url
    assert bob.url == bob_url

    # Bob sends Alice's mint's tokens back using the same wallet database.
    bob_at_alice_mint = await Wallet.with_db(
        alice_url, bob.db.db_location, name=bob.name
    )
    assert bob_at_alice_mint.url == alice_url
    await transfer(bob_at_alice_mint, alice, 8, legacy)
    await bob_at_alice_mint.db.engine.dispose()
    await bob.load_proofs(reload=True, all_keysets=True)
    assert (await alice.balance_per_minturl())[alice_url]["available"] == 56
    assert (await bob.balance_per_minturl())[alice_url]["available"] == 8


@pytest.mark.asyncio
async def test_redeem_token_with_multiple_mints(wallets):
    alice, bob = wallets
    await transfer(bob, alice, 16, legacy=True)
    await alice.load_proofs(reload=True, all_keysets=True)
    await alice.load_keysets_from_db(url=None)

    with pytest.raises(ValueError, match="single mint URL"):
        await alice.serialize_proofs(alice.proofs)
    serialized = await alice.serialize_proofs(alice.proofs, legacy=True)

    token = TokenV3.deserialize(serialized)
    assert set(token.mints) == {alice.url, bob.url}
    assert token.amount == 80

    mint_wallet = await receive(bob, token)
    await mint_wallet.db.engine.dispose()
    await bob.load_proofs(reload=True, all_keysets=True)
    assert bob.balance.amount == 128
    assert await bob.balance_per_minturl(unit=Unit.sat) == {
        url: {"balance": 64, "available": 64, "unit": "sat"}
        for url in (alice.url, bob.url)
    }
    assert {proof.id for proof in bob.proofs} == {
        alice.keyset_id,
        bob.keyset_id,
    }
