import asyncio
import socket
import sys
import time
from contextlib import ExitStack
from subprocess import STDOUT, Popen

import httpx
import pytest
import pytest_asyncio
from click.testing import CliRunner

from cashu.core.base import (
    NUT10Option,
    PaymentRequest,
    SupportedMethod,
    TokenV3,
    TokenV4,
    Unit,
)
from cashu.core.crypto.secp import PrivateKey
from cashu.core.nuts.nut18 import serialize
from cashu.core.nuts.nut26 import serialize as serialize_bech32m
from cashu.core.settings import settings
from cashu.wallet.cli.cli import cli
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
settings.mint_derivation_path_list = ["m/0'/2'/0'"]
settings.mint_input_fee_ppk = int(sys.argv[4])
settings.mint_require_auth = False
settings.mint_rpc_server_enable = False
settings.fakewallet_brr = True
settings.fakewallet_delay_incoming_payment = 0
uvicorn.run("cashu.mint.app:app", host="127.0.0.1", port=int(sys.argv[3]))
"""


@pytest.fixture(scope="module")
def mint(tmp_path_factory, request):
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
                        str(getattr(request, "param", 0)),
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

    token = deserialize_token_from_string(serialized)
    assert token.serialize() == serialized
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


async def _fund_request_wallet(url, directory, name, amount, unit="sat", split=None):
    wallet = await Wallet.with_db(url, str(directory / name), name=name, unit=unit)
    try:
        await wallet.load_mint()
        quote = await wallet.request_mint(amount)
        await wallet.mint(amount, split=split, quote_id=quote.quote)
    finally:
        await wallet.db.engine.dispose()


@pytest.mark.parametrize(
    "encode", [serialize, serialize_bech32m], ids=["nut18", "nut26"]
)
@pytest.mark.parametrize("unit", ["sat", "usd"])
@pytest.mark.parametrize(
    "preferred_balance,explicit,strict,disabled,expected",
    [
        (16, False, False, False, 0),
        (8, False, False, False, 1),
        (16, True, False, False, 1),
        (16, False, True, False, 0),
        (8, False, True, False, None),
        (16, False, False, True, 1),
    ],
)
def test_cli_selects_payment_request_mint(
    mint,
    tmp_path,
    monkeypatch,
    encode,
    unit,
    preferred_balance,
    explicit,
    strict,
    disabled,
    expected,
):
    monkeypatch.setattr(settings, "cashu_dir", str(tmp_path))
    monkeypatch.setattr(settings, "mint_url", mint[1])
    monkeypatch.setattr(settings, "wallet_unit", "sat")
    for url, amount in zip(mint, [preferred_balance, 64]):
        asyncio.run(_fund_request_wallet(url, tmp_path, "payer", amount, unit))

    if disabled:
        load_info = Wallet.load_mint_info

        async def disabled_info(wallet, *args, **kwargs):
            info = await load_info(wallet, *args, **kwargs)
            if wallet.url == mint[0] and info:
                info.nuts[5]["disabled"] = True
            return info

        monkeypatch.setattr(Wallet, "load_mint_info", disabled_info)

    request = PaymentRequest(
        a=10,
        u=unit,
        m=[mint[0] + "/"],
        mp=not strict,
        sm=[SupportedMethod(mn="bolt11", mf=5)],
    )
    prefix = ["--wallet", "payer", "--tests", "--yes"]
    if explicit:
        prefix += ["--host", mint[1], "--unit", unit]
    result = CliRunner().invoke(cli, [*prefix, "pay", encode(request)])
    if expected is None:
        assert result.exit_code == 1
        assert "No funded mint satisfies" in result.output
        assert "cashuB" not in result.stdout
        return
    assert result.exit_code == 0, (result.output, result.exception)
    token = TokenV4.deserialize(
        next(line for line in result.stdout.splitlines() if line.startswith("cashuB"))
    )
    assert token.mint == mint[expected]
    assert token.unit == unit
    assert token.amount == (10 if expected == 0 else 15)


@pytest.mark.parametrize("mint", [250, 1000], indirect=True)
@pytest.mark.parametrize(
    "encode", [serialize, serialize_bech32m], ids=["nut18", "nut26"]
)
@pytest.mark.parametrize("locked", [False, True])
@pytest.mark.parametrize("fee", [0, 5])
@pytest.mark.parametrize("amount", [8, 10])
def test_payment_request_redeemed_value(
    mint, tmp_path, monkeypatch, encode, locked, fee, amount
):
    monkeypatch.setattr(settings, "cashu_dir", str(tmp_path))
    monkeypatch.setattr(settings, "mint_url", mint[0])
    asyncio.run(_fund_request_wallet(mint[0], tmp_path, "payer", 64))

    async def receiver():
        wallet = await Wallet.with_db(
            mint[0], str(tmp_path / "receiver"), name="receiver"
        )
        await wallet.load_mint()
        return wallet

    recipient = asyncio.run(receiver())
    pubkey = asyncio.run(recipient.create_p2pk_pubkey())
    request = PaymentRequest(
        a=amount,
        u="sat",
        sm=[SupportedMethod(mn="bolt11", mf=fee)],
        nut10=NUT10Option(k="P2PK", d=pubkey) if locked else None,
    )
    result = CliRunner().invoke(
        cli,
        [
            "--wallet",
            "payer",
            "--host",
            mint[0],
            "--tests",
            "pay",
            encode(request),
            "-y",
        ],
    )
    assert result.exit_code == 0, (result.output, result.exception)
    token = TokenV4.deserialize(
        next(line for line in result.stdout.splitlines() if line.startswith("cashuB"))
    )

    async def redeem():
        try:
            proofs = token.proofs
            await recipient._expand_short_keyset_ids(proofs)
            assert recipient.keysets[proofs[0].id].input_fee_ppk > 0
            assert token.amount - recipient.get_fees_for_proofs(proofs) >= amount + fee
            await recipient.redeem(proofs)
            assert recipient.available_balance >= amount + fee
        finally:
            await recipient.db.engine.dispose()

    asyncio.run(redeem())


@pytest.mark.parametrize("mint", [1000], indirect=True)
@pytest.mark.parametrize(
    "encode", [serialize, serialize_bech32m], ids=["nut18", "nut26"]
)
@pytest.mark.parametrize("locked", [False, True])
def test_request_selection_accounts_for_swap_fees(
    mint, tmp_path, monkeypatch, encode, locked
):
    monkeypatch.setattr(settings, "cashu_dir", str(tmp_path))
    monkeypatch.setattr(settings, "mint_url", mint[1])
    for url, amount in zip(mint, [16, 64]):
        asyncio.run(
            _fund_request_wallet(url, tmp_path, "payer", amount, split=[amount])
        )
    request = PaymentRequest(
        a=15,
        u="sat",
        m=[mint[0]],
        mp=True,
        nut10=(
            NUT10Option(k="P2PK", d=PrivateKey().public_key.format().hex())
            if locked
            else None
        ),
    )
    result = CliRunner().invoke(
        cli, ["--wallet", "payer", "--tests", "--yes", "pay", encode(request)]
    )
    assert result.exit_code == 0, (result.output, result.exception)
    token = TokenV4.deserialize(
        next(line for line in result.stdout.splitlines() if line.startswith("cashuB"))
    )
    assert token.mint == mint[1 if locked else 0]
