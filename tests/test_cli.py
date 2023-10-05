import asyncio
import base64
import json

import pytest
from click.testing import CliRunner

from cashu.core.base import TokenV3
from cashu.core.settings import settings
from cashu.wallet.cli.cli import cli
from cashu.wallet.wallet import Wallet


@pytest.fixture(autouse=True, scope="session")
def cli_prefix():
    yield ["--wallet", "test_cli_wallet", "--host", settings.mint_url, "--tests"]


async def init_wallet():
    wallet = await Wallet.with_db(
        url=settings.mint_host,
        db="test_data/test_cli_wallet",
        name="wallet",
    )
    await wallet.load_proofs()
    return wallet


def test_info(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "info"],
    )
    assert result.exception is None
    print("INFO")
    print(result.output)
    result.output.startswith(f"Version: {settings.version}")
    assert result.exit_code == 0


def test_info_with_mint(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "info", "--mint"],
    )
    assert result.exception is None
    print("INFO -M")
    print(result.output)
    assert "Mint name" in result.output
    assert result.exit_code == 0


def test_info_with_mnemonic(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "info", "--mnemonic"],
    )
    assert result.exception is None
    print("INFO -M")
    print(result.output)
    assert "Mnemonic" in result.output
    assert result.exit_code == 0


def test_balance(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "balance"],
    )
    assert result.exception is None
    print("------ BALANCE ------")
    print(result.output)
    w = asyncio.run(init_wallet())
    assert f"Balance: {w.available_balance} sat" in result.output
    assert result.exit_code == 0


def test_invoice(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "1000"],
    )
    assert result.exception is None
    print("INVOICE")
    print(result.output)
    wallet = asyncio.run(init_wallet())
    # assert wallet.available_balance >= 1000
    assert f"Balance: {wallet.available_balance} sat" in result.output
    assert result.exit_code == 0


def test_invoice_with_split(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "10", "-s", "1"],
    )
    assert result.exception is None
    # wallet = asyncio.run(init_wallet())
    # assert wallet.proof_amounts.count(1) >= 10


def test_wallets(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "wallets"],
    )
    assert result.exception is None
    print("WALLETS")
    # on github this is empty
    if len(result.output):
        assert "test_cli_wallet" in result.output
    assert result.exit_code == 0


def test_send(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "send", "10"],
    )
    assert result.exception is None
    print(result.output)
    token_str = result.output.split("\n")[0]
    assert "cashuA" in token_str, "output does not have a token"
    token = TokenV3.deserialize(token_str)
    assert token.token[0].proofs[0].dleq is None, "dleq included"


def test_send_with_dleq(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "send", "10", "--dleq"],
    )
    assert result.exception is None
    print(result.output)
    token_str = result.output.split("\n")[0]
    assert "cashuA" in token_str, "output does not have a token"
    token = TokenV3.deserialize(token_str)
    assert token.token[0].proofs[0].dleq is not None, "no dleq included"


def test_send_legacy(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "send", "10", "--legacy"],
    )
    assert result.exception is None
    print(result.output)
    # this is the legacy token in the output
    token_str = result.output.split("\n")[4]
    assert token_str.startswith("eyJwcm9v"), "output is not as expected"


def test_send_without_split(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "send", "2", "--nosplit"],
    )
    assert result.exception is None
    print("SEND")
    print(result.output)
    assert "cashuA" in result.output, "output does not have a token"


def test_send_without_split_but_wrong_amount(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "send", "10", "--nosplit"],
    )
    assert "No proof with this amount found" in str(result.exception)


def test_receive_tokenv3(mint, cli_prefix):
    runner = CliRunner()
    token = (
        "cashuAeyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogIjFjQ05JQVoyWC93MSIsICJhbW91bnQiOiAyLCAic2VjcmV0IjogIld6TEF2VW53SDlRaFYwQU1rMy1oYWciLC"
        "AiQyI6ICIwMmZlMzUxYjAyN2FlMGY1ZDkyN2U2ZjFjMTljMjNjNTc3NzRhZTI2M2UyOGExN2E2MTUxNjY1ZjU3NWNhNjMyNWMifSwgeyJpZCI6ICIxY0NOSUFaMlgvdzEiLCAiYW"
        "1vdW50IjogOCwgInNlY3JldCI6ICJDamFTeTcyR2dVOGwzMGV6bE5zZnVBIiwgIkMiOiAiMDNjMzM0OTJlM2ZlNjI4NzFhMWEzMDhiNWUyYjVhZjBkNWI1Mjk5YzI0YmVkNDI2Zj"
        "Q1YzZmNDg5N2QzZjc4NGQ5In1dLCAibWludCI6ICJodHRwOi8vbG9jYWxob3N0OjMzMzcifV19"
    )
    result = runner.invoke(
        cli,
        [
            *cli_prefix,
            "receive",
            token,
        ],
    )
    assert result.exception is None
    print("RECEIVE")
    print(result.output)


def test_receive_tokenv3_no_mint(mint, cli_prefix):
    # this test works only if the previous test succeeds because we simulate the case
    # where the mint URL is not in the token therefore, we need to know the mint keyset
    # already and have the mint URL in the db
    runner = CliRunner()
    token_dict = {
        "token": [
            {
                "proofs": [
                    {
                        "id": "d5c08d2006765ffc",
                        "amount": 2,
                        "secret": "-h3FW0Qh_QX-oZsUvsDn6Q",
                        "C": "036937837eb89eb86325f09e29211d1a2894e346bc5c40e6a18e599fec6108df0b",
                    },
                    {
                        "id": "d5c08d2006765ffc",
                        "amount": 8,
                        "secret": "7wEa5H3dhRDdMf_xsY7srg",
                        "C": "02bffd3ced9165237108664132b281b0af65e3eeed5672adf34cea71988aec55b5",
                    },
                ]
            }
        ]
    }
    token = "cashuA" + base64.b64encode(json.dumps(token_dict).encode()).decode()
    result = runner.invoke(
        cli,
        [
            *cli_prefix,
            "receive",
            token,
        ],
    )
    assert result.exception is None
    print("RECEIVE")
    print(result.output)


def test_receive_tokenv2(mint, cli_prefix):
    runner = CliRunner()
    token_dict = {
        "proofs": [
            {
                "id": "d5c08d2006765ffc",
                "amount": 2,
                "secret": "aRdDo9EuoreE_9otztMUZg",
                "C": (
                    "03a369fe27b1bef9883074427dc3756e458e2c0b455c0befdc8f5f507bc90d16e7"
                ),
            },
            {
                "id": "d5c08d2006765ffc",
                "amount": 8,
                "secret": "LFPlZzR-LXq_aqC0hTx42g",
                "C": (
                    "034cbc41af48210af65fb5c9b393d28f2d9d6a9a9326bb7346c5dfdf159095326c"
                ),
            },
        ],
        "mints": [{"url": "http://localhost:3337", "ids": ["d5c08d2006765ffc"]}],
    }
    token = base64.b64encode(json.dumps(token_dict).encode()).decode()
    result = runner.invoke(
        cli,
        [*cli_prefix, "receive", token],
    )
    assert result.exception is None
    print("RECEIVE")
    print(result.output)


def test_receive_tokenv1(mint, cli_prefix):
    runner = CliRunner()
    token_dict = [
        {
            "id": "d5c08d2006765ffc",
            "amount": 2,
            "secret": "Fulsgs2KPWQLqIK_m4K80A",
            "C": "0357898ec9a2217eaab1d77bc537695022e256a9c2c0674d2e3ab3bb4b4d331fb1",
        },
        {
            "id": "d5c08d2006765ffc",
            "amount": 8,
            "secret": "reD0Ck5MKlAMD4ui68K_lA",
            "C": "023d83d4140545d5588652359b2a21a89c865db3302e9316da39604a06d60ad38f",
        },
    ]
    token = base64.b64encode(json.dumps(token_dict).encode()).decode()
    result = runner.invoke(
        cli,
        [*cli_prefix, "receive", token],
    )
    assert result.exception is None
    print("RECEIVE")
    print(result.output)


def test_nostr_send(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            *cli_prefix,
            "send",
            "1",
            "-n",
            "aafa164a8ab54a6b6c67bbac98a5d5aec7ea4075af8928a11478ab9d74aec4ca",
            "-y",
        ],
    )
    assert result.exception is None
    print("NOSTR_SEND")
    print(result.output)


def test_pending(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "pending"],
    )
    assert result.exception is None
    print(result.output)
    assert result.exit_code == 0


def test_selfpay(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "selfpay"],
    )
    assert result.exception is None
    print(result.output)
    assert result.exit_code == 0
