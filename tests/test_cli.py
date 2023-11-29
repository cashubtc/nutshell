import asyncio
from typing import Tuple

import pytest
from click.testing import CliRunner

from cashu.core.base import TokenV3
from cashu.core.settings import settings
from cashu.wallet.cli.cli import cli
from cashu.wallet.wallet import Wallet
from tests.helpers import is_fake, pay_if_regtest


@pytest.fixture(autouse=True, scope="session")
def cli_prefix():
    yield ["--wallet", "test_cli_wallet", "--host", settings.mint_url, "--tests"]


def get_bolt11_and_invoice_id_from_invoice_command(output: str) -> Tuple[str, str]:
    invoice = [
        line.split(" ")[1] for line in output.split("\n") if line.startswith("Invoice")
    ][0]
    invoice_id = [
        line.split(" ")[-1] for line in output.split("\n") if line.startswith("You can")
    ][0]
    return invoice, invoice_id


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


@pytest.mark.skipif(not is_fake, reason="only on fakewallet")
def test_invoice_automatic_fakewallet(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "1000"],
    )
    assert result.exception is None
    print("INVOICE")
    print(result.output)
    wallet = asyncio.run(init_wallet())
    assert wallet.available_balance >= 1000
    assert f"Balance: {wallet.available_balance} sat" in result.output
    assert result.exit_code == 0


def test_invoice(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "-n", "1000"],
    )

    assert result.exception is None

    invoice, invoice_id = get_bolt11_and_invoice_id_from_invoice_command(result.output)
    pay_if_regtest(invoice)

    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "1000", "--id", invoice_id],
    )
    assert result.exception is None

    wallet = asyncio.run(init_wallet())
    assert wallet.available_balance >= 1000
    assert result.exit_code == 0


def test_invoice_with_split(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            *cli_prefix,
            "invoice",
            "10",
            "-s",
            "1",
            "-n",
        ],
    )
    assert result.exception is None

    invoice, invoice_id = get_bolt11_and_invoice_id_from_invoice_command(result.output)
    pay_if_regtest(invoice)
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "10", "-s", "1", "--id", invoice_id],
    )
    assert result.exception is None

    assert result.exception is None
    wallet = asyncio.run(init_wallet())
    assert wallet.proof_amounts.count(1) >= 10


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
    token = (
        "cashuAeyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogIjFjQ05JQVoyWC93MSIsICJhbW91bnQiOiAyLCAic2VjcmV0IjogIi1oM0ZXMFFoX1FYLW9ac1V2c0RuNlEiLC"
        "AiQyI6ICIwMzY5Mzc4MzdlYjg5ZWI4NjMyNWYwOWUyOTIxMWQxYTI4OTRlMzQ2YmM1YzQwZTZhMThlNTk5ZmVjNjEwOGRmMGIifSwgeyJpZCI6ICIxY0NOSUFaMlgvdzEiLCAiYW"
        "1vdW50IjogOCwgInNlY3JldCI6ICI3d0VhNUgzZGhSRGRNZl94c1k3c3JnIiwgIkMiOiAiMDJiZmZkM2NlZDkxNjUyMzcxMDg2NjQxMzJiMjgxYjBhZjY1ZTNlZWVkNTY3MmFkZj"
        "M0Y2VhNzE5ODhhZWM1NWI1In1dfV19"
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


def test_receive_tokenv2(mint, cli_prefix):
    runner = CliRunner()
    token = (
        "eyJwcm9vZnMiOiBbeyJpZCI6ICIxY0NOSUFaMlgvdzEiLCAiYW1vdW50IjogMiwgInNlY3JldCI6ICJhUmREbzlFdW9yZUVfOW90enRNVVpnIiwgIkMiOiAiMDNhMzY5ZmUy"
        "N2IxYmVmOTg4MzA3NDQyN2RjMzc1NmU0NThlMmMwYjQ1NWMwYmVmZGM4ZjVmNTA3YmM5MGQxNmU3In0sIHsiaWQiOiAiMWNDTklBWjJYL3cxIiwgImFtb3VudCI6IDgsICJzZWNy"
        "ZXQiOiAiTEZQbFp6Ui1MWHFfYXFDMGhUeDQyZyIsICJDIjogIjAzNGNiYzQxYWY0ODIxMGFmNjVmYjVjOWIzOTNkMjhmMmQ5ZDZhOWE5MzI2YmI3MzQ2YzVkZmRmMTU5MDk1MzI2"
        "YyJ9XSwgIm1pbnRzIjogW3sidXJsIjogImh0dHA6Ly9sb2NhbGhvc3Q6MzMzNyIsICJpZHMiOiBbIjFjQ05JQVoyWC93MSJdfV19"
    )
    result = runner.invoke(
        cli,
        [*cli_prefix, "receive", token],
    )
    assert result.exception is None
    print("RECEIVE")
    print(result.output)


def test_receive_tokenv1(mint, cli_prefix):
    runner = CliRunner()
    token = (
        "W3siaWQiOiAiMWNDTklBWjJYL3cxIiwgImFtb3VudCI6IDIsICJzZWNyZXQiOiAiRnVsc2dzMktQV1FMcUlLX200SzgwQSIsICJDIjogIjAzNTc4OThlYzlhMjIxN2VhYWIx"
        "ZDc3YmM1Mzc2OTUwMjJlMjU2YTljMmMwNjc0ZDJlM2FiM2JiNGI0ZDMzMWZiMSJ9LCB7ImlkIjogIjFjQ05JQVoyWC93MSIsICJhbW91bnQiOiA4LCAic2VjcmV0IjogInJlRDBD"
        "azVNS2xBTUQ0dWk2OEtfbEEiLCAiQyI6ICIwMjNkODNkNDE0MDU0NWQ1NTg4NjUyMzU5YjJhMjFhODljODY1ZGIzMzAyZTkzMTZkYTM5NjA0YTA2ZDYwYWQzOGYifV0="
    )
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
