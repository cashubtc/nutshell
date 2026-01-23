import asyncio
from typing import Tuple

import bolt11
import pytest
from click.testing import CliRunner

from cashu.core.base import TokenV4
from cashu.core.settings import settings
from cashu.wallet.cli.cli import cli
from cashu.wallet.wallet import Wallet
from tests.helpers import (
    get_real_invoice,
    is_deprecated_api_only,
    is_fake,
    is_regtest,
    pay_if_regtest,
)


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


def get_invoice_from_invoices_command(output: str) -> dict[str, str]:
    splitted = output.split("\n")
    removed_empty_and_hiphens = [
        value for value in splitted if value and not value.startswith("-----")
    ]
    # filter only lines that have ": " in them
    removed_empty_and_hiphens = [
        value for value in removed_empty_and_hiphens if ": " in value
    ]
    dict_output = {
        f"{value.split(': ')[0]}": value.split(": ")[1]
        for value in removed_empty_and_hiphens
    }

    return dict_output


async def reset_invoices(wallet: Wallet):
    await wallet.db.execute("DELETE FROM bolt11_melt_quotes")
    await wallet.db.execute("DELETE FROM bolt11_mint_quotes")


async def init_wallet():
    settings.debug = False
    wallet = await Wallet.with_db(
        url=settings.mint_url,
        db="test_data/test_cli_wallet",
        name="test_cli_wallet",
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
    print("INFO --MINT")
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
    print("INFO --MNEMONIC")
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
    assert f"Balance: {w.available_balance}" in result.output
    assert result.exit_code == 0


        pytest.skip("only works with v1 API")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "1000"],
    )

    wallet = asyncio.run(init_wallet())
    assert wallet.available_balance >= 1000
    assert result.exit_code == 0


        pytest.skip("only works with v1 API")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "-v", "invoice", "1000"],
    )

    wallet = asyncio.run(init_wallet())
    assert wallet.available_balance >= 1000
    assert "Request: POST" in result.output
    assert "Response: 200" in result.output


def test_invoice_return_immediately(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "-n", "1000"],
    )

    assert result.exception is None

    invoice, invoice_id = get_bolt11_and_invoice_id_from_invoice_command(result.output)
    asyncio.run(pay_if_regtest(invoice))

    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "1000", "--id", invoice_id],
    )
    assert result.exception is None

    wallet = asyncio.run(init_wallet())
    assert wallet.available_balance >= 1000
    assert result.exit_code == 0


