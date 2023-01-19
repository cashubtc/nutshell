import asyncio
import pytest
from click.testing import CliRunner

from cashu.core.settings import VERSION
from cashu.wallet.cli import cli


from cashu.wallet.wallet import Wallet
from cashu.core.migrations import migrate_databases
from cashu.wallet import migrations

from tests.conftest import mint, SERVER_ENDPOINT

cli_prefix = ["--wallet", "test_wallet", "--host", SERVER_ENDPOINT]


async def init_wallet():
    wallet = Wallet(SERVER_ENDPOINT, "data/test_wallet", "wallet")
    await migrate_databases(wallet.db, migrations)
    await wallet.load_proofs()
    return wallet


@pytest.mark.asyncio
def test_info():
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "info"],
    )
    print("INFO")
    print(result.output)
    result.output.startswith(f"Version: {VERSION}")
    assert result.exit_code == 0


@pytest.mark.asyncio
def test_balance():
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "balance"],
    )
    print("------ BALANCE ------")
    print(result.output)
    wallet = asyncio.run(init_wallet())
    assert f"Balance: {wallet.available_balance} sat" in result.output
    assert result.exit_code == 0


@pytest.mark.asyncio
def test_wallets():
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "wallets"],
    )
    print("WALLETS")
    print(result.output)
    assert "test_wallet" in result.output
    assert result.exit_code == 0


@pytest.mark.asyncio
def test_invoice(mint):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "1000"],
    )
    print("INVOICE")
    print(result.output)
    wallet = asyncio.run(init_wallet())
    assert f"Balance: {wallet.available_balance} sat" in result.output
    assert result.exit_code == 0
