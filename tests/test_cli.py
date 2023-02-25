import asyncio

import pytest
from click.testing import CliRunner

from cashu.core.migrations import migrate_databases
from cashu.core.settings import VERSION
from cashu.wallet import migrations
from cashu.wallet.cli.cli import cli
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT, mint

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
    # on github this is empty
    if len(result.output):
        assert "test_wallet" in result.output
    assert result.exit_code == 0


@pytest.mark.asyncio
def test_invoice():
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


@pytest.mark.asyncio
def test_send(mint):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "send", "10"],
    )
    print("SEND")
    print(result.output)

    token = [l for l in result.output.split("\n") if l.startswith("ey")][0]
    print("TOKEN")
    print(token)


@pytest.mark.asyncio
def test_receive_tokenv2(mint):
    runner = CliRunner()
    token = "eyJwcm9vZnMiOiBbeyJpZCI6ICJEU0FsOW52dnlmdmEiLCAiYW1vdW50IjogMiwgInNlY3JldCI6ICJ3MEs4dE9OcFJOdVFvUzQ1Y2g1NkJ3IiwgIkMiOiAiMDI3NzcxODY4NWQ0MDgxNmQ0MTdmZGE1NWUzN2YxOTFkN2E5ODA0N2QyYWE2YzFlNDRhMWZjNTM1ZmViZDdjZDQ5In0sIHsiaWQiOiAiRFNBbDludnZ5ZnZhIiwgImFtb3VudCI6IDgsICJzZWNyZXQiOiAiX2J4cDVHeG1JQUVaRFB5Sm5qaFUxdyIsICJDIjogIjAzZTY2M2UzOWYyNTZlZTAzOTBiNGFiMThkZDA2OTc0NjRjZjIzYTM4OTc1MDlmZDFlYzQ1MzMxMTRlMTcwMDQ2NCJ9XSwgIm1pbnRzIjogW3sidXJsIjogImh0dHA6Ly9sb2NhbGhvc3Q6MzMzNyIsICJpZHMiOiBbIkRTQWw5bnZ2eWZ2YSJdfV19"
    result = runner.invoke(
        cli,
        [*cli_prefix, "receive", token],
    )

    print("RECEIVE")
    print(result.output)


@pytest.mark.asyncio
def test_receive_tokenv1(mint):
    runner = CliRunner()
    token = "3siaWQiOiAiRFNBbDludnZ5ZnZhIiwgImFtb3VudCI6IDIsICJzZWNyZXQiOiAiX3VOV1ZNeDRhQndieWszRDZoLWREZyIsICJDIjogIjAyMmEzMzRmZTIzYTA1OTJhZmM3OTk3OWQyZDJmMmUwOTgxMGNkZTRlNDY5ZGYwYzZhMGE4ZDg0ZmY1MmIxOTZhNyJ9LCB7ImlkIjogIkRTQWw5bnZ2eWZ2YSIsICJhbW91bnQiOiA4LCAic2VjcmV0IjogIk9VUUxnRE90WXhHOXJUMzZKdHFwbWciLCAiQyI6ICIwMzVmMGM2NTNhNTEzMGY4ZmQwNjY5NDg5YzEwMDY3N2Q5NGU0MGFlZjhkYWE0OWZiZDIyZTgzZjhjNThkZjczMTUifV0"
    result = runner.invoke(
        cli,
        [*cli_prefix, "receive", token],
    )

    print("RECEIVE")
    print(result.output)


@pytest.mark.asyncio()
def test_nostr_send(mint):
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

    print("NOSTR_SEND")
    print(result.output)
