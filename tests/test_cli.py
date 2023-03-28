import asyncio

import pytest
from click.testing import CliRunner

from cashu.core.migrations import migrate_databases
from cashu.core.settings import settings
from cashu.wallet import migrations
from cashu.wallet.cli.cli import cli
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT, mint


@pytest.fixture(autouse=True, scope="session")
def cli_prefix():
    yield ["--wallet", "test_wallet", "--host", settings.mint_url]


@pytest.fixture(scope="session")
def wallet():
    wallet = Wallet(settings.mint_host, "data/test_wallet", "wallet")
    asyncio.run(migrate_databases(wallet.db, migrations))
    asyncio.run(wallet.load_proofs())
    yield wallet


async def init_wallet():
    wallet = Wallet(settings.mint_host, "data/test_wallet", "wallet")
    await migrate_databases(wallet.db, migrations)
    await wallet.load_proofs()
    return wallet


@pytest.mark.asyncio
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


@pytest.mark.asyncio
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


@pytest.mark.asyncio
def test_invoice(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "1000"],
    )
    assert result.exception is None
    print("INVOICE")
    print(result.output)
    # wallet = asyncio.run(init_wallet())
    # assert f"Balance: {wallet.available_balance} sat" in result.output
    assert result.exit_code == 0


@pytest.mark.asyncio
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
        assert "test_wallet" in result.output
    assert result.exit_code == 0


@pytest.mark.asyncio
def test_send(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "send", "10"],
    )
    assert result.exception is None
    print("SEND")
    print(result.output)
    assert "cashuA" in result.output, "output does not have a token"


@pytest.mark.asyncio
def test_receive_tokenv3(mint, cli_prefix):
    runner = CliRunner()
    token = "cashuAeyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogIjBwY3JpVWE5QTEvaiIsICJhbW91bnQiOiAyLCAic2VjcmV0IjogImRkRUtudHdrU2ZMeFdWcFUtaHBjM0EiLCAiQyI6ICIwMzAzNjI2YzM4YzczZTcwZGZjYzUwMDBjZmI5OTYyNTM4MWQyYmM2MzExMmM2YzE5MzM5ZDU4Y2UzOWIyODNhNzkifSwgeyJpZCI6ICIwcGNyaVVhOUExL2oiLCAiYW1vdW50IjogOCwgInNlY3JldCI6ICJwcXRZMGh2MXlmS2R6a0dCLUU5TGJnIiwgIkMiOiAiMDM4MzFkYmNhODIzMDdkOTVjYWY2MDI2ZDZlZmI2YzMyYjQ3MTQ1MWVhMmJjNDY5ZWE2YTE5ZDc0MjM1M2Y2MTk1In1dLCAibWludCI6ICJodHRwOi8vbG9jYWxob3N0OjMzMzcifV19"
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


@pytest.mark.skip
@pytest.mark.asyncio
def test_receive_tokenv3_no_mint(mint, wallet, cli_prefix):
    runner = CliRunner()
    token = "cashuAeyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogIjBwY3JpVWE5QTEvaiIsICJhbW91bnQiOiAyLCAic2VjcmV0IjogInN2V0NUQlRJeVJnNXNYalhfcHhlQXciLCAiQyI6ICIwMmI1NGY4YTkwNmE2ZmQ2ZTRiM2RlODBjNWQxZTJmNzQzODQ1NzZkNDlkYmVlOTUzZDU4MWZiNzM5YTgwMGQxM2MifSwgeyJpZCI6ICIwcGNyaVVhOUExL2oiLCAiYW1vdW50IjogOCwgInNlY3JldCI6ICI4bWliQ1dFeE05dTBzNXpZOHdGRkV3IiwgIkMiOiAiMDI5YTQwOWM1MmQ0NTNiNzc5YTcyOTM0NDNiOWYxZGU3ZTU5OWYwMTI4ODJjMzRiNzExMjdiMDgxZTVmNTIyODI3In1dfV19"
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


# eyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogIjBwY3JpVWE5QTEvaiIsICJhbW91bnQiOiAyLCAic2VjcmV0IjogImRkRUtudHdrU2ZMeFdWcFUtaHBjM0EiLCAiQyI6ICIwMzAzNjI2YzM4YzczZTcwZGZjYzUwMDBjZmI5OTYyNTM4MWQyYmM2MzExMmM2YzE5MzM5ZDU4Y2UzOWIyODNhNzkifSwgeyJpZCI6ICIwcGNyaVVhOUExL2oiLCAiYW1vdW50IjogOCwgInNlY3JldCI6ICJwcXRZMGh2MXlmS2R6a0dCLUU5TGJnIiwgIkMiOiAiMDM4MzFkYmNhODIzMDdkOTVjYWY2MDI2ZDZlZmI2YzMyYjQ3MTQ1MWVhMmJjNDY5ZWE2YTE5ZDc0MjM1M2Y2MTk1In1dfV19


# @pytest.mark.asyncio
# def test_receive_tokenv3(mint):
#     wallet = asyncio.run(init_wallet())
#     runner = CliRunner()
#     token = "cashuAeyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogIjVXRWJoUzJiOXZrTyIsICJhbW91bnQiOiAyLCAic2VjcmV0IjogInpINEM3OXpwZWJYaDIxTDBEWk1qb1EiLCAiQyI6ICIwMmI4ZDZjYzA3NjliMWNiZmQyNzkwN2U2YTQ5YmY2MGMyYzUwYmUwNzhmOGNjMWU1YWE1NTY2NjE1Y2QwOGZmM2YifSwgeyJpZCI6ICI1V0ViaFMyYjl2a08iLCAiYW1vdW50IjogOCwgInNlY3JldCI6ICJSYW1aZEJ4a01ybWtmdXh6SjFIOU9RIiwgIkMiOiAiMDI2ZGU2ZDNjZDlmNDY4MDYzMTJkYTczZDE2YzQ2ZDc3NGNkODlhZTk2NzUwMWI3MzA1MmQwNTVmODZkNmJmMmMwIn1dLCAibWludCI6ICJodHRwOi8vbG9jYWxob3N0OjMzMzcifV19"
#     result = runner.invoke(
#         cli,
#         [*cli_prefix, "receive", token],
#     )
#     assert result.exception is None
#     print("RECEIVE")
#     print(result.output)


# @pytest.mark.asyncio
# def test_receive_tokenv3_no_mint(mint):
#     runner = CliRunner()
#     token = "cashuAeyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogIjVXRWJoUzJiOXZrTyIsICJhbW91bnQiOiAyLCAic2VjcmV0IjogInpINEM3OXpwZWJYaDIxTDBEWk1qb1EiLCAiQyI6ICIwMmI4ZDZjYzA3NjliMWNiZmQyNzkwN2U2YTQ5YmY2MGMyYzUwYmUwNzhmOGNjMWU1YWE1NTY2NjE1Y2QwOGZmM2YifSwgeyJpZCI6ICI1V0ViaFMyYjl2a08iLCAiYW1vdW50IjogOCwgInNlY3JldCI6ICJSYW1aZEJ4a01ybWtmdXh6SjFIOU9RIiwgIkMiOiAiMDI2ZGU2ZDNjZDlmNDY4MDYzMTJkYTczZDE2YzQ2ZDc3NGNkODlhZTk2NzUwMWI3MzA1MmQwNTVmODZkNmJmMmMwIn1dfV19"
#     result = runner.invoke(
#         cli,
#         [*cli_prefix, "receive", token],
#     )
#     assert result.exception is None
#     print("RECEIVE")
#     print(result.output)


@pytest.mark.skip
@pytest.mark.asyncio
def test_receive_tokenv2(mint, cli_prefix):
    runner = CliRunner()
    token = "eyJwcm9vZnMiOiBbeyJpZCI6ICJEU0FsOW52dnlmdmEiLCAiYW1vdW50IjogMiwgInNlY3JldCI6ICJ3MEs4dE9OcFJOdVFvUzQ1Y2g1NkJ3IiwgIkMiOiAiMDI3NzcxODY4NWQ0MDgxNmQ0MTdmZGE1NWUzN2YxOTFkN2E5ODA0N2QyYWE2YzFlNDRhMWZjNTM1ZmViZDdjZDQ5In0sIHsiaWQiOiAiRFNBbDludnZ5ZnZhIiwgImFtb3VudCI6IDgsICJzZWNyZXQiOiAiX2J4cDVHeG1JQUVaRFB5Sm5qaFUxdyIsICJDIjogIjAzZTY2M2UzOWYyNTZlZTAzOTBiNGFiMThkZDA2OTc0NjRjZjIzYTM4OTc1MDlmZDFlYzQ1MzMxMTRlMTcwMDQ2NCJ9XSwgIm1pbnRzIjogW3sidXJsIjogImh0dHA6Ly9sb2NhbGhvc3Q6MzMzNyIsICJpZHMiOiBbIkRTQWw5bnZ2eWZ2YSJdfV19"
    result = runner.invoke(
        cli,
        [*cli_prefix, "receive", token],
    )
    assert result.exception is None
    print("RECEIVE")
    print(result.output)


@pytest.mark.skip
@pytest.mark.asyncio
def test_receive_tokenv1(mint, cli_prefix):
    runner = CliRunner()
    token = "3siaWQiOiAiRFNBbDludnZ5ZnZhIiwgImFtb3VudCI6IDIsICJzZWNyZXQiOiAiX3VOV1ZNeDRhQndieWszRDZoLWREZyIsICJDIjogIjAyMmEzMzRmZTIzYTA1OTJhZmM3OTk3OWQyZDJmMmUwOTgxMGNkZTRlNDY5ZGYwYzZhMGE4ZDg0ZmY1MmIxOTZhNyJ9LCB7ImlkIjogIkRTQWw5bnZ2eWZ2YSIsICJhbW91bnQiOiA4LCAic2VjcmV0IjogIk9VUUxnRE90WXhHOXJUMzZKdHFwbWciLCAiQyI6ICIwMzVmMGM2NTNhNTEzMGY4ZmQwNjY5NDg5YzEwMDY3N2Q5NGU0MGFlZjhkYWE0OWZiZDIyZTgzZjhjNThkZjczMTUifV0"
    result = runner.invoke(
        cli,
        [*cli_prefix, "receive", token],
    )
    assert result.exception is None
    print("RECEIVE")
    print(result.output)


@pytest.mark.asyncio()
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
