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
    token = "cashuAeyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogImF5TVViZTk4NVVzeiIsICJhbW91bnQiOiAyLCAic2VjcmV0IjogImdQNDlRdl9EZkhxck5zMjVxY1E4a0EiLCAiQyI6ICIwMzZiNjY1MzIxYzBlNGRkYTIwMTI1YTYwOWU4Y2FlMmEzMzRkODRhZDhjZWU4NjY2NTQxYjYyZjk1YjA0Y2FhNmUifSwgeyJpZCI6ICJheU1VYmU5ODVVc3oiLCAiYW1vdW50IjogOCwgInNlY3JldCI6ICJzTWJ4WGtVTlZKVTh0MTd5cVFJMnFBIiwgIkMiOiAiMDM5ZmIzMTQxN2IyNmY2YWUwMjE1NmYxNzgyZWExYTQ4NTAwMzU2OTVlMTUxODZkNmMwM2MxMzI3ZWU3YWQwZjhlIn1dLCAibWludCI6ICJodHRwOi8vbG9jYWxob3N0OjMzMzcifV19"
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


@pytest.mark.asyncio
def test_receive_tokenv3_no_mint(mint, cli_prefix):
    # this test works only if the previous test succeeds because we simulate the case where the mint URL is not in the token
    # therefore, we need to know the mint keyset already and have the mint URL in the db
    runner = CliRunner()
    token = "cashuAeyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogImF5TVViZTk4NVVzeiIsICJhbW91bnQiOiAyLCAic2VjcmV0IjogIkw4XzlBc3d0Rzh1UENmZ29xWnRVRFEiLCAiQyI6ICIwMmE1ZWMzYmY0Nzk2ZTg1NjJhNGRjYjM2YWRkOWYwNDhmZTU3ZGU0ZjEyMjgxMzA3N2FlZjBlM2Y2ZGIwY2U3ZGQifSwgeyJpZCI6ICJheU1VYmU5ODVVc3oiLCAiYW1vdW50IjogOCwgInNlY3JldCI6ICJ2WWJKZXNhS3BMTnNwaXl3cXd3ejFRIiwgIkMiOiAiMDJjNWVkNDc4YjZjOWU0MTExYjhlOGU1MjBlNThhMTVhYzQzMjUwMGM1MTU2ZmFjNDkyN2Q0ODVhNzM3ZTdlYzA4In1dfV19"
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


@pytest.mark.asyncio
def test_receive_tokenv2(mint, cli_prefix):
    runner = CliRunner()
    token = "eyJwcm9vZnMiOiBbeyJpZCI6ICJheU1VYmU5ODVVc3oiLCAiYW1vdW50IjogMiwgInNlY3JldCI6ICJ5WWxWR2lmSmJQbGRJZmp5YUxYSnNBIiwgIkMiOiAiMDJlNDE5ZjExNGFlNTFiMzI1MGVkYjE5YTI4NzQ0MjgwMjAwMGE3NTFhZmEwZGZmZDM2N2QxYTI0NTI3NjY2NmIwIn0sIHsiaWQiOiAiYXlNVWJlOTg1VXN6IiwgImFtb3VudCI6IDgsICJzZWNyZXQiOiAiVlZraDZGTW5sUVZ2WlZOR2Z6emUwQSIsICJDIjogIjAyZGMxZDhjZmFiNDA2NGI4MWFhZThiZWEzNTBjNjIzNWM1NDIzOGNiN2E5ZmYxNTJjNjMxMTAwN2FlNDEzZmFlNyJ9XSwgIm1pbnRzIjogW3sidXJsIjogImh0dHA6Ly9sb2NhbGhvc3Q6MzMzNyIsICJpZHMiOiBbImF5TVViZTk4NVVzeiJdfV19"
    result = runner.invoke(
        cli,
        [*cli_prefix, "receive", token],
    )
    assert result.exception is None
    print("RECEIVE")
    print(result.output)


@pytest.mark.asyncio
def test_receive_tokenv1(mint, cli_prefix):
    runner = CliRunner()
    token = "W3siaWQiOiAiYXlNVWJlOTg1VXN6IiwgImFtb3VudCI6IDIsICJzZWNyZXQiOiAicTR6WFdzYl84cGlBRHRQSzB1MFAwdyIsICJDIjogIjAyNDVlYjFmY2E1ODhlYWM0Y2M3OGJkZTJiYmMzOGQwMmY4YTIyZTEyMjcyMjQ2M2RiNDk5ZjA0ZWQ2ZDMzNjZkZCJ9LCB7ImlkIjogImF5TVViZTk4NVVzeiIsICJhbW91bnQiOiA4LCAic2VjcmV0IjogInBsaTNKX0QwNkxQZ3RmaW5EZkFWckEiLCAiQyI6ICIwMmU0MDFlMTBhYjI3ODJlYzQzYjMxZmZmMGMxZjc4N2FlYjgyODViNjkxMTAyMzlmYTJiN2VkNzA2MzdhMTliNzUifV0="
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
