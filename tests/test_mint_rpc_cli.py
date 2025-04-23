
import pytest
from click.testing import CliRunner

from cashu.core.settings import settings
from cashu.mint.management_rpc.cli.cli import cli


@pytest.fixture(autouse=True, scope="session")
def cli_prefix():
    yield ["--insecure", "--host", settings.mint_rpc_server_addr, "--port", settings.mint_rpc_server_port]

'''
async def init_wallet():
    settings.debug = False
    wallet = await Wallet.with_db(
        url=settings.mint_url,
        db="test_data/test_cli_wallet",
        name="test_cli_wallet",
    )
    await wallet.load_proofs()
    return wallet
'''

def test_get_info(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "get-info"],
    )
    assert result.exception is None
    print("GET-INFO")
    print(result.output)
    #result.output.startswith(f"Version: {settings.version}")
    assert False