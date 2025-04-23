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
    result = runner.invoke(cli, [*cli_prefix, "get-info"])
    assert result.exception is None
    assert "Mint Info:" in result.output

def test_update_motd(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(cli, [*cli_prefix, "update", "motd", "Updated MOTD"])
    assert result.exception is None
    assert "Motd successfully updated!" in result.output

def test_update_short_description(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(cli, [*cli_prefix, "update", "description", "New short description"])
    assert result.exception is None
    assert "Short description successfully updated!" in result.output

def test_update_long_description(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(cli, [*cli_prefix, "update", "long-description", "New long description"])
    assert result.exception is None
    assert "Long description successfully updated!" in result.output

def test_update_icon_url(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(cli, [*cli_prefix, "update", "icon-url", "http://example.com/icon.png"])
    assert result.exception is None
    assert "Icon url successfully updated!" in result.output

def test_update_name(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(cli, [*cli_prefix, "update", "name", "New Mint Name"])
    assert result.exception is None
    assert "Name successfully updated!" in result.output

def test_add_mint_url(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(cli, [*cli_prefix, "update", "url", "add", "http://example.com"])
    assert "Url successfully added!" in result.output

def test_remove_mint_url(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(cli, [*cli_prefix, "update", "url", "remove", "http://example.com"])
    assert result.exception is None
    assert "Url successfully removed!" in result.output

def test_add_contact(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(cli, [*cli_prefix, "update", "contact", "add", "email", "example@example.com"])
    assert result.exception is None
    assert "Contact method already set" in result.output

    result = runner.invoke(cli, [*cli_prefix, "update", "contact", "add", "signal", "@example.420"])
    assert result.exception is None
    assert "Contact successfully added!" in result.output

def test_remove_contact(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(cli, [*cli_prefix, "update", "contact", "remove", "email"])
    assert result.exception is None
    assert "Contact successfully removed!" in result.output

    result = runner.invoke(cli, [*cli_prefix, "update", "contact", "remove", "email"])
    assert "Contact method not found" in result.output

def test_update_lightning_fee(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(cli, [*cli_prefix, "update", "lightning-fee", "2.5", "100"])
    assert result.exception is None
    assert "Lightning fee successfully updated!" in result.output

def test_update_auth_limits(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(cli, [*cli_prefix, "update", "auth", "60", "10"])
    assert result.exception is None
    assert "Rate limit per minute successfully updated!" in result.output

'''
def test_update_mint_quote(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(cli, [*cli_prefix, "update", "mint-quote", "quote-id", "PENDING"])
    assert result.exception is None
    assert "Successfully updated!" in result.output

def test_update_melt_quote(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(cli, [*cli_prefix, "update", "melt-quote", "quote-id", "PAID"])
    assert result.exception is None
    assert "Successfully updated!" in result.output

def test_get_mint_quote(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(cli, [*cli_prefix, "get", "mint-quote", "quote-id"])
    assert result.exception is None
    assert "mint quote:" in result.output

def test_get_melt_quote(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(cli, [*cli_prefix, "get", "melt-quote", "quote-id"])
    assert result.exception is None
    assert "mint quote:" in result.output
'''