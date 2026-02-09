import asyncio

import pytest
from click.testing import CliRunner

from cashu.core.settings import settings
from cashu.mint.management_rpc.cli.cli import cli
from cashu.wallet.wallet import Wallet

from .helpers import is_deprecated_api_only, is_fake

payment_request = (
    "lnbc10u1pjap7phpp50s9lzr3477j0tvacpfy2ucrs4q0q6cvn232ex7nt2zqxxxj8gxrsdpv2phhwetjv4jzqcneypqyc6t8dp6xu6twva2xjuzzda6qcqzzsxqrrsss"
    "p575z0n39w2j7zgnpqtdlrgz9rycner4eptjm3lz363dzylnrm3h4s9qyyssqfz8jglcshnlcf0zkw4qu8fyr564lg59x5al724kms3h6gpuhx9xrfv27tgx3l3u3cyf6"
    "3r52u0xmac6max8mdupghfzh84t4hfsvrfsqwnuszf"
)

@pytest.fixture(autouse=True)
def cli_prefix():
    yield ["--insecure", "--host", settings.mint_rpc_server_addr, "--port", settings.mint_rpc_server_port]

async def init_wallet():
    settings.debug = False
    wallet = await Wallet.with_db(
        url=settings.mint_url,
        db="test_data/test_cli_wallet",
        name="test_cli_wallet",
    )
    await wallet.load_proofs()
    return wallet

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
    assert "Url successfully removed!" in result.output or "Contact method not found" in result.output

def test_add_remove_contact(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(cli, [*cli_prefix, "update", "contact", "add", "signal", "@example.420"])
    assert result.exception is None
    assert "Contact successfully added!" in result.output

    result = runner.invoke(cli, [*cli_prefix, "update", "contact", "remove", "signal"])
    assert result.exception is None
    assert "Contact successfully removed!" in result.output

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

@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake,
    reason=(
        "Only FakeWallet will mark the quote as paid"
    ),
)
async def test_update_mint_quote(cli_prefix):
    wallet = await init_wallet()
    mint_quote = await wallet.request_mint(100)
    await asyncio.sleep(1)
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "update", "mint-quote", "--", mint_quote.quote, "ISSUED"],
    )
    assert result.exception is None
    assert "Successfully updated!" in result.output

@pytest.mark.asyncio
@pytest.mark.skipif(
    is_deprecated_api_only,
    reason=("Deprecated API"),
)
async def test_update_melt_quote(cli_prefix):
    wallet = await init_wallet()
    melt_quote = await wallet.melt_quote("lnbc1u1p5qefdgsp5xj5cl559ks226f3vf3d7x2ev2qadplmkswp4649h755cfekdufsspp5sxenacdev78ssuwn5vehycs7ch2ds23hhzytut4ncm27gywtv6rqdqqcqpjrzjqdgp5ar48c8k4cns58jw9lamcdlh57trvrn9psgjrsvwz94j9tqsvrqsvcqqvqsqqqqqqqlgqqqzwyqq2q9qxpqysgqzg8e75zkcxazmd0wqmre6xgkumt7sl4ftsw0q4c6zvz8hn6zjxwz9fmdmwpupw7tw79f7gmukyeeh8vusvt03pgwfud9shj849rvrnqpgcpusw")
    assert melt_quote.quote
    await asyncio.sleep(1)
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "update", "melt-quote", "--", melt_quote.quote, "PAID"],
    )
    assert result.exception is None
    assert "Successfully updated!" in result.output

@pytest.mark.asyncio
async def test_get_mint_quote(cli_prefix):
    wallet = await init_wallet()
    mint_quote = await wallet.request_mint(100)
    await asyncio.sleep(1)
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "get", "mint-quote", "--", mint_quote.quote],
    )
    assert result.exception is None
    assert "mint quote:" in result.output

@pytest.mark.asyncio
@pytest.mark.skipif(
    is_deprecated_api_only,
    reason=("Deprecated API"),
)
async def test_get_melt_quote(cli_prefix):
    wallet = await init_wallet()
    melt_quote = await wallet.melt_quote("lnbc1u1p5qefd7sp55l6kmcrnqz5rejy4lghmgf9de0ucmmn2s3lvkvtkrr0qkwk5r0espp5da4x63rspz5rcfretdh6573c6qlpnzpxc8yq26cyqjc4sk0srfwsdqqcqpjrzjqv3dpepm8kfdxrk3sl6wzqdf49s9c0h9ljtjrek6c08r6aejlwcnur2z3sqqrrgqqyqqqqqqqqqqfcsqjq9qxpqysgq4l5rfjd4h84w7prmtgzjvq79ddy266svuz0d7dg44jmnwjpxg0zxef6hn4j8nzfp4c67qjpe0c9aw63ghu7rtcdg6n4zka9hym69euqq8w5wmj")
    await asyncio.sleep(1)
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "get", "melt-quote", "--", melt_quote.quote],
    )
    assert result.exception is None
    assert "melt quote:" in result.output

'''
@pytest.mark.asyncio
async def test_rotate_next_keyset(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(cli, [*cli_prefix, "next-keyset", "sat", "2"]) # Rotate keyset and add a 2 sat ppk fee
    assert result.exception is None
    print(result.output)
    assert "New keyset successfully created:" in result.output
    assert "keyset.unit = 'sat'" in result.output
    assert "keyset.input_fee_ppk = 2" in result.output
'''
