import asyncio
from pathlib import Path

import pytest
from click.testing import CliRunner

from cashu.core.settings import settings
from cashu.wallet.cli.cli import cli
from cashu.wallet.wallet import Wallet
from tests.helpers import is_fake


@pytest.mark.skipif(not is_fake, reason="requires FakeWallet")
@pytest.mark.parametrize("wallet_name", ["wallet", "bob"])
@pytest.mark.parametrize("legacy", [False, True], ids=["token_v4", "token_v3"])
def test_named_wallet_receive_list_and_spend(
    mint, monkeypatch, tmp_path: Path, wallet_name: str, legacy: bool
):
    """Regression for #1154: CLI commands must use the selected wallet database."""
    monkeypatch.setattr(settings, "cashu_dir", str(tmp_path))
    monkeypatch.setattr(settings, "wallet_name", "wallet")
    monkeypatch.setattr(settings, "wallet_verbose_requests", False)
    monkeypatch.setattr(settings, "debug", False)
    mint_url = settings.mint_url
    assert mint_url
    runner = CliRunner()

    def invoke(name: str, *command: str) -> str:
        result = runner.invoke(
            cli,
            [
                "--host",
                mint_url,
                "--wallet",
                name,
                "--unit",
                "sat",
                "--tests",
                "--yes",
                *command,
            ],
        )
        assert result.exit_code == 0, (result.output, result.exception)
        return result.output

    def token_from(output: str) -> str:
        return next(
            line
            for line in output.splitlines()
            if line.startswith(("cashuA", "cashuB"))
        )

    async def fund_sender():
        sender = await Wallet.with_db(mint_url, str(tmp_path / "sender"), name="sender")
        try:
            await sender.load_mint()
            quote = await sender.request_mint(256)
            await sender.mint(256, quote_id=quote.quote)
        finally:
            await sender.db.engine.dispose()

    asyncio.run(fund_sender())
    token = token_from(
        invoke("sender", "send", "250", *(["--legacy"] if legacy else []))
    )
    assert token.startswith("cashuA" if legacy else "cashuB")
    assert "Received 250 sat" in invoke(wallet_name, "receive", token)
    assert "Balance: 250 sat" in invoke(wallet_name, "balance")
    assert f"Wallet: {wallet_name}\tBalance: 250 sat (available: 250 sat) *" in invoke(
        wallet_name, "wallets"
    )
    if wallet_name != "wallet":
        assert not (tmp_path / wallet_name / "wallet.sqlite3").exists()

    outgoing = token_from(invoke(wallet_name, "send", "50"))
    assert "Balance: 200 sat" in invoke(wallet_name, "balance")
    assert f"Wallet: {wallet_name}\tBalance: 250 sat (available: 200 sat) *" in invoke(
        wallet_name, "wallets"
    )
    assert "Received 50 sat" in invoke("recipient", "receive", outgoing)
    assert "Balance: 50 sat" in invoke("recipient", "balance")
