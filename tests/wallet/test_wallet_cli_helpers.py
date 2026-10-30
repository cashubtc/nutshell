from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import click
import pytest

from cashu.core.base import Unit
from cashu.core.settings import settings
from cashu.wallet.cli import cli_helpers


@pytest.fixture
def mint_context(monkeypatch, tmp_path):
    # The largest available balance is neither the last URL nor the largest
    # total balance: reserved proofs must not determine the default mint.
    balances = {
        "https://a-large.test": {"available": 200, "balance": 201, "unit": "usd"},
        "https://z-small.test": {"available": 100, "balance": 1000, "unit": "usd"},
    }
    wallet = SimpleNamespace(
        url="https://default.test",
        name="my-wallet",
        unit=Unit.usd,
        load_proofs=AsyncMock(),
        balance_per_minturl=AsyncMock(return_value=balances),
        balance_per_keyset=Mock(return_value={}),
    )
    selected = SimpleNamespace(load_proofs=AsyncMock())
    with_db = AsyncMock(return_value=selected)
    monkeypatch.setattr(cli_helpers.Wallet, "with_db", with_db)
    monkeypatch.setattr(settings, "cashu_dir", str(tmp_path))
    ctx = click.Context(
        click.Command("send"),
        obj={"WALLET": wallet, "HOST": None, "WALLET_NAME": "wallet-dir", "YES": False},
    )
    return SimpleNamespace(
        ctx=ctx,
        wallet=wallet,
        balances=balances,
        selected=selected,
        with_db=with_db,
        db_path=str(tmp_path / "wallet-dir"),
    )


def assert_selected_wallet(context, selected, url):
    assert selected is context.selected
    context.wallet.load_proofs.assert_awaited_once_with(reload=True, all_keysets=True)
    context.wallet.balance_per_minturl.assert_awaited_once_with(unit=Unit.usd)
    context.with_db.assert_awaited_once_with(
        url, context.db_path, name="my-wallet", unit="usd"
    )
    selected.load_proofs.assert_awaited_once_with(reload=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "yes, choice, expected_url",
    [
        (True, None, "https://a-large.test"),
        (False, "", "https://a-large.test"),
        (False, "1", "https://a-large.test"),
        (False, "2", "https://z-small.test"),
    ],
)
async def test_select_mint(
    mint_context, monkeypatch, capsys, yes, choice, expected_url
):
    mint_context.ctx.obj["YES"] = yes
    prompt = Mock(return_value=choice)
    monkeypatch.setattr("builtins.input", prompt)

    selected = await cli_helpers.get_mint_wallet(mint_context.ctx)

    assert_selected_wallet(mint_context, selected, expected_url)
    output = capsys.readouterr().out
    assert "You have balances in 2 mints:" in output
    assert "https://a-large.test" in output
    assert "https://z-small.test" in output
    if yes:
        prompt.assert_not_called()
    else:
        prompt.assert_called_once_with(
            "Select mint [1-2] or press enter for mint with largest balance (Mint 1): "
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("choice", ["0", "00", "-1", "3", "abc", "1.5", "²"])
async def test_select_mint_rejects_invalid_choice(mint_context, monkeypatch, choice):
    monkeypatch.setattr("builtins.input", Mock(return_value=choice))

    with pytest.raises(Exception, match=r"^invalid input\.$"):
        await cli_helpers.get_mint_wallet(mint_context.ctx)

    mint_context.with_db.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "funded, host, expected_url",
    [
        (True, None, "https://a-large.test"),
        (True, "https://a-large.test", "https://a-large.test"),
        (True, "https://new.test", "https://new.test"),
        (False, "https://new.test", "https://new.test"),
        (False, None, "https://default.test"),
    ],
)
async def test_select_mint_without_multiple_balances(
    mint_context, monkeypatch, funded, host, expected_url
):
    balances = (
        {"https://a-large.test": mint_context.balances["https://a-large.test"]}
        if funded
        else {}
    )
    mint_context.wallet.balance_per_minturl.return_value = balances
    mint_context.ctx.obj["HOST"] = host
    prompt = Mock(side_effect=AssertionError("a single mint needs no selection"))
    monkeypatch.setattr("builtins.input", prompt)

    selected = await cli_helpers.get_mint_wallet(mint_context.ctx)

    assert_selected_wallet(mint_context, selected, expected_url)
    prompt.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "choice, expected_unit",
    [
        ("", Unit.sat),
        ("1", Unit.sat),
        ("2", Unit.usd),
        ("0", None),
        ("00", None),
        ("-1", None),
        ("3", None),
        ("abc", None),
        ("²", None),
    ],
)
async def test_select_unit_validates_choice(monkeypatch, capsys, choice, expected_unit):
    wallet = SimpleNamespace(
        url="https://mint.test",
        unit=Unit.sat,
        load_proofs=AsyncMock(),
        balance_per_unit=lambda: {
            Unit.sat: {"available": 1},
            Unit.usd: {"available": 2},
        },
    )
    ctx = click.Context(click.Command("send"), obj={"WALLET": wallet, "UNIT": None})
    monkeypatch.setattr(settings, "wallet_unit", "sat")
    prompt = Mock(return_value=choice)
    monkeypatch.setattr("builtins.input", prompt)

    if expected_unit is None:
        with pytest.raises(Exception, match=r"^invalid input\.$"):
            await cli_helpers.get_unit_wallet(ctx)
        assert wallet.unit == Unit.sat
    else:
        assert await cli_helpers.get_unit_wallet(ctx) is wallet
        assert wallet.unit == expected_unit
        assert settings.wallet_unit == expected_unit.name

    wallet.load_proofs.assert_awaited_once_with(reload=False)
    prompt.assert_called_once_with(
        "Select unit [1-2] or press enter for your default 'sat': "
    )
    expected_output = (
        "You have balances in 2 units:\n\n"
        "Unit 1 (sat) – Balance: 1 sat\n"
        "Unit 2 (usd) – Balance: $0.02 USD\n\n"
    )
    if expected_unit is not None:
        expected_output += f"Selected unit: {expected_unit.name}\n\n"
    assert capsys.readouterr().out == expected_output


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "units, explicit_unit, yes, default_unit, expected_unit",
    [
        ([], None, False, "sat", Unit.sat),
        ([Unit.usd], None, False, "sat", Unit.usd),
        ([Unit.usd], "sat", False, "sat", Unit.sat),
        ([Unit.sat, Unit.usd], "usd", False, "sat", Unit.usd),
        ([Unit.sat, Unit.usd], None, True, "sat", Unit.sat),
        ([Unit.sat, Unit.usd], None, True, "usd", Unit.usd),
    ],
)
async def test_select_unit_without_prompt(
    monkeypatch, units, explicit_unit, yes, default_unit, expected_unit
):
    wallet = SimpleNamespace(
        url="https://mint.test",
        unit=Unit.sat,
        load_proofs=AsyncMock(),
        balance_per_unit=lambda: {unit: {"available": 1} for unit in units},
    )
    ctx = click.Context(
        click.Command("send"),
        obj={"WALLET": wallet, "UNIT": explicit_unit, "YES": yes},
    )
    monkeypatch.setattr(settings, "wallet_unit", default_unit)
    prompt = Mock(side_effect=AssertionError("unit selection should not prompt"))
    monkeypatch.setattr("builtins.input", prompt)

    assert await cli_helpers.get_unit_wallet(ctx) is wallet
    assert wallet.unit == expected_unit
    assert settings.wallet_unit == expected_unit.name
    wallet.load_proofs.assert_awaited_once_with(reload=False)
    prompt.assert_not_called()
