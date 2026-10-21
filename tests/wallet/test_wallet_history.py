import asyncio
import sqlite3
from types import ModuleType
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio
from click.testing import CliRunner

from cashu.core.base import (
    Amount,
    MeltQuote,
    MeltQuoteState,
    MintQuote,
    MintQuoteState,
    Unit,
)
from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.core.models import PostMeltQuoteResponse
from cashu.core.settings import settings
from cashu.lightning.fake import FakeWallet
from cashu.wallet import migrations
from cashu.wallet.cli.cli import cli
from cashu.wallet.crud import (
    get_history,
    store_bolt11_melt_quote,
    store_bolt11_mint_quote,
    store_ecash_transaction,
)
from cashu.wallet.helpers import deserialize_token_from_string, receive, send
from cashu.wallet.wallet import Wallet
from tests.helpers import is_fake


@pytest.mark.parametrize("preimage", [None, "ab" * 32], ids=["missing", "supplied"])
def test_melt_response_retains_preimage(preimage):
    response = PostMeltQuoteResponse(
        quote="paid-quote",
        amount=8,
        unit="sat",
        request="test-payment-request",
        fee_reserve=0,
        state="PAID",
        expiry=None,
        payment_preimage=preimage,
    )
    quote = MeltQuote.from_resp_wallet(response, "https://mint.test")
    assert quote.payment_preimage == preimage


@pytest_asyncio.fixture
async def wallet_db(tmp_path):
    db = Database("wallet", str(tmp_path))
    await migrate_databases(db, migrations)
    yield db
    await db.engine.dispose()


async def fund(wallet, amount=64):
    await wallet.load_mint()
    quote = await wallet.request_mint(amount)
    await wallet.mint(amount, quote.quote)
    return quote


@pytest_asyncio.fixture
async def wallets(tmp_path):
    if not is_fake:
        pytest.skip("History flow tests require FakeWallet")
    sender = await Wallet.with_db(settings.mint_url, str(tmp_path / "sender"))
    receiver = await Wallet.with_db(settings.mint_url, str(tmp_path / "receiver"))
    await fund(sender)
    await receiver.load_mint()
    yield sender, receiver
    await sender.db.engine.dispose()
    await receiver.db.engine.dispose()


@pytest.mark.asyncio
async def test_quote_only_upgrade_and_projection(tmp_path):
    # Run the actual pre-history migrations, then upgrade a populated wallet.
    before = ModuleType("cashu.wallet.migrations")
    before.__dict__.update(
        (name, value)
        for name, value in vars(migrations).items()
        if name != "m020_create_ecash_transactions" and name != "__name__"
    )
    db = Database("wallet", str(tmp_path))
    try:
        await migrate_databases(db, before)
        for quote_id, state, issued, timestamp in [
            ("legacy", MintQuoteState.issued, None, None),
            ("reused", MintQuoteState.paid, 12, 100),
            ("paid-only", MintQuoteState.paid, 0, 100),
            ("unpaid", MintQuoteState.unpaid, 0, 100),
        ]:
            await store_bolt11_mint_quote(
                db,
                MintQuote(
                    quote=quote_id,
                    method="bolt11",
                    request=quote_id,
                    checking_id="",
                    unit="sat",
                    amount=64,
                    state=state,
                    amount_issued=issued,
                    mint="https://old-mint.test",
                    paid_time=timestamp,
                ),
            )
        await migrate_databases(db, migrations)
        assert [(r["reference"], r["amount"]) for r in await get_history(db)] == [
            ("reused", 12),
            ("legacy", 64),
        ]
        assert (await get_history(db))[1]["created_time"] is None
        assert all(r["mint"] == "https://old-mint.test" for r in await get_history(db))
        # A second startup must not recreate the table or fabricate old events.
        await migrate_databases(db, migrations)
        assert not await db.fetchall("SELECT * FROM ecash_transactions")
    finally:
        await db.engine.dispose()


@pytest.mark.asyncio
async def test_history_has_stable_ties_and_preserves_mints_units(
    wallet_db, monkeypatch
):
    monkeypatch.setattr("cashu.wallet.crud.time.time", lambda: 100)
    for kind, amount, unit, mint in [
        ("send", 8, "sat", "https://a.test"),
        ("receive", 123, "usd", "https://b.test"),
        ("send", 2, "sat", "https://a.test"),
    ]:
        await store_ecash_transaction(
            wallet_db, tx_type=kind, amount=amount, unit=unit, mint=mint
        )
    rows = await get_history(wallet_db)
    assert [(r["type"], r["amount"], r["unit"], r["mint"]) for r in rows] == [
        ("receive", 123, "usd", "https://b.test"),
        ("send", -8, "sat", "https://a.test"),
        ("send", -2, "sat", "https://a.test"),
    ]
    assert await get_history(wallet_db) == rows


@pytest.mark.asyncio
async def test_real_transfer_melt_and_reload(wallets):
    sender, receiver = wallets
    _, serialized = await send(sender, amount=16, lock="", legacy=False)
    token = deserialize_token_from_string(serialized)
    await receive(receiver, token)
    await sender.invalidate(sender.proofs, check_spendable=True)
    invoice = await FakeWallet(unit=Unit.sat).create_invoice(Amount(Unit.sat, 8))
    quote = await sender.melt_quote(invoice.payment_request)
    proofs, _ = await sender.select_to_send(
        sender.proofs, quote.amount + quote.fee_reserve, include_fees=True
    )
    response = await sender.melt(
        proofs, invoice.payment_request, quote.fee_reserve, quote.quote
    )
    rows = await get_history(sender.db)
    assert sorted((r["type"], r["amount"]) for r in rows) == [
        ("melt", -8),
        ("mint", 64),
        ("send", -16),
    ]
    assert all(r["mint"] == sender.url and r["unit"] == "sat" for r in rows)
    mint_row = next(r for r in rows if r["type"] == "mint")
    assert mint_row["method"] == "bolt11"
    assert mint_row["reference"]
    melt_row = next(r for r in rows if r["type"] == "melt")
    assert melt_row["reference"] == quote.quote
    assert melt_row["request"] == invoice.payment_request
    assert melt_row["payment_preimage"] == response.payment_preimage
    send_row = next(r for r in rows if r["type"] == "send")
    assert send_row["method"] is None
    assert send_row["request"] is None
    assert send_row["payment_preimage"] is None
    assert [(r["type"], r["amount"]) for r in await get_history(receiver.db)] == [
        ("receive", 16)
    ]
    reloaded = await Wallet.with_db(sender.url, sender.db.db_location)
    try:
        assert await get_history(reloaded.db) == rows
    finally:
        await reloaded.db.engine.dispose()
    with pytest.raises(Exception):
        await send(sender, amount=1000000, lock="", legacy=False)
    with pytest.raises(Exception):
        await receive(receiver, deserialize_token_from_string(serialized))
    assert await get_history(sender.db) == rows
    assert len(await get_history(receiver.db)) == 1


@pytest.mark.asyncio
async def test_owned_inputs_do_not_become_income_when_cache_is_empty(wallets):
    sender, _ = wallets
    _, serialized = await send(sender, amount=16, lock="", legacy=False)
    reopened = await Wallet.with_db(sender.url, sender.db.db_location)
    try:
        await reopened.load_mint()
        assert not reopened.proofs
        token = deserialize_token_from_string(serialized)
        proofs = token.proofs
        await reopened._expand_short_keyset_ids(proofs)
        await reopened.redeem(proofs)
        await reopened.load_proofs(reload=True)
        await reopened.redeem(reopened.proofs)  # selfpay/refresh
        assert {r["type"] for r in await get_history(reopened.db)} == {"mint", "send"}
    finally:
        await reopened.db.engine.dispose()


@pytest.mark.asyncio
async def test_mixed_owned_and_outside_inputs_count_only_outside_credit(wallets):
    sender, receiver = wallets
    await fund(receiver, 16)
    owned = list(receiver.proofs)
    _, serialized = await send(sender, amount=8, lock="", legacy=False)
    token = deserialize_token_from_string(serialized)
    outside = token.proofs
    await receiver._expand_short_keyset_ids(outside)
    await receiver.redeem(owned + outside)
    assert sorted((r["type"], r["amount"]) for r in await get_history(receiver.db)) == [
        ("mint", 16),
        ("receive", 8),
    ]


@pytest.mark.parametrize("cached", [False, True], ids=["uncached", "cached"])
def test_history_cli_empty_formats_units_and_does_not_poll(tmp_path, monkeypatch, cached):
    monkeypatch.setattr(settings, "cashu_dir", str(tmp_path))
    monkeypatch.setattr(settings, "debug", False)
    host = settings.mint_url if cached else "https://uncached-mint.invalid"

    async def prepare():
        wallet = await Wallet.with_db(
            host, str(tmp_path / "cli"), name="cli"
        )
        if cached:
            await wallet.load_mint()
        else:
            assert not wallet.mint_info
            assert not wallet.keysets
        await wallet.db.engine.dispose()

    asyncio.run(prepare())
    request = AsyncMock(side_effect=AssertionError("History must not poll the mint"))
    monkeypatch.setattr(httpx.AsyncClient, "request", request)
    args = ["--host", host, "--wallet", "cli", "--tests", "history"]
    runner = CliRunner()
    result = runner.invoke(cli, args)
    assert result.exit_code == 0, result.output
    assert "No transaction history." in result.output
    request.assert_not_called()

    async def add_rows():
        db = Database("cli", str(tmp_path / "cli"))
        await store_ecash_transaction(
            db, tx_type="receive", amount=123, unit="usd", mint="https://usd.test"
        )
        await store_bolt11_mint_quote(
            db,
            MintQuote(
                quote="legacy",
                method="bolt11",
                request="legacy",
                checking_id="",
                unit="sat",
                amount=8,
                state=MintQuoteState.issued,
                amount_issued=None,
                mint="https://sat.test",
            ),
        )
        for name, preimage in [
            ("missing", None),
            ("empty", ""),
            ("supplied", "ab" * 32),
        ]:
            await store_bolt11_melt_quote(
                db,
                MeltQuote(
                    quote=f"melt-{name}",
                    method="bolt11",
                    request=f"test-request-{name}",
                    checking_id="",
                    unit="sat",
                    amount=2,
                    fee_reserve=0,
                    state=MeltQuoteState.paid,
                    mint="https://sat.test",
                    paid_time=100,
                    payment_preimage=preimage,
                ),
            )
        await db.engine.dispose()

    asyncio.run(add_rows())
    path = tmp_path / "cli" / "cli.sqlite3"
    with sqlite3.connect(path) as db:
        before = list(db.iterdump())
    result = runner.invoke(cli, args)
    assert result.exit_code == 0, result.output
    assert "+$1.23 USD" in result.output and "https://usd.test" in result.output
    assert "+8 sat" in result.output and "unknown" in result.output
    assert "Payment method: bolt11" in result.output
    assert "Quote ID: legacy" in result.output
    for name in ("missing", "empty", "supplied"):
        assert f"Payment request: test-request-{name}" in result.output
    assert (
        f"Payment request: test-request-supplied\n  Preimage: {'ab' * 32}"
        in result.output
    )
    assert result.output.count("  Preimage:") == 1
    assert "Time (UTC)" in result.output
    assert runner.invoke(cli, args).output == result.output
    with sqlite3.connect(path) as db:
        assert list(db.iterdump()) == before
    request.assert_not_called()
