from types import SimpleNamespace
from typing import Optional, cast

import pytest
import pytest_asyncio

from cashu.core.base import Unit
from cashu.core.mint_info import MintInfo
from cashu.core.models import PostMeltQuoteResponse
from cashu.wallet.crud import get_bolt11_melt_quote
from cashu.wallet.v1_api import LedgerAPI
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import assert_err, is_fake


def quote_resp(amount: int, unit: str = "sat") -> PostMeltQuoteResponse:
    return PostMeltQuoteResponse(
        quote="q",
        amount=amount,
        unit=unit,
        request="lnbc1",
        fee_reserve=0,
        state="UNPAID",
        expiry=None,
    )


def check(
    unit: Unit, amount: int, expected_msat: int, resp_unit: Optional[str] = None
) -> None:
    wallet = cast(Wallet, SimpleNamespace(unit=unit))
    Wallet._check_melt_quote(
        wallet, quote_resp(amount, resp_unit or unit.name), expected_msat
    )


@pytest.mark.parametrize(
    "unit,amount,expected_msat",
    [
        (Unit.sat, 20, 20_000),
        (Unit.sat, 21, 20_500),  # rounded up
        (Unit.sat, 20, 20_500),  # rounded down: the mint's loss
        (Unit.sat, 2, 1_999),
        (Unit.msat, 20_500, 20_500),
        (Unit.usd, 10**9, 20_000),  # not checked without a rate
    ],
)
def test_check_melt_quote_accepts(unit, amount, expected_msat):
    check(unit, amount, expected_msat)


@pytest.mark.parametrize(
    "unit,amount,expected_msat",
    [
        (Unit.sat, 21, 20_000),
        (Unit.sat, 22, 20_500),
        (Unit.sat, 3, 1_999),
        (Unit.msat, 20_501, 20_500),
    ],
)
def test_check_melt_quote_refuses_overquote(unit, amount, expected_msat):
    with pytest.raises(Exception, match="at most"):
        check(unit, amount, expected_msat)


def test_check_melt_quote_refuses_other_unit():
    with pytest.raises(Exception, match="Mint quoted in msat"):
        check(Unit.sat, 20, 20_000, resp_unit="msat")


@pytest_asyncio.fixture(scope="function")
async def wallet1(mint, tmp_path):
    wallet1 = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db=str(tmp_path / "wallet1"),
        name="wallet1",
    )
    await wallet1.load_mint()
    yield wallet1
    await wallet1.db.engine.dispose()


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="needs the fake backend's internal invoices")
async def test_melt_quote_honest(wallet1: Wallet):
    invoice = (await wallet1.request_mint(64)).request
    quote = await wallet1.melt_quote(invoice)
    assert quote.amount == 64
    assert await get_bolt11_melt_quote(db=wallet1.db, quote=quote.quote)


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="needs the fake backend's internal invoices")
async def test_melt_quote_overquote_refused_before_storing(
    wallet1: Wallet, monkeypatch
):
    invoice = (await wallet1.request_mint(64)).request
    original = LedgerAPI.melt_quote
    seen = {}

    async def inflated(self, payment_request, unit, amount_msat=None):
        resp = await original(self, payment_request, unit, amount_msat)
        seen["quote"] = resp.quote
        return resp.model_copy(update={"amount": resp.amount + 1})

    monkeypatch.setattr(LedgerAPI, "melt_quote", inflated)
    await assert_err(wallet1.melt_quote(invoice), "at most 64 sat")
    assert await get_bolt11_melt_quote(db=wallet1.db, quote=seen["quote"]) is None


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="needs the fake backend's internal invoices")
async def test_melt_quote_zero_amount_msat_checks_invoice_amount(wallet1: Wallet):
    # LedgerAPI.melt_quote sends no MPP option for a falsy amount_msat, so the
    # mint quotes the whole invoice and the check must expect the same.
    invoice = (await wallet1.request_mint(64)).request
    quote = await wallet1.melt_quote(invoice, amount_msat=0)
    assert quote.amount == 64
    assert await get_bolt11_melt_quote(db=wallet1.db, quote=quote.quote)


def mpp_stub(monkeypatch, wallet: Wallet, supported: bool, add: int = 0):
    """Stub the mint's MPP support and quote: amount = requested partial + add."""
    calls = []
    monkeypatch.setattr(MintInfo, "supports_mpp", lambda self, method, unit: supported)

    async def melt_quote(self, payment_request, unit, amount_msat=None):
        calls.append(amount_msat)
        return PostMeltQuoteResponse(
            quote=f"mpp-{len(calls)}",
            amount=-(-amount_msat // 1000) + add,
            unit=unit.name,
            request=payment_request,
            fee_reserve=0,
            state="UNPAID",
            expiry=None,
        )

    monkeypatch.setattr(LedgerAPI, "melt_quote", melt_quote)
    return calls


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="needs the fake backend's internal invoices")
async def test_melt_quote_mpp_checks_requested_partial(wallet1: Wallet, monkeypatch):
    invoice = (await wallet1.request_mint(64)).request
    calls = mpp_stub(monkeypatch, wallet1, supported=True)
    quote = await wallet1.melt_quote(invoice, amount_msat=32_000)
    assert calls == [32_000]
    assert quote.amount == 32
    assert await get_bolt11_melt_quote(db=wallet1.db, quote=quote.quote)


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="needs the fake backend's internal invoices")
async def test_melt_quote_mpp_inflated_partial_refused_before_storing(
    wallet1: Wallet, monkeypatch
):
    # 40 sat is within the 64-sat invoice, but above the 32-sat partial asked for
    invoice = (await wallet1.request_mint(64)).request
    mpp_stub(monkeypatch, wallet1, supported=True, add=8)
    await assert_err(wallet1.melt_quote(invoice, amount_msat=32_000), "at most 32 sat")
    assert await get_bolt11_melt_quote(db=wallet1.db, quote="mpp-1") is None


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="needs the fake backend's internal invoices")
async def test_melt_quote_mpp_unsupported_still_refused(wallet1: Wallet, monkeypatch):
    invoice = (await wallet1.request_mint(64)).request
    calls = mpp_stub(monkeypatch, wallet1, supported=False)
    await assert_err(
        wallet1.melt_quote(invoice, amount_msat=32_000),
        "Mint does not support MPP",
    )
    assert calls == []
