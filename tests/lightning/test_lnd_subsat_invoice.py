"""A melt quote that covers the whole invoice must not be paid as a partial one.

The quote amount is rounded up to the backend unit, so an invoice whose amount
carries sub-satoshi precision — what a wallet produces when the user enters a
fiat amount — leaves the quote slightly above the invoice amount. Reading that
rounding as a partial payment sends an ordinary melt through QueryRoutes, which
only knows the public graph and cannot reach a destination that is published in
the invoice's route hints (Phoenix and other private-channel wallets).
"""

import json
from types import SimpleNamespace
from typing import Any

import pytest

from cashu.core.base import MeltQuote, MeltQuoteState, Unit
from cashu.lightning.base import PaymentResult
from cashu.lightning.lnd_grpc.lnd_grpc import LndRPCWallet
from cashu.lightning.lndrest import LndRestWallet

# a real fiat-denominated Phoenix invoice: 24_779.417 sat
SUBSAT_INVOICE_MSAT = 24_779_417
SUBSAT_QUOTE_SAT = 24_780  # what get_payment_quote rounds it up to


def _quote(amount: int) -> MeltQuote:
    return MeltQuote(
        quote="q1",
        method="bolt11",
        request="lnbc1fake",
        checking_id="checking-1",
        unit="sat",
        amount=amount,
        fee_reserve=1,
        state=MeltQuoteState.unpaid,
    )


class FakePayment:
    status = 2  # SUCCEEDED
    payment_hash = "11" * 32
    fee_msat = 0
    payment_preimage = "ab" * 32
    failure_reason = 0


def _mock_grpc(monkeypatch, wallet, invoice_amount_msat: int) -> dict[str, Any]:
    """Route both paths to recognisable outcomes and report which one ran."""
    calls: dict[str, Any] = {"partial": False, "send_payment": False}

    class FakeStub:
        def __init__(self, channel):
            pass

        async def SendPaymentV2(self, request):
            calls["send_payment"] = True
            calls["payment_request"] = request.payment_request
            yield FakePayment()

    class FakeChannel:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    async def fake_partial(quote, amount, fee_limit_msat):
        calls["partial"] = True
        return SimpleNamespace(result=PaymentResult.FAILED)

    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.grpc.aio.secure_channel",
        lambda *args, **kwargs: FakeChannel(),
    )
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.routerstub.RouterStub", FakeStub
    )
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.bolt11.decode",
        lambda request: SimpleNamespace(amount_msat=invoice_amount_msat),
    )
    monkeypatch.setattr(
        "cashu.lightning.lnd_grpc.lnd_grpc.settings.mint_lnd_allow_self_payment", False
    )
    monkeypatch.setattr(wallet, "pay_partial_invoice", fake_partial)
    return calls


def _grpc_wallet() -> LndRPCWallet:
    wallet = object.__new__(LndRPCWallet)
    wallet.unit = Unit.sat
    wallet.supports_mpp = True
    wallet.endpoint = "localhost:10009"
    wallet.combined_creds = None
    return wallet


@pytest.mark.asyncio
async def test_lndrpc_subsat_invoice_is_paid_in_full(monkeypatch):
    """Rounding the quote up past the invoice amount is not a partial payment."""
    wallet = _grpc_wallet()
    calls = _mock_grpc(monkeypatch, wallet, SUBSAT_INVOICE_MSAT)

    result = await wallet.pay_invoice(_quote(SUBSAT_QUOTE_SAT), fee_limit_msat=1000)

    assert calls["partial"] is False
    assert calls["send_payment"] is True
    # the whole payment request is handed to lnd, which reads its route hints
    assert calls["payment_request"] == "lnbc1fake"
    assert result.result == PaymentResult.SETTLED


@pytest.mark.asyncio
async def test_lndrpc_quote_below_invoice_is_still_partial(monkeypatch):
    """A quote that covers only part of the invoice keeps using MPP."""
    wallet = _grpc_wallet()
    calls = _mock_grpc(monkeypatch, wallet, 2000)

    await wallet.pay_invoice(_quote(1), fee_limit_msat=1000)

    assert calls["partial"] is True
    assert calls["send_payment"] is False


def _mock_rest(monkeypatch, wallet, invoice_amount_msat: int) -> dict[str, Any]:
    calls: dict[str, Any] = {"partial": False, "send_payment": False}

    class FakeStream:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def aiter_lines(self):
            yield json.dumps(
                {
                    "result": {
                        "status": "SUCCEEDED",
                        "payment_hash": "11" * 32,
                        "payment_preimage": "ab" * 32,
                        "fee_msat": "0",
                    }
                }
            )

    class FakeClient:
        def stream(self, method, url, **kwargs):
            calls["send_payment"] = True
            calls["payment_request"] = kwargs["json"]["payment_request"]
            return FakeStream()

    async def fake_partial(quote, amount, fee_limit_msat):
        calls["partial"] = True
        return SimpleNamespace(result=PaymentResult.FAILED)

    wallet.client = FakeClient()
    monkeypatch.setattr(
        "cashu.lightning.lndrest.bolt11.decode",
        lambda request: SimpleNamespace(amount_msat=invoice_amount_msat),
    )
    monkeypatch.setattr(
        "cashu.lightning.lndrest.settings.mint_lnd_allow_self_payment", False
    )
    monkeypatch.setattr(wallet, "pay_partial_invoice", fake_partial)
    return calls


def _rest_wallet() -> LndRestWallet:
    wallet = object.__new__(LndRestWallet)
    wallet.unit = Unit.sat
    wallet.supports_mpp = True
    wallet.endpoint = "http://localhost:8080"
    wallet.macaroon = "macaroon"
    wallet.cert = None
    return wallet


@pytest.mark.asyncio
async def test_lndrest_subsat_invoice_is_paid_in_full(monkeypatch):
    wallet = _rest_wallet()
    calls = _mock_rest(monkeypatch, wallet, SUBSAT_INVOICE_MSAT)

    result = await wallet.pay_invoice(_quote(SUBSAT_QUOTE_SAT), fee_limit_msat=1000)

    assert calls["partial"] is False
    assert calls["send_payment"] is True
    assert calls["payment_request"] == "lnbc1fake"
    assert result.result == PaymentResult.SETTLED


@pytest.mark.asyncio
async def test_lndrest_quote_below_invoice_is_still_partial(monkeypatch):
    wallet = _rest_wallet()
    calls = _mock_rest(monkeypatch, wallet, 2000)

    await wallet.pay_invoice(_quote(1), fee_limit_msat=1000)

    assert calls["partial"] is True
    assert calls["send_payment"] is False
