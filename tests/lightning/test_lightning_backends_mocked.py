import base64
import json
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest

from cashu.core.base import Amount, MeltQuote, MeltQuoteState, Unit
from cashu.core.helpers import fee_reserve
from cashu.core.models import (
    PostMeltQuoteRequest,
    PostMeltRequestOptionMpp,
    PostMeltRequestOptions,
)
from cashu.lightning.base import PaymentResult, Unsupported
from cashu.lightning.blink import BlinkWallet
from cashu.lightning.clnrest import CLNRestWallet
from cashu.lightning.corelightningrest import CoreLightningRestWallet
from cashu.lightning.lnbits import LNbitsWallet  # type: ignore[attr-defined]
from cashu.lightning.lndrest import LndRestWallet
from cashu.lightning.strike import StrikeWallet


def _response(status_code: int, json_data=None, text: str = "") -> httpx.Response:
    request = httpx.Request("POST", "https://backend.test")
    if json_data is not None:
        return httpx.Response(status_code, json=json_data, request=request)
    return httpx.Response(status_code, text=text, request=request)


def _quote(request: str, amount: int = 1, unit: str = "sat") -> MeltQuote:
    return MeltQuote(
        quote="q1",
        method="bolt11",
        request=request,
        checking_id="checking-1",
        unit=unit,
        amount=amount,
        fee_reserve=1,
        state=MeltQuoteState.unpaid,
    )


class _StreamResponse:
    def __init__(self, lines: list[str]):
        self.lines = lines

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def aiter_lines(self):
        for line in self.lines:
            yield line


@pytest.mark.asyncio
async def test_lnbits_status_returns_error_on_detail():
    wallet = object.__new__(LNbitsWallet)
    wallet.unit = Unit.sat
    wallet.endpoint = "https://lnbits.test"

    class Client:
        async def get(self, url, timeout=None):
            return _response(200, {"detail": "bad key"})

    cast(Any, wallet).client = Client()

    status = await wallet.status()
    assert status.error_message == "LNbits error: bad key"
    assert status.balance.amount == 0


@pytest.mark.asyncio
async def test_lnbits_create_invoice_http_error_returns_failure():
    wallet = object.__new__(LNbitsWallet)
    wallet.unit = Unit.sat
    wallet.endpoint = "https://lnbits.test"

    class Client:
        async def post(self, url, json=None):
            return _response(500, {"detail": "bad"})

    cast(Any, wallet).client = Client()

    invoice = await wallet.create_invoice(Amount(Unit.sat, 2))
    assert not invoice.ok
    assert "HTTP status" in str(invoice.error_message)


@pytest.mark.asyncio
async def test_lnbits_pay_invoice_without_hash_is_unknown():
    wallet = object.__new__(LNbitsWallet)
    wallet.unit = Unit.sat
    wallet.endpoint = "https://lnbits.test"

    class Client:
        async def post(self, url, json=None, timeout=None):
            return _response(200, {"paid": True})

    cast(Any, wallet).client = Client()
    result = await wallet.pay_invoice(_quote("lnbc1fake"), 1000)
    assert result.result == PaymentResult.UNKNOWN
    assert result.error_message == "No payment_hash received"


@pytest.mark.asyncio
async def test_lnbits_get_payment_status_rejects_invalid_response():
    wallet = object.__new__(LNbitsWallet)
    wallet.unit = Unit.sat
    wallet.endpoint = "https://lnbits.test"

    class Client:
        async def get(self, url):
            return _response(200, {"foo": "bar"})

    cast(Any, wallet).client = Client()
    status = await wallet.get_payment_status("hash")
    assert status.result == PaymentResult.UNKNOWN
    assert status.error_message == "invalid response"


@pytest.mark.asyncio
async def test_lnbits_get_invoice_status_maps_pending_and_failed():
    wallet = object.__new__(LNbitsWallet)
    wallet.unit = Unit.sat
    wallet.endpoint = "https://lnbits.test"

    class Client:
        calls = 0

        async def get(self, url):
            Client.calls += 1
            if Client.calls == 1:
                return _response(
                    200,
                    {
                        "paid": False,
                        "details": {"status": "pending", "fee": -2},
                        "preimage": None,
                    },
                )
            return _response(
                200,
                {
                    "paid": False,
                    "details": {"status": "failed", "fee": -3},
                    "preimage": None,
                },
            )

    cast(Any, wallet).client = Client()
    pending = await wallet.get_invoice_status("hash")
    failed = await wallet.get_invoice_status("hash")

    assert pending.result == PaymentResult.PENDING
    assert failed.result == PaymentResult.FAILED


@pytest.mark.asyncio
async def test_strike_status_falls_back_to_usdt_for_usd_unit():
    wallet = object.__new__(StrikeWallet)
    wallet.unit = Unit.usd
    wallet.endpoint = "https://strike.test"
    wallet.currency = "USD"

    class Client:
        async def get(self, url, timeout=None):
            return _response(200, [{"currency": "USDT", "total": "12.34"}])

    cast(Any, wallet).client = Client()
    status = await wallet.status()
    assert wallet.currency == "USDT"
    assert status.balance.unit == Unit.usd
    assert status.balance.amount == 1234


@pytest.mark.asyncio
async def test_strike_get_payment_quote_checks_currency_mismatch():
    wallet = object.__new__(StrikeWallet)
    wallet.unit = Unit.sat
    wallet.endpoint = "https://strike.test"
    wallet.currency = "BTC"

    class Client:
        async def post(self, url, json=None, timeout=None):
            return _response(
                200,
                {
                    "lightningNetworkFee": {"amount": "0.00001", "currency": "BTC"},
                    "paymentQuoteId": "quote-1",
                    "validUntil": "now",
                    "amount": {"amount": "1.00", "currency": "USD"},
                    "totalFee": {"amount": "0.00001", "currency": "BTC"},
                    "totalAmount": {"amount": "0.00002", "currency": "BTC"},
                },
            )

    cast(Any, wallet).client = Client()

    melt_quote = PostMeltQuoteRequest(unit="sat", request="lnbc1")
    with pytest.raises(Exception, match="Expected currency BTC, got USD"):
        await wallet.get_payment_quote(melt_quote)


@pytest.mark.asyncio
async def test_strike_pay_invoice_http_error_returns_failed():
    wallet = object.__new__(StrikeWallet)
    wallet.unit = Unit.sat
    wallet.endpoint = "https://strike.test"

    class Client:
        async def patch(self, url, timeout=None):
            return _response(400, {"data": {"message": "route error"}})

    cast(Any, wallet).client = Client()
    result = await wallet.pay_invoice(_quote("lnbc1fake"), 1000)
    assert result.result == PaymentResult.FAILED
    assert result.error_message == "route error"


@pytest.mark.asyncio
async def test_strike_get_payment_status_404_returns_unknown():
    wallet = object.__new__(StrikeWallet)
    wallet.unit = Unit.sat
    wallet.endpoint = "https://strike.test"

    class Client:
        async def get(self, url):
            return _response(404, text="missing")

    cast(Any, wallet).client = Client()
    status = await wallet.get_payment_status("missing-id")
    assert status.result == PaymentResult.UNKNOWN
    assert status.error_message == "missing"


def test_strike_fee_int_rejects_unexpected_currency():
    wallet = object.__new__(StrikeWallet)
    wallet.unit = Unit.sat

    quote = SimpleNamespace(totalFee=SimpleNamespace(amount="1", currency="XYZ"))
    with pytest.raises(Exception, match="Unexpected currency"):
        wallet.fee_int(cast(Any, quote), Unit.sat)


@pytest.mark.asyncio
async def test_clnrest_create_invoice_description_hash_unsupported():
    wallet = object.__new__(CLNRestWallet)
    wallet.unit = Unit.sat
    with pytest.raises(Unsupported):
        await wallet.create_invoice(Amount(Unit.sat, 1), description_hash=b"x")


@pytest.mark.asyncio
async def test_clnrest_pay_invoice_mpp_not_supported(monkeypatch):
    wallet = object.__new__(CLNRestWallet)
    wallet.unit = Unit.sat
    wallet.supports_mpp = False

    class Client:
        async def post(self, *args, **kwargs):
            raise AssertionError("client.post should not be called for unsupported MPP")

    cast(Any, wallet).client = Client()
    monkeypatch.setattr(
        "cashu.lightning.clnrest.decode",
        lambda request: SimpleNamespace(amount_msat=2000),
    )

    result = await wallet.pay_invoice(
        _quote("lnbc1fake", amount=1), fee_limit_msat=1000
    )
    assert result.result == PaymentResult.FAILED
    assert result.error_message == "mint does not support MPP"


@pytest.mark.asyncio
async def test_clnrest_get_payment_status_not_found_is_unknown():
    wallet = object.__new__(CLNRestWallet)
    wallet.unit = Unit.sat

    class Client:
        async def post(self, *args, **kwargs):
            return _response(200, {"pays": []})

    cast(Any, wallet).client = Client()
    status = await wallet.get_payment_status("hash")
    assert status.result == PaymentResult.UNKNOWN
    assert status.error_message == "payment not found"


@pytest.mark.asyncio
async def test_clnrest_status_handles_no_data():
    wallet = object.__new__(CLNRestWallet)
    wallet.unit = Unit.sat
    wallet.url = "https://cln.test"

    class Client:
        async def post(self, *args, **kwargs):
            return _response(200, {})

    cast(Any, wallet).client = Client()
    status = await wallet.status()
    assert status.error_message == "no data"
    assert status.balance.amount == 0


@pytest.mark.asyncio
async def test_clnrest_get_payment_quote_uses_mpp_amount(monkeypatch):
    wallet = object.__new__(CLNRestWallet)
    wallet.unit = Unit.sat
    monkeypatch.setattr(
        "cashu.lightning.clnrest.decode",
        lambda request: SimpleNamespace(amount_msat=2000, payment_hash="ph"),
    )
    request = PostMeltQuoteRequest(
        unit="sat",
        request="lnbc1",
        options=PostMeltRequestOptions(mpp=PostMeltRequestOptionMpp(amount=1500)),
    )
    quote = await wallet.get_payment_quote(request)
    assert quote.amount == Amount(Unit.sat, 2)
    assert quote.fee == Amount(Unit.sat, fee_reserve(1500) // 1000)


@pytest.mark.asyncio
async def test_corelightningrest_create_invoice_description_hash_unsupported():
    wallet = object.__new__(CoreLightningRestWallet)
    wallet.unit = Unit.sat
    with pytest.raises(Unsupported):
        await wallet.create_invoice(Amount(Unit.sat, 1), description_hash=b"x")


@pytest.mark.asyncio
async def test_corelightningrest_get_payment_status_not_found_is_unknown():
    wallet = object.__new__(CoreLightningRestWallet)
    wallet.unit = Unit.sat

    class Client:
        async def get(self, *args, **kwargs):
            return _response(200, {"pays": []})

    cast(Any, wallet).client = Client()
    status = await wallet.get_payment_status("hash")
    assert status.result == PaymentResult.UNKNOWN
    assert status.error_message == "payment not found"


@pytest.mark.asyncio
async def test_corelightningrest_status_with_error_payload_returns_failure():
    wallet = object.__new__(CoreLightningRestWallet)
    wallet.unit = Unit.sat
    wallet.url = "https://coreln.test"

    class Client:
        async def get(self, *args, **kwargs):
            return _response(200, {"error": "denied"})

    cast(Any, wallet).client = Client()
    status = await wallet.status()
    assert "Failed to connect" in str(status.error_message)
    assert status.balance.amount == 0


@pytest.mark.asyncio
async def test_lndrest_create_invoice_decodes_r_hash():
    wallet = object.__new__(LndRestWallet)
    wallet.unit = Unit.sat
    r_hash = base64.b64encode(bytes.fromhex("11" * 32)).decode("ascii")

    class Client:
        async def post(self, url=None, json=None):
            return _response(200, {"payment_request": "lnbc1", "r_hash": r_hash})

    cast(Any, wallet).client = Client()
    invoice = await wallet.create_invoice(Amount(Unit.sat, 2))
    assert invoice.ok
    assert invoice.checking_id == "11" * 32


@pytest.mark.asyncio
async def test_lndrest_pay_invoice_returns_failed_on_payment_error(monkeypatch):
    wallet = object.__new__(LndRestWallet)
    wallet.unit = Unit.sat
    wallet.supports_mpp = False

    class Client:
        async def post(self, *args, **kwargs):
            return _response(200, {"payment_error": "denied"})

    cast(Any, wallet).client = Client()
    monkeypatch.setattr(
        "cashu.lightning.lndrest.bolt11.decode",
        lambda request: SimpleNamespace(amount_msat=1000),
    )
    result = await wallet.pay_invoice(
        _quote("lnbc1fake", amount=1), fee_limit_msat=1000
    )
    assert result.result == PaymentResult.FAILED
    assert result.error_message == "denied"


@pytest.mark.asyncio
async def test_lndrest_get_payment_status_reads_stream_result():
    wallet = object.__new__(LndRestWallet)
    wallet.unit = Unit.sat

    class Client:
        def stream(self, method, url, timeout=None):
            return _StreamResponse(
                [
                    json.dumps(
                        {
                            "result": {
                                "status": "SUCCEEDED",
                                "fee_msat": 7,
                                "payment_preimage": "abc",
                            }
                        }
                    )
                ]
            )

    cast(Any, wallet).client = Client()
    status = await wallet.get_payment_status("11" * 32)
    assert status.result == PaymentResult.SETTLED
    assert status.fee == Amount(Unit.msat, 7)
    assert status.preimage == "abc"


@pytest.mark.asyncio
async def test_lndrest_status_connect_error_returns_unknown():
    wallet = object.__new__(LndRestWallet)
    wallet.unit = Unit.sat
    wallet.endpoint = "https://lnd.test"

    class Client:
        async def get(self, *args, **kwargs):
            raise httpx.ConnectError(
                "boom", request=httpx.Request("GET", "https://lnd.test")
            )

    cast(Any, wallet).client = Client()
    status = await wallet.status()
    assert status.balance.amount == 0
    assert "Unable to connect" in str(status.error_message)


@pytest.mark.asyncio
async def test_lndrest_get_invoice_status_invalid_json_is_unknown():
    wallet = object.__new__(LndRestWallet)
    wallet.unit = Unit.sat

    class Client:
        async def get(self, *args, **kwargs):
            return _response(200, text="not-json")

    cast(Any, wallet).client = Client()
    status = await wallet.get_invoice_status("check")
    assert status.result == PaymentResult.UNKNOWN


@pytest.mark.asyncio
async def test_lndrest_get_payment_quote_uses_mpp_amount(monkeypatch):
    wallet = object.__new__(LndRestWallet)
    wallet.unit = Unit.sat
    monkeypatch.setattr(
        "cashu.lightning.lndrest.decode",
        lambda request: SimpleNamespace(amount_msat=2000, payment_hash="ph"),
    )
    request = PostMeltQuoteRequest(
        unit="sat",
        request="lnbc1",
        options=PostMeltRequestOptions(mpp=PostMeltRequestOptionMpp(amount=1500)),
    )
    quote = await wallet.get_payment_quote(request)
    assert quote.amount == Amount(Unit.sat, 2)
    assert quote.fee == Amount(Unit.sat, fee_reserve(1500) // 1000)


@pytest.mark.asyncio
async def test_blink_get_payment_status_send_receive_pair_is_failed(monkeypatch):
    wallet = object.__new__(BlinkWallet)
    wallet.unit = Unit.sat
    wallet.wallet_ids = {Unit.sat: "wbtc"}
    wallet.endpoint = "https://blink.test"

    class Client:
        async def post(self, *args, **kwargs):
            return _response(
                200,
                {
                    "data": {
                        "me": {
                            "defaultAccount": {
                                "walletById": {
                                    "transactionsByPaymentHash": [
                                        {"direction": "SEND", "status": "FAILURE"},
                                        {"direction": "RECEIVE", "status": "FAILURE"},
                                    ]
                                }
                            }
                        }
                    }
                },
            )

    cast(Any, wallet).client = Client()
    invoice = "lnbc10u1pjap7phpp50s9lzr3477j0tvacpfy2ucrs4q0q6cvn232ex7nt2zqxxxj8gxrsdpv2phhwetjv4jzqcneypqyc6t8dp6xu6twva2xjuzzda6qcqzzsxqrrsssp575z0n39w2j7zgnpqtdlrgz9rycner4eptjm3lz363dzylnrm3h4s9qyyssqfz8jglcshnlcf0zkw4qu8fyr564lg59x5al724kms3h6gpuhx9xrfv27tgx3l3u3cyf63r52u0xmac6max8mdupghfzh84t4hfsvrfsqwnuszf"
    status = await wallet.get_payment_status(invoice)
    assert status.result == PaymentResult.FAILED
    assert status.error_message == "Payment failed"


@pytest.mark.asyncio
async def test_blink_get_sats_per_usd_raises_on_missing_conversion():
    wallet = object.__new__(BlinkWallet)
    wallet.unit = Unit.usd
    wallet.endpoint = "https://blink.test"

    class Client:
        async def post(self, *args, **kwargs):
            return _response(200, {"data": {"currencyConversionEstimation": None}})

    cast(Any, wallet).client = Client()
    with pytest.raises(Exception, match="Currency conversion service unavailable"):
        await wallet._get_sats_per_usd()
