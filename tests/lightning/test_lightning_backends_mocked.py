import base64
import json
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

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
from cashu.lightning.clnrest import (
    CLN_PAYMENT_STATUS_COMPLETE,
    CLN_PAYMENT_STATUS_FAILED,
    CLN_PAYMENT_STATUS_PENDING,
    CLNRestWallet,
)
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
async def test_clnrest_pay_invoice_uses_xpay(monkeypatch):
    wallet = object.__new__(CLNRestWallet)
    wallet.unit = Unit.sat
    wallet.supports_mpp = True
    request_data = None

    class Client:
        async def post(self, url, data=None, timeout=None):
            nonlocal request_data
            assert url == "/v1/xpay"
            assert timeout is None
            request_data = data
            return _response(
                200,
                {
                    "payment_preimage": "preimage",
                    "failed_parts": 0,
                    "successful_parts": 1,
                    "amount_msat": 1000,
                    "amount_sent_msat": 1100,
                },
            )

    cast(Any, wallet).client = Client()
    monkeypatch.setattr(
        "cashu.lightning.clnrest.decode",
        lambda request: SimpleNamespace(amount_msat=1000, payment_hash="hash"),
    )

    result = await wallet.pay_invoice(_quote("lnbc1fake", amount=1), fee_limit_msat=100)

    assert request_data == {"invstring": "lnbc1fake", "maxfee": 100}
    assert result.result == PaymentResult.SETTLED
    assert result.checking_id == "hash"
    assert result.fee == Amount(Unit.msat, 100)
    assert result.preimage == "preimage"


@pytest.mark.asyncio
async def test_clnrest_xpay_uses_partial_msat_for_mpp(monkeypatch):
    wallet = object.__new__(CLNRestWallet)
    wallet.unit = Unit.sat
    wallet.supports_mpp = True
    request_data = None

    class Client:
        async def post(self, url, data=None, timeout=None):
            nonlocal request_data
            request_data = data
            return _response(
                200,
                {
                    "payment_preimage": "preimage",
                    "failed_parts": 0,
                    "successful_parts": 1,
                    "amount_msat": 1000,
                    "amount_sent_msat": 1000,
                },
            )

    cast(Any, wallet).client = Client()
    monkeypatch.setattr(
        "cashu.lightning.clnrest.decode",
        lambda request: SimpleNamespace(amount_msat=2000, payment_hash="hash"),
    )

    result = await wallet.pay_invoice(_quote("lnbc1fake", amount=1), fee_limit_msat=100)

    assert request_data == {
        "invstring": "lnbc1fake",
        "maxfee": 100,
        "partial_msat": 1000,
    }
    assert result.result == PaymentResult.SETTLED


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
@pytest.mark.parametrize(
    "pays, expected_result, expected_fee, expected_preimage",
    [
        (
            [
                {"status": CLN_PAYMENT_STATUS_FAILED},
                {"status": CLN_PAYMENT_STATUS_PENDING},
            ],
            PaymentResult.PENDING,
            None,
            None,
        ),
        (
            [
                {"status": CLN_PAYMENT_STATUS_FAILED},
                {
                    "status": CLN_PAYMENT_STATUS_COMPLETE,
                    "amount_sent_msat": 1100,
                    "amount_msat": 1000,
                    "preimage": "preimage",
                },
            ],
            PaymentResult.SETTLED,
            100,
            "preimage",
        ),
        (
            [
                {
                    "status": CLN_PAYMENT_STATUS_COMPLETE,
                    "amount_sent_msat": 1100,
                    "amount_msat": 1000,
                    "preimage": "preimage",
                },
                {"status": CLN_PAYMENT_STATUS_PENDING},
            ],
            PaymentResult.PENDING,
            None,
            None,
        ),
        (
            [
                {"status": CLN_PAYMENT_STATUS_FAILED},
                {"status": CLN_PAYMENT_STATUS_FAILED},
            ],
            PaymentResult.FAILED,
            None,
            None,
        ),
        (
            [
                {"status": CLN_PAYMENT_STATUS_FAILED},
                {"status": "unexpected"},
            ],
            PaymentResult.UNKNOWN,
            None,
            None,
        ),
    ],
)
async def test_cln_get_payment_status_aggregates_all_pay_attempts(
    pays, expected_result, expected_fee, expected_preimage
):
    wallet = object.__new__(CLNRestWallet)
    wallet.unit = Unit.sat

    class Client:
        async def get(self, *args, **kwargs):
            return _response(200, {"pays": pays})

        async def post(self, *args, **kwargs):
            return _response(200, {"pays": pays})

    cast(Any, wallet).client = Client()
    status = await wallet.get_payment_status("hash")

    assert status.result == expected_result
    assert (status.fee.amount if status.fee else None) == expected_fee
    assert status.preimage == expected_preimage


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
async def test_lndrest_pay_invoice_settled_reads_stream_result(monkeypatch):
    wallet = object.__new__(LndRestWallet)
    wallet.unit = Unit.sat
    wallet.supports_mpp = False

    lines = [
        json.dumps(
            {
                "result": {
                    "status": "SUCCEEDED",
                    "payment_hash": "11" * 32,
                    "fee_msat": "7",
                    "payment_preimage": "ab" * 32,
                }
            }
        )
    ]

    class Client:
        def stream(self, method, url, json=None, timeout=None):
            assert method == "POST"
            assert url == "/v2/router/send"
            assert json is not None
            assert json["payment_request"] == "lnbc1fake"
            assert json["fee_limit_msat"] == "1000"
            return _StreamResponse(lines)

    cast(Any, wallet).client = Client()
    monkeypatch.setattr(
        "cashu.lightning.lndrest.bolt11.decode",
        lambda request: SimpleNamespace(amount_msat=1000),
    )
    result = await wallet.pay_invoice(
        _quote("lnbc1fake", amount=1), fee_limit_msat=1000
    )
    assert result.result == PaymentResult.SETTLED
    assert result.checking_id == "11" * 32
    assert result.fee == Amount(Unit.msat, 7)
    assert result.preimage == "ab" * 32


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled, expected", [(True, True), (False, False)])
async def test_lndrest_pay_invoice_sends_allow_self_payment(
    monkeypatch, enabled, expected
):
    wallet = object.__new__(LndRestWallet)
    wallet.unit = Unit.sat
    wallet.supports_mpp = False

    captured: dict[str, Any] = {}

    lines = [
        json.dumps(
            {
                "result": {
                    "status": "SUCCEEDED",
                    "payment_hash": "11" * 32,
                    "fee_msat": "7",
                    "payment_preimage": "ab" * 32,
                }
            }
        )
    ]

    class Client:
        def stream(self, method, url, json=None, timeout=None):
            captured["json"] = json
            return _StreamResponse(lines)

    cast(Any, wallet).client = Client()
    monkeypatch.setattr(
        "cashu.lightning.lndrest.bolt11.decode",
        lambda request: SimpleNamespace(amount_msat=1000),
    )
    monkeypatch.setattr(
        "cashu.lightning.lndrest.settings.mint_lnd_allow_self_payment",
        enabled,
    )
    result = await wallet.pay_invoice(
        _quote("lnbc1fake", amount=1), fee_limit_msat=1000
    )
    assert result.result == PaymentResult.SETTLED
    assert captured["json"]["allow_self_payment"] is expected


@pytest.mark.asyncio
async def test_lndrest_pay_invoice_returns_failed_on_payment_failure(monkeypatch):
    wallet = object.__new__(LndRestWallet)
    wallet.unit = Unit.sat
    wallet.supports_mpp = False

    lines = [
        json.dumps(
            {
                "result": {
                    "status": "FAILED",
                    "failure_reason": "FAILURE_REASON_NO_ROUTE",
                }
            }
        )
    ]

    class Client:
        def stream(self, method, url, json=None, timeout=None):
            return _StreamResponse(lines)

    cast(Any, wallet).client = Client()
    monkeypatch.setattr(
        "cashu.lightning.lndrest.bolt11.decode",
        lambda request: SimpleNamespace(amount_msat=1000),
    )
    result = await wallet.pay_invoice(
        _quote("lnbc1fake", amount=1), fee_limit_msat=1000
    )
    assert result.result == PaymentResult.FAILED
    assert result.error_message == "FAILURE_REASON_NO_ROUTE"


@pytest.mark.asyncio
async def test_lndrest_pay_invoice_returns_failed_on_rest_proxy_error(monkeypatch):
    wallet = object.__new__(LndRestWallet)
    wallet.unit = Unit.sat
    wallet.supports_mpp = False

    lines = [json.dumps({"code": 5, "message": "Not Found", "details": []})]

    class Client:
        def stream(self, method, url, json=None, timeout=None):
            return _StreamResponse(lines)

    cast(Any, wallet).client = Client()
    monkeypatch.setattr(
        "cashu.lightning.lndrest.bolt11.decode",
        lambda request: SimpleNamespace(amount_msat=1000),
    )
    result = await wallet.pay_invoice(
        _quote("lnbc1fake", amount=1), fee_limit_msat=1000
    )
    assert result.result == PaymentResult.FAILED
    assert result.error_message == "Not Found"


@pytest.mark.asyncio
async def test_lndrest_pay_invoice_unknown_on_stream_error(monkeypatch):
    # a streaming error envelope (e.g. payment already in flight) arrives after
    # the request was accepted, so the payment may be live: must be UNKNOWN, not
    # FAILED, so the ledger re-checks the real state with TrackPaymentV2.
    wallet = object.__new__(LndRestWallet)
    wallet.unit = Unit.sat
    wallet.supports_mpp = False

    lines = [json.dumps({"error": {"code": 6, "message": "invoice is already paid"}})]

    class Client:
        def stream(self, method, url, json=None, timeout=None):
            return _StreamResponse(lines)

    cast(Any, wallet).client = Client()
    monkeypatch.setattr(
        "cashu.lightning.lndrest.bolt11.decode",
        lambda request: SimpleNamespace(amount_msat=1000),
    )
    result = await wallet.pay_invoice(
        _quote("lnbc1fake", amount=1), fee_limit_msat=1000
    )
    assert result.result == PaymentResult.UNKNOWN
    assert result.error_message == "invoice is already paid"


@pytest.mark.asyncio
async def test_lndrest_pay_invoice_unknown_on_empty_stream(monkeypatch):
    wallet = object.__new__(LndRestWallet)
    wallet.unit = Unit.sat
    wallet.supports_mpp = False

    class Client:
        def stream(self, method, url, json=None, timeout=None):
            return _StreamResponse([])

    cast(Any, wallet).client = Client()
    monkeypatch.setattr(
        "cashu.lightning.lndrest.bolt11.decode",
        lambda request: SimpleNamespace(amount_msat=1000),
    )
    result = await wallet.pay_invoice(
        _quote("lnbc1fake", amount=1), fee_limit_msat=1000
    )
    assert result.result == PaymentResult.UNKNOWN


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
@pytest.mark.parametrize("operation", ["pay", "status"])
@pytest.mark.parametrize("unit", [Unit.sat, Unit.msat])
async def test_spark_returns_payment_fees_in_wallet_unit(operation, unit):
    import breez_sdk_spark as breez

    from cashu.lightning.sparkl2 import SparkL2Wallet

    wallet = SparkL2Wallet(unit=unit)
    sdk = AsyncMock()
    wallet.sdk = sdk
    # UniFFI decodes u128 values to Python integers despite the str annotation.
    payment = breez.Payment(
        id="payment-id",
        payment_type=breez.PaymentType.SEND,
        status=breez.PaymentStatus.COMPLETED,
        amount=1,
        fees=7,
        timestamp=0,
        method=breez.PaymentMethod.LIGHTNING,
        details=None,
        conversion_details=None,
    )
    sdk.get_payment.return_value = SimpleNamespace(payment=payment)
    sdk.send_payment.return_value = SimpleNamespace(payment=payment)
    sdk.prepare_send_payment.return_value = SimpleNamespace(
        payment_method=SimpleNamespace(
            is_bolt11_invoice=lambda: True,
            lightning_fee_sats=7,
            spark_transfer_fee_sats=0,
        )
    )

    if operation == "pay":
        result = await wallet.pay_invoice(_quote("lnbcrt1test"), fee_limit_msat=7000)
    else:
        result = await wallet.get_payment_status(payment.id)

    assert result.settled
    assert result.fee == Amount(Unit.sat, 7).to(unit)
    assert isinstance(result.fee.amount, int)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["quote", "pay"])
async def test_spark_wraps_invoice_in_sdk_payment_request(operation):
    from breez_sdk_spark import PaymentRequest

    from cashu.lightning.sparkl2 import SparkL2Wallet

    wallet = SparkL2Wallet(unit=Unit.sat)
    sdk = AsyncMock()
    sdk.prepare_send_payment.side_effect = RuntimeError("stop after preparation")
    wallet.sdk = sdk
    invoice = "lnbcrt1test"

    if operation == "pay":
        result = await wallet.pay_invoice(_quote(invoice), fee_limit_msat=1000)
        assert result.failed
    else:
        with pytest.raises(Exception, match="stop after preparation"):
            await wallet.get_payment_quote(
                PostMeltQuoteRequest(unit="sat", request=invoice)
            )

    sdk.prepare_send_payment.assert_awaited_once()
    request = sdk.prepare_send_payment.call_args.args[0]
    assert isinstance(request.payment_request, PaymentRequest.INPUT)
    assert request.payment_request.input == invoice
    sdk.send_payment.assert_not_awaited()


def _spark_lightning_payment(status, preimage=None, payment_hash="a" * 64):
    import breez_sdk_spark as breez

    return breez.Payment(
        id="sdk-payment-uuid",
        payment_type=breez.PaymentType.SEND,
        status=status,
        amount=64,
        fees=7,
        timestamp=1,
        method=breez.PaymentMethod.LIGHTNING,
        conversion_details=None,
        details=breez.PaymentDetails.LIGHTNING(
            description=None,
            invoice="lnbcrt1test",
            destination_pubkey="",
            htlc_details=breez.SparkHtlcDetails(
                payment_hash=payment_hash,
                preimage=preimage,
                expiry_time=0,
                status=(
                    breez.SparkHtlcStatus.PREIMAGE_SHARED
                    if preimage
                    else breez.SparkHtlcStatus.WAITING_FOR_PREIMAGE
                ),
            ),
            lnurl_pay_info=None,
            lnurl_withdraw_info=None,
            lnurl_receive_metadata=None,
            conversion_info=None,
        ),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["pay", "status"])
async def test_spark_completed_transfer_waits_for_lightning_preimage(operation):
    import breez_sdk_spark as breez

    from cashu.lightning.sparkl2 import SparkL2Wallet

    wallet = SparkL2Wallet(Unit.sat)
    sdk = AsyncMock()
    wallet.sdk = sdk
    payment = _spark_lightning_payment(breez.PaymentStatus.COMPLETED)
    sdk.send_payment.return_value = SimpleNamespace(payment=payment)
    sdk.get_payment.return_value = SimpleNamespace(payment=payment)
    sdk.prepare_send_payment.return_value = SimpleNamespace(
        payment_method=SimpleNamespace(
            is_bolt11_invoice=lambda: True,
            lightning_fee_sats=7,
            spark_transfer_fee_sats=0,
        )
    )

    if operation == "pay":
        result = await wallet.pay_invoice(_quote("lnbcrt1test"), 7000)
        assert result.checking_id == payment.id
    else:
        result = await wallet.get_payment_status(payment.id)
    assert result.pending
    assert result.preimage is None

    payment.details.htlc_details.preimage = "b" * 64
    settled = await wallet.get_payment_status(payment.id)
    assert settled.settled
    assert settled.preimage == "b" * 64
    assert settled.fee == Amount(Unit.sat, 7)


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["PENDING", "FAILED", "COMPLETED"])
async def test_spark_checks_payment_by_quote_hash_after_reconnecting(state):
    import breez_sdk_spark as breez

    from cashu.lightning.sparkl2 import SparkL2Wallet

    # A new backend instance has no in-memory mapping from BOLT11 hash to UUID.
    wallet = SparkL2Wallet(Unit.sat)
    sdk = AsyncMock()
    wallet.sdk = sdk
    preimage = "b" * 64 if state == "COMPLETED" else None
    payment = _spark_lightning_payment(
        getattr(breez.PaymentStatus, state), preimage=preimage
    )
    unrelated = _spark_lightning_payment(
        breez.PaymentStatus.COMPLETED, preimage="c" * 64, payment_hash="d" * 64
    )
    sdk.list_payments.return_value = SimpleNamespace(payments=[unrelated, payment])

    status = await wallet.get_payment_status("a" * 64)

    assert (
        status.result
        == {
            "PENDING": PaymentResult.PENDING,
            "FAILED": PaymentResult.FAILED,
            "COMPLETED": PaymentResult.SETTLED,
        }[state]
    )
    assert status.preimage == preimage
    request = sdk.list_payments.call_args.args[0]
    assert request.type_filter == [breez.PaymentType.SEND]
    assert request.sort_ascending is False
    sdk.get_payment.assert_not_awaited()


@pytest.mark.asyncio
async def test_spark_pay_invoice_rejects_non_bolt11():
    from cashu.lightning.sparkl2 import SparkL2Wallet

    wallet = object.__new__(SparkL2Wallet)
    wallet.unit = Unit.sat

    async def mock_ensure_sdk():
        pass

    cast(Any, wallet)._ensure_sdk = mock_ensure_sdk

    class MockMethod:
        def is_bolt11_invoice(self):
            return False

    class MockPrepareResponse:
        payment_method = MockMethod()

    class MockSDK:
        async def prepare_send_payment(self, req):
            return MockPrepareResponse()

    cast(Any, wallet).sdk = MockSDK()

    res = await wallet.pay_invoice(_quote("non-bolt11"), 1000)
    assert res.result == PaymentResult.FAILED
    assert "Only BOLT11 payments are supported" in str(res.error_message)


@pytest.mark.asyncio
async def test_spark_pay_invoice_prepare_error_is_failed(monkeypatch):
    from cashu.lightning import sparkl2

    wallet = object.__new__(sparkl2.SparkL2Wallet)
    wallet.unit = Unit.sat

    async def mock_ensure_sdk():
        pass

    cast(Any, wallet)._ensure_sdk = mock_ensure_sdk
    monkeypatch.setattr(
        sparkl2.breez_sdk_spark,
        "PrepareSendPaymentRequest",
        lambda **kwargs: SimpleNamespace(**kwargs),
    )

    class MockSDK:
        async def prepare_send_payment(self, req):
            raise RuntimeError("prepare failed")

    cast(Any, wallet).sdk = MockSDK()

    res = await wallet.pay_invoice(_quote("lnbc1fake"), 1000)
    assert res.result == PaymentResult.FAILED
    assert "Failed to prepare payment" in str(res.error_message)


@pytest.mark.asyncio
async def test_spark_pay_invoice_send_error_is_unknown(monkeypatch):
    from cashu.lightning import sparkl2

    wallet = object.__new__(sparkl2.SparkL2Wallet)
    wallet.unit = Unit.sat
    wallet.prefer_spark_over_lightning = True

    async def mock_ensure_sdk():
        pass

    cast(Any, wallet)._ensure_sdk = mock_ensure_sdk
    send_request = None

    def mock_send_payment_request(**kwargs):
        nonlocal send_request
        send_request = SimpleNamespace(**kwargs)
        return send_request

    monkeypatch.setattr(
        sparkl2.breez_sdk_spark,
        "PrepareSendPaymentRequest",
        lambda **kwargs: SimpleNamespace(**kwargs),
    )
    monkeypatch.setattr(
        sparkl2.breez_sdk_spark,
        "SendPaymentRequest",
        mock_send_payment_request,
    )

    class MockMethod:
        lightning_fee_sats = 0
        spark_transfer_fee_sats = 0

        def is_bolt11_invoice(self):
            return True

    class MockPrepareResponse:
        payment_method = MockMethod()

    class MockSDK:
        async def prepare_send_payment(self, req):
            return MockPrepareResponse()

        async def send_payment(self, req):
            raise RuntimeError("send failed")

    cast(Any, wallet).sdk = MockSDK()

    res = await wallet.pay_invoice(_quote("lnbc1fake"), 1000)
    assert res.result == PaymentResult.UNKNOWN
    assert res.checking_id == "checking-1"
    assert "Payment failed or unknown" in str(res.error_message)
    assert send_request
    assert send_request.options.prefer_spark is True
    assert (
        send_request.options.completion_timeout_secs
        == sparkl2.SPARK_SEND_PAYMENT_COMPLETION_TIMEOUT_SECONDS
    )


@pytest.mark.asyncio
async def test_spark_get_invoice_status_not_found_is_unknown(monkeypatch):
    from cashu.lightning import sparkl2

    wallet = object.__new__(sparkl2.SparkL2Wallet)
    wallet.unit = Unit.sat

    async def mock_ensure_sdk():
        pass

    cast(Any, wallet)._ensure_sdk = mock_ensure_sdk
    monkeypatch.setattr(
        sparkl2.breez_sdk_spark,
        "ListPaymentsRequest",
        lambda **kwargs: SimpleNamespace(**kwargs),
    )

    class MockSDK:
        async def list_payments(self, req):
            return SimpleNamespace(payments=[])

    cast(Any, wallet).sdk = MockSDK()

    status = await wallet.get_invoice_status("missing-hash")
    assert status.result == PaymentResult.UNKNOWN
    assert status.error_message == "Invoice not found"


@pytest.mark.asyncio
async def test_spark_get_payment_quote_rejects_non_bolt11():
    from cashu.lightning.sparkl2 import SparkL2Wallet

    wallet = object.__new__(SparkL2Wallet)
    wallet.unit = Unit.sat

    async def mock_ensure_sdk():
        pass

    cast(Any, wallet)._ensure_sdk = mock_ensure_sdk

    class MockMethod:
        def is_bolt11_invoice(self):
            return False

    class MockPrepareResponse:
        payment_method = MockMethod()

    class MockSDK:
        async def prepare_send_payment(self, req):
            return MockPrepareResponse()

    cast(Any, wallet).sdk = MockSDK()

    melt_quote = PostMeltQuoteRequest(unit="sat", request="non-bolt11")
    with pytest.raises(Exception, match="Only BOLT11 payments are supported"):
        await wallet.get_payment_quote(melt_quote)
