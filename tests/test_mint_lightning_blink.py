import pytest
import respx
from httpx import Response

from cashu.core.base import Amount, MeltQuote, Unit
from cashu.core.settings import settings
from cashu.lightning.blink import BlinkWallet  # noqa: F401

settings.mint_blink_key = "123"
blink = BlinkWallet()
payment_request = (
    "lnbc10u1pjap7phpp50s9lzr3477j0tvacpfy2ucrs4q0q6cvn232ex7nt2zqxxxj8gxrsdpv2phhwetjv4jzqcneypqyc6t8dp6xu6twva2xjuzzda6qcqzzsxqrrsss"
    "p575z0n39w2j7zgnpqtdlrgz9rycner4eptjm3lz363dzylnrm3h4s9qyyssqfz8jglcshnlcf0zkw4qu8fyr564lg59x5al724kms3h6gpuhx9xrfv27tgx3l3u3cyf6"
    "3r52u0xmac6max8mdupghfzh84t4hfsvrfsqwnuszf"
)


@respx.mock
@pytest.mark.asyncio
async def test_blink_status():
    mock_response = {
        "data": {
            "me": {
                "defaultAccount": {
                    "wallets": [
                        {"walletCurrency": "USD", "id": "123", "balance": 32142},
                        {
                            "walletCurrency": "BTC",
                            "id": "456",
                            "balance": 100000,
                        },
                    ]
                }
            }
        }
    }
    respx.post(blink.endpoint).mock(return_value=Response(200, json=mock_response))
    status = await blink.status()
    assert status.balance == 100000


@respx.mock
@pytest.mark.asyncio
async def test_blink_create_invoice():
    mock_response = {
        "data": {
            "lnInvoiceCreateOnBehalfOfRecipient": {
                "invoice": {"paymentRequest": payment_request}
            }
        }
    }
    respx.post(blink.endpoint).mock(return_value=Response(200, json=mock_response))
    invoice = await blink.create_invoice(Amount(Unit.sat, 1000))
    assert invoice.checking_id == invoice.payment_request
    assert invoice.ok


@respx.mock
@pytest.mark.asyncio
async def test_blink_pay_invoice():
    mock_response = {
        "data": {
            "lnInvoicePaymentSend": {
                "status": "SUCCESS",
                "transaction": {"settlementFee": 10},
            }
        }
    }
    respx.post(blink.endpoint).mock(return_value=Response(200, json=mock_response))
    quote = MeltQuote(
        request=payment_request,
        quote="asd",
        method="bolt11",
        checking_id=payment_request,
        unit="sat",
        amount=100,
        fee_reserve=12,
        paid=False,
    )
    payment = await blink.pay_invoice(quote, 1000)
    assert payment.ok
    assert payment.fee
    assert payment.fee.amount == 10
    assert payment.error_message is None
    assert payment.checking_id == payment_request


@respx.mock
@pytest.mark.asyncio
async def test_blink_get_invoice_status():
    mock_response = {
        "data": {
            "lnInvoicePaymentStatus": {
                "status": "PAID",
                "errors": [],
            }
        }
    }
    respx.post(blink.endpoint).mock(return_value=Response(200, json=mock_response))
    status = await blink.get_invoice_status("123")
    assert status.paid


@respx.mock
@pytest.mark.asyncio
async def test_blink_get_payment_status():
    mock_response = {
        "data": {
            "me": {
                "defaultAccount": {
                    "walletById": {
                        "transactionsByPaymentHash": [
                            {"status": "SUCCESS", "settlementFee": 10}
                        ]
                    }
                }
            }
        }
    }
    respx.post(blink.endpoint).mock(return_value=Response(200, json=mock_response))
    status = await blink.get_payment_status(payment_request)
    assert status.paid
    assert status.fee
    assert status.fee.amount == 10
    assert status.preimage is None


@respx.mock
@pytest.mark.asyncio
async def test_blink_get_payment_quote():
    # response says 1 sat fees but invoice * 0.5% is 5 sat so we expect 5 sat
    mock_response = {"data": {"lnInvoiceFeeProbe": {"amount": 1}}}
    respx.post(blink.endpoint).mock(return_value=Response(200, json=mock_response))
    quote = await blink.get_payment_quote(payment_request)
    assert quote.checking_id == payment_request
    assert quote.amount == Amount(Unit.msat, 1000000)  # msat
    assert quote.fee == Amount(Unit.msat, 5000)  # msat

    # response says 10 sat fees but invoice * 0.5% is 5 sat so we expect 10 sat
    mock_response = {"data": {"lnInvoiceFeeProbe": {"amount": 10}}}
    respx.post(blink.endpoint).mock(return_value=Response(200, json=mock_response))
    quote = await blink.get_payment_quote(payment_request)
    assert quote.checking_id == payment_request
    assert quote.amount == Amount(Unit.msat, 1000000)  # msat
    assert quote.fee == Amount(Unit.msat, 10000)  # msat
