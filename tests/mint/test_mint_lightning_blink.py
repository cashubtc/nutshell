import pytest
import respx
from httpx import Response

from cashu.core.base import Amount, MeltQuote, MeltQuoteState, Unit
from cashu.core.models import PostMeltQuoteRequest
from cashu.core.settings import settings
from cashu.lightning.blink import MINIMUM_FEE_MSAT, BlinkWallet  # type: ignore

settings.mint_blink_key = "123"
blink = BlinkWallet(unit=Unit.sat)
blink_usd = BlinkWallet(unit=Unit.usd)
payment_request = (
    "lnbc10u1pjap7phpp50s9lzr3477j0tvacpfy2ucrs4q0q6cvn232ex7nt2zqxxxj8gxrsdpv2phhwetjv4jzqcneypqyc6t8dp6xu6twva2xjuzzda6qcqzzsxqrrsss"
    "p575z0n39w2j7zgnpqtdlrgz9rycner4eptjm3lz363dzylnrm3h4s9qyyssqfz8jglcshnlcf0zkw4qu8fyr564lg59x5al724kms3h6gpuhx9xrfv27tgx3l3u3cyf6"
    "3r52u0xmac6max8mdupghfzh84t4hfsvrfsqwnuszf"
)  # 1000 sat

payment_request_10k = (
    "lnbc100u1pjaxuyzpp5wn37d3mx38haqs7nd5he4j7pq4r806e6s83jdksxrd77pnanm3zqdpv2phhwetjv4jzqcneypqyc6t8dp6xu6twva2xjuzzda6qcqzzsxqrrss"
    "sp5ayy0uuhwgy8hwphvy7ptzpg2dfn8vt3vlgsk53rsvj76jvafhujs9qyyssqc8aj03s5au3tgu6pj0rm0ws4a838s8ffe3y3qkj77esh7qmgsz7qlvdlzgj6dvx7tx7"
    "zn6k352z85rvdqvlszrevvzakp96a4pvyn2cpgaaks6"
)

payment_request_4973 = (
    "lnbc49730n1pjaxuxnpp5zw0ry2w2heyuv7wk4r6z38vvgnaudfst0hl2p5xnv0mjkxtavg2qdpv2phhwetjv4jzqcneypqyc6t8dp6xu6twva2xjuzzda6qcqzzsxqrr"
    "sssp5x8tv2ka0m95hgek25kauw540m0dx727stqqr07l8h37v5283sn5q9qyyssqeevcs6vxcdnerk5w5mwfmntsf8nze7nxrf97dywmga7v0742vhmxtjrulgu3kah4f"
    "2r6025j974jpjg4mkqhv2gdls5k7e5cvwdf4wcp3ytsvx"
)
payment_request_1 = (
    "lnbc10n1pjaxujrpp5sqehn6h5p8xpa0c0lvj5vy3a537gxfk5e7h2ate2alfw3y5cm6xqdpv2phhwetjv4jzqcneypqyc6t8dp6xu6twva2xjuzzda6qcqzzsxqrrsss"
    "p5fkxsvyl0r32mvnhv9cws4rp986v0wjl2lp93zzl8jejnuwzvpynq9qyyssqqmsnatsz87qrgls98c97dfa6l2z3rzg2x6kxmrvpz886rwjylmd56y3qxzfulrq03kkh"
    "hwk6r32wes6pjt2zykhnsjn30c6uhuk0wugp3x74al"
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
                "transaction": {
                    "settlementFee": 10,
                    "settlementVia": {
                        "preImage": "123",
                    },
                },
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
        state=MeltQuoteState.unpaid,
    )
    payment = await blink.pay_invoice(quote, 1000)
    assert payment.settled
    assert payment.fee
    assert payment.fee.amount == 10
    assert payment.error_message is None
    assert payment.checking_id == payment_request


@respx.mock
@pytest.mark.asyncio
async def test_blink_pay_invoice_failure():
    mock_response = {
        "data": {
            "lnInvoicePaymentSend": {
                "status": "FAILURE",
                "errors": [
                    {"message": "This is the error", "codee": "ROUTE_FINDING_ERROR"},
                ],
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
        state=MeltQuoteState.unpaid,
    )
    payment = await blink.pay_invoice(quote, 1000)
    assert not payment.settled
    assert payment.fee is None
    assert payment.error_message
    assert "This is the error" in payment.error_message
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
    assert status.settled


@respx.mock
@pytest.mark.asyncio
async def test_blink_get_payment_status():
    mock_response = {
        "data": {
            "me": {
                "defaultAccount": {
                    "walletById": {
                        "transactionsByPaymentHash": [
                            {
                                "status": "SUCCESS",
                                "settlementFee": 10,
                                "direction": "SEND",
                                "settlementVia": {
                                    "preImage": "123",
                                },
                            }
                        ]
                    }
                }
            }
        }
    }
    respx.post(blink.endpoint).mock(return_value=Response(200, json=mock_response))
    status = await blink.get_payment_status(payment_request)
    assert status.settled
    assert status.fee
    assert status.fee.amount == 10
    assert status.preimage == "123"


@respx.mock
@pytest.mark.asyncio
async def test_blink_get_payment_quote():
    # response says 1 sat fees but invoice (1000 sat) * 0.5% is 5 sat so we expect MINIMUM_FEE_MSAT/1000 sat
    mock_response = {"data": {"lnInvoiceFeeProbe": {"amount": 1}}}
    respx.post(blink.endpoint).mock(return_value=Response(200, json=mock_response))
    melt_quote_request = PostMeltQuoteRequest(
        unit=Unit.sat.name, request=payment_request
    )
    quote = await blink.get_payment_quote(melt_quote_request)
    assert quote.checking_id == payment_request
    assert quote.amount == Amount(Unit.sat, 1000)  # sat
    assert quote.fee == Amount(Unit.sat, MINIMUM_FEE_MSAT // 1000)  # msat

    # response says 10 sat fees but invoice (1000 sat) * 0.5% is 5 sat so we expect 10 sat
    mock_response = {"data": {"lnInvoiceFeeProbe": {"amount": 10}}}
    respx.post(blink.endpoint).mock(return_value=Response(200, json=mock_response))
    melt_quote_request = PostMeltQuoteRequest(
        unit=Unit.sat.name, request=payment_request
    )
    quote = await blink.get_payment_quote(melt_quote_request)
    assert quote.checking_id == payment_request
    assert quote.amount == Amount(Unit.sat, 1000)  # sat
    assert quote.fee == Amount(Unit.sat, 10)  # sat

    # response says 10 sat fees but invoice (4973 sat) * 0.5% is 24.865 sat so we expect 25 sat
    mock_response = {"data": {"lnInvoiceFeeProbe": {"amount": 10}}}
    respx.post(blink.endpoint).mock(return_value=Response(200, json=mock_response))
    melt_quote_request_4973 = PostMeltQuoteRequest(
        unit=Unit.sat.name, request=payment_request_4973
    )
    quote = await blink.get_payment_quote(melt_quote_request_4973)
    assert quote.checking_id == payment_request_4973
    assert quote.amount == Amount(Unit.sat, 4973)  # sat
    assert quote.fee == Amount(Unit.sat, 25)  # sat

    # response says 0 sat fees but invoice (1 sat) * 0.5% is 0.005 sat so we expect MINIMUM_FEE_MSAT/1000 sat
    mock_response = {"data": {"lnInvoiceFeeProbe": {"amount": 0}}}
    respx.post(blink.endpoint).mock(return_value=Response(200, json=mock_response))
    melt_quote_request_1 = PostMeltQuoteRequest(
        unit=Unit.sat.name, request=payment_request_1
    )
    quote = await blink.get_payment_quote(melt_quote_request_1)
    assert quote.checking_id == payment_request_1
    assert quote.amount == Amount(Unit.sat, 1)  # sat
    assert quote.fee == Amount(Unit.sat, MINIMUM_FEE_MSAT // 1000)  # msat


@respx.mock
@pytest.mark.asyncio
async def test_blink_get_payment_quote_backend_error():
    # response says error but invoice (1000 sat) * 0.5% is 5 sat so we expect 10 sat (MINIMUM_FEE_MSAT)
    mock_response = {"data": {"lnInvoiceFeeProbe": {"errors": [{"message": "error"}]}}}
    respx.post(blink.endpoint).mock(return_value=Response(200, json=mock_response))
    melt_quote_request = PostMeltQuoteRequest(
        unit=Unit.sat.name, request=payment_request
    )
    quote = await blink.get_payment_quote(melt_quote_request)
    assert quote.checking_id == payment_request
    assert quote.amount == Amount(Unit.sat, 1000)  # sat
    assert quote.fee == Amount(Unit.sat, MINIMUM_FEE_MSAT // 1000)  # msat


PRICE_RESPONSE = {
    "data": {
        "currencyConversionEstimation": {
            "btcSatAmount": 100,
            "usdCentAmount": 100,
        }
    }
}


@respx.mock
@pytest.mark.asyncio
async def test_blink_status_usd():
    mock_response = {
        "data": {
            "me": {
                "defaultAccount": {
                    "wallets": [
                        {"walletCurrency": "USD", "id": "usd-wallet-123", "balance": 10000},
                        {"walletCurrency": "BTC", "id": "btc-wallet-456", "balance": 100000},
                    ]
                }
            }
        }
    }
    respx.post(blink_usd.endpoint).mock(return_value=Response(200, json=mock_response))
    status = await blink_usd.status()
    assert status.balance.amount == 10000
    assert status.balance.unit == Unit.usd
    assert blink_usd.wallet_ids[Unit.usd] == "usd-wallet-123"


@respx.mock
@pytest.mark.asyncio
async def test_blink_create_invoice_usd():
    blink_usd.wallet_ids[Unit.usd] = "usd-wallet-123"
    mock_response = {
        "data": {
            "lnUsdInvoiceCreateOnBehalfOfRecipient": {
                "invoice": {"paymentRequest": payment_request}
            }
        }
    }
    respx.post(blink_usd.endpoint).mock(return_value=Response(200, json=mock_response))
    invoice = await blink_usd.create_invoice(Amount(Unit.usd, 1000))
    assert invoice.checking_id == invoice.payment_request
    assert invoice.ok


@respx.mock
@pytest.mark.asyncio
async def test_blink_pay_invoice_usd():
    blink_usd.wallet_ids[Unit.usd] = "usd-wallet-123"
    payment_response = {
        "data": {
            "lnInvoicePaymentSend": {
                "status": "SUCCESS",
                "transaction": {
                    "settlementAmount": -1010,
                    "settlementFee": 1000,
                    "settlementVia": {"preImage": "abc123"},
                },
            }
        }
    }
    status_response = {
        "data": {
            "me": {
                "defaultAccount": {
                    "walletById": {
                        "transactionsByPaymentHash": [
                            {
                                "status": "SUCCESS",
                                "settlementAmount": -1010,
                                "settlementFee": 1000,
                                "direction": "SEND",
                                "settlementVia": {"preImage": "abc123"},
                            }
                        ]
                    }
                }
            }
        }
    }
    respx.post(blink_usd.endpoint).mock(
        side_effect=[
            Response(200, json=payment_response),
            Response(200, json=status_response),
            Response(200, json=PRICE_RESPONSE),
        ]
    )
    quote = MeltQuote(
        request=payment_request,
        quote="asd",
        method="bolt11",
        checking_id=payment_request,
        unit="usd",
        amount=1000,
        fee_reserve=100,
        state=MeltQuoteState.unpaid,
    )
    payment = await blink_usd.pay_invoice(quote, 1000)
    assert payment.settled
    assert payment.fee
    assert payment.fee.unit == Unit.usd
    assert payment.fee.amount == 10
    assert payment.error_message is None


@respx.mock
@pytest.mark.asyncio
async def test_blink_get_payment_status_usd():
    blink_usd.wallet_ids[Unit.usd] = "usd-wallet-123"
    status_response = {
        "data": {
            "me": {
                "defaultAccount": {
                    "walletById": {
                        "transactionsByPaymentHash": [
                            {
                                "status": "SUCCESS",
                                "settlementAmount": -1010,
                                "settlementFee": 1000,
                                "direction": "SEND",
                                "settlementVia": {"preImage": "abc123"},
                            }
                        ]
                    }
                }
            }
        }
    }
    respx.post(blink_usd.endpoint).mock(
        side_effect=[
            Response(200, json=status_response),
            Response(200, json=PRICE_RESPONSE),
        ]
    )
    status = await blink_usd.get_payment_status(payment_request)
    assert status.settled
    assert status.fee
    assert status.fee.unit == Unit.usd
    assert status.fee.amount == 10
    assert status.preimage == "abc123"


@respx.mock
@pytest.mark.asyncio
async def test_blink_get_payment_quote_usd():
    blink_usd.wallet_ids[Unit.usd] = "usd-wallet-123"
    fee_probe_response = {"data": {"lnUsdInvoiceFeeProbe": {"amount": 10}}}
    respx.post(blink_usd.endpoint).mock(
        side_effect=[
            Response(200, json=fee_probe_response),
            Response(200, json=PRICE_RESPONSE),
        ]
    )
    melt_quote_request = PostMeltQuoteRequest(
        unit=Unit.usd.name, request=payment_request
    )
    quote = await blink_usd.get_payment_quote(melt_quote_request)
    assert quote.checking_id == payment_request
    assert quote.amount.unit == Unit.usd
    assert quote.fee.unit == Unit.usd
    assert quote.amount.amount == 1000
    assert quote.fee.amount == 10
