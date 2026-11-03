import time

import pytest
from bolt11.exceptions import Bolt11Exception

from cashu.core.errors import AmountlessInvoiceNotSupportedError, QuoteExpiredError
from cashu.lightning.clnrest import CLNRestWallet
from cashu.lightning.fake import FakeWallet
from cashu.lightning.lnd_grpc.lnd_grpc import LndRPCWallet
from cashu.lightning.lndrest import LndRestWallet
from cashu.lightning.sparkl2 import SparkL2Wallet
from cashu.lightning.strike import StrikeWallet
from tests.helpers import get_fake_invoice


@pytest.fixture(
    params=[
        CLNRestWallet,
        FakeWallet,
        LndRestWallet,
        LndRPCWallet,
        SparkL2Wallet,
        StrikeWallet,
    ],
    ids=["cln", "fake", "lnd-rest", "lnd-grpc", "spark", "strike"],
)
def backend(request):
    # Validation must work locally, without initializing a backend connection.
    return object.__new__(request.param)


@pytest.mark.parametrize("expiry", [60, None], ids=["explicit", "bolt11-default"])
def test_validation_returns_absolute_invoice_expiry(backend, expiry):
    now = int(time.time())
    invoice = get_fake_invoice(2, date=now, expiry=expiry)

    assert backend.validate_payment_request(invoice) == now + (
        3600 if expiry is None else expiry
    )


@pytest.mark.parametrize("expiry", [60, None], ids=["explicit", "bolt11-default"])
def test_expired_invoice_is_rejected(backend, expiry):
    invoice = get_fake_invoice(2, date=int(time.time()) - 7200, expiry=expiry)

    with pytest.raises(QuoteExpiredError, match="invoice expired"):
        backend.validate_payment_request(invoice)


def test_amountless_invoice_is_rejected(backend):
    with pytest.raises(AmountlessInvoiceNotSupportedError, match="invoice has no amount"):
        backend.validate_payment_request(get_fake_invoice(0))


def test_malformed_request_is_rejected(backend):
    with pytest.raises(Bolt11Exception):
        backend.validate_payment_request("invalid-payment-request")
