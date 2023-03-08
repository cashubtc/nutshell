from mock import AsyncMock

from cashu.core import bolt11
from cashu.lightning.base import PaymentResponse, PaymentStatus, StatusResponse, Wallet
from cashu.lightning.fake import FakeWallet

LIGHTNING_BACKEND = FakeWallet()


def pay_invoice_side_effect(
    payment_request: str, fee_limit_msat: int
) -> PaymentResponse:
    invoice = bolt11.decode(payment_request)
    return PaymentResponse(
        True,  # ok
        invoice.payment_hash,  # checking_id (i.e. payment_hash)
        0,  # fee_msat
        "",  # no error
    )


WALLET.pay_invoice = AsyncMock(side_effect=pay_invoice_side_effect)
WALLET.get_invoice_status = AsyncMock(
    return_value=PaymentStatus(
        True,  # paid
    )
)
WALLET.get_payment_status = AsyncMock(
    return_value=PaymentStatus(
        True,  # paid
    )
)
