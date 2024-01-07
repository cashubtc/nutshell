# type: ignore
from typing import Optional

import httpx
from bolt11 import (
    decode,
)

from ..core.base import Amount, MeltQuote, Unit
from ..core.helpers import fee_reserve
from ..core.settings import settings
from .base import (
    InvoiceResponse,
    LightningBackend,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentStatus,
    StatusResponse,
)


class LNbitsWallet(LightningBackend):
    """https://github.com/lnbits/lnbits"""

    units = set([Unit.sat])

    def __init__(self):
        self.endpoint = settings.mint_lnbits_endpoint
        self.client = httpx.AsyncClient(
            verify=not settings.debug,
            headers={"X-Api-Key": settings.mint_lnbits_key},
        )

    async def status(self) -> StatusResponse:
        try:
            r = await self.client.get(url=f"{self.endpoint}/api/v1/wallet", timeout=15)
            r.raise_for_status()
        except Exception as exc:
            return StatusResponse(
                error_message=f"Failed to connect to {self.endpoint} due to: {exc}",
                balance=0,
            )

        try:
            data: dict = r.json()
        except Exception:
            return StatusResponse(
                error_message=(
                    f"Failed to connect to {self.endpoint}, got: '{r.text[:200]}...'"
                ),
                balance=0,
            )
        if "detail" in data:
            return StatusResponse(
                error_message=f"LNbits error: {data['detail']}", balance=0
            )

        return StatusResponse(error_message=None, balance=data["balance"])

    async def create_invoice(
        self,
        amount: Amount,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[bytes] = None,
    ) -> InvoiceResponse:
        self.assert_unit_supported(amount.unit)

        data = {"out": False, "amount": amount.to(Unit.sat).amount}
        if description_hash:
            data["description_hash"] = description_hash.hex()
        if unhashed_description:
            data["unhashed_description"] = unhashed_description.hex()

        data["memo"] = memo or ""
        try:
            r = await self.client.post(
                url=f"{self.endpoint}/api/v1/payments", json=data
            )
            r.raise_for_status()
        except Exception:
            return InvoiceResponse(
                ok=False,
                error_message=r.json()["detail"],
            )

        data = r.json()
        checking_id, payment_request = data["checking_id"], data["payment_request"]

        return InvoiceResponse(
            ok=True,
            checking_id=checking_id,
            payment_request=payment_request,
        )

    async def pay_invoice(
        self, quote: MeltQuote, fee_limit_msat: int
    ) -> PaymentResponse:
        try:
            r = await self.client.post(
                url=f"{self.endpoint}/api/v1/payments",
                json={"out": True, "bolt11": quote.request},
                timeout=None,
            )
            r.raise_for_status()
        except Exception:
            return PaymentResponse(error_message=r.json()["detail"])
        if r.status_code > 299:
            return PaymentResponse(error_message=(f"HTTP status: {r.reason_phrase}",))
        if "detail" in r.json():
            return PaymentResponse(error_message=(r.json()["detail"],))

        data: dict = r.json()
        checking_id = data["payment_hash"]

        # we do this to get the fee and preimage
        payment: PaymentStatus = await self.get_payment_status(checking_id)

        return PaymentResponse(
            ok=True,
            checking_id=checking_id,
            fee=payment.fee,
            preimage=payment.preimage,
        )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        try:
            r = await self.client.get(
                url=f"{self.endpoint}/api/v1/payments/{checking_id}"
            )
            r.raise_for_status()
        except Exception:
            return PaymentStatus(paid=None)
        data: dict = r.json()
        if data.get("detail"):
            return PaymentStatus(paid=None)
        return PaymentStatus(paid=r.json()["paid"])

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        try:
            r = await self.client.get(
                url=f"{self.endpoint}/api/v1/payments/{checking_id}"
            )
            r.raise_for_status()
        except Exception:
            return PaymentStatus(paid=None)
        data = r.json()
        if "paid" not in data and "details" not in data:
            return PaymentStatus(paid=None)

        return PaymentStatus(
            paid=data["paid"],
            fee=Amount(unit=Unit.msat, amount=abs(data["details"]["fee"])),
            preimage=data["preimage"],
        )

    async def get_payment_quote(self, bolt11: str) -> PaymentQuoteResponse:
        invoice_obj = decode(bolt11)
        assert invoice_obj.amount_msat, "invoice has no amount."
        amount_msat = int(invoice_obj.amount_msat)
        fees_msat = fee_reserve(amount_msat)
        fees = Amount(unit=Unit.msat, amount=fees_msat)
        amount = Amount(unit=Unit.msat, amount=amount_msat)
        return PaymentQuoteResponse(
            checking_id=invoice_obj.payment_hash, fee=fees, amount=amount
        )
