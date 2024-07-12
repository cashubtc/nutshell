# type: ignore
import secrets
from typing import AsyncGenerator, Dict, Optional

import httpx

from ..core.base import Amount, MeltQuote, Unit
from ..core.models import PostMeltQuoteRequest
from ..core.settings import settings
from .base import (
    InvoiceResponse,
    LightningBackend,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentStatus,
    StatusResponse,
)

USDT = "USDT"


class StrikeWallet(LightningBackend):
    """https://docs.strike.me/api/"""

    supported_units = [Unit.sat, Unit.usd, Unit.eur]
    currency_map = {Unit.sat: "BTC", Unit.usd: "USD", Unit.eur: "EUR"}

    def __init__(self, unit: Unit, **kwargs):
        self.assert_unit_supported(unit)
        self.unit = unit
        self.endpoint = "https://api.strike.me"
        self.currency = self.currency_map[self.unit]

        # bearer auth with settings.mint_strike_key
        bearer_auth = {
            "Authorization": f"Bearer {settings.mint_strike_key}",
        }
        self.client = httpx.AsyncClient(
            verify=not settings.debug,
            headers=bearer_auth,
        )

    async def status(self) -> StatusResponse:
        try:
            r = await self.client.get(url=f"{self.endpoint}/v1/balances", timeout=15)
            r.raise_for_status()
        except Exception as exc:
            return StatusResponse(
                error_message=f"Failed to connect to {self.endpoint} due to: {exc}",
                balance=0,
            )

        try:
            data = r.json()
        except Exception:
            return StatusResponse(
                error_message=(
                    f"Failed to connect to {self.endpoint}, got: '{r.text[:200]}...'"
                ),
                balance=0,
            )

        for balance in data:
            if balance["currency"] == self.currency:
                return StatusResponse(
                    error_message=None,
                    balance=Amount.from_float(
                        float(balance["total"]), self.unit
                    ).amount,
                )

        # if no the unit is USD but no USD balance was found, we try USDT
        if self.unit == Unit.usd:
            for balance in data:
                if balance["currency"] == USDT:
                    self.currency = USDT
                    return StatusResponse(
                        error_message=None,
                        balance=Amount.from_float(
                            float(balance["total"]), self.unit
                        ).amount,
                    )

        return StatusResponse(
            error_message=f"Could not find balance for currency {self.currency}",
            balance=0,
        )

    async def create_invoice(
        self,
        amount: Amount,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[bytes] = None,
    ) -> InvoiceResponse:
        self.assert_unit_supported(amount.unit)

        data: Dict = {"out": False, "amount": amount}
        if description_hash:
            data["description_hash"] = description_hash.hex()
        if unhashed_description:
            data["unhashed_description"] = unhashed_description.hex()

        data["memo"] = memo or ""
        payload = {
            "correlationId": secrets.token_hex(16),
            "description": "Invoice for order 123",
            "amount": {"amount": amount.to_float_string(), "currency": self.currency},
        }
        try:
            r = await self.client.post(url=f"{self.endpoint}/v1/invoices", json=payload)
            r.raise_for_status()
        except Exception:
            return InvoiceResponse(
                paid=False,
                checking_id=None,
                payment_request=None,
                error_message=r.json()["detail"],
            )

        quote = r.json()
        invoice_id = quote.get("invoiceId")

        try:
            payload = {"descriptionHash": secrets.token_hex(32)}
            r2 = await self.client.post(
                f"{self.endpoint}/v1/invoices/{invoice_id}/quote", json=payload
            )
        except Exception:
            return InvoiceResponse(
                paid=False,
                checking_id=None,
                payment_request=None,
                error_message=r.json()["detail"],
            )

        data2 = r2.json()
        payment_request = data2.get("lnInvoice")
        assert payment_request, "Did not receive an invoice"
        checking_id = invoice_id
        return InvoiceResponse(
            ok=True,
            checking_id=checking_id,
            payment_request=payment_request,
            error_message=None,
        )

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        bolt11 = melt_quote.request
        try:
            r = await self.client.post(
                url=f"{self.endpoint}/v1/payment-quotes/lightning",
                json={"sourceCurrency": self.currency, "lnInvoice": bolt11},
                timeout=None,
            )
            r.raise_for_status()
        except Exception:
            error_message = r.json()["data"]["message"]
            raise Exception(error_message)
        data = r.json()

        amount = Amount.from_float(float(data.get("amount").get("amount")), self.unit)
        quote = PaymentQuoteResponse(
            amount=amount,
            checking_id=data.get("paymentQuoteId"),
            fee=Amount(self.unit, 0),
        )
        return quote

    async def pay_invoice(
        self, quote: MeltQuote, fee_limit_msat: int
    ) -> PaymentResponse:
        # we need to get the checking_id of this quote
        try:
            r = await self.client.patch(
                url=f"{self.endpoint}/v1/payment-quotes/{quote.checking_id}/execute",
                timeout=None,
            )
            r.raise_for_status()
        except Exception:
            error_message = r.json()["data"]["message"]
            return PaymentResponse(
                ok=None,
                checking_id=None,
                fee=None,
                preimage=None,
                error_message=error_message,
            )

        data = r.json()
        states = {"PENDING": None, "COMPLETED": True, "FAILED": False}
        if states[data.get("state")]:
            return PaymentResponse(
                ok=True, checking_id=None, fee=None, preimage=None, error_message=None
            )
        else:
            return PaymentResponse(
                ok=False, checking_id=None, fee=None, preimage=None, error_message=None
            )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        try:
            r = await self.client.get(url=f"{self.endpoint}/v1/invoices/{checking_id}")
            r.raise_for_status()
        except Exception:
            return PaymentStatus(paid=None)
        data = r.json()
        states = {"PENDING": None, "UNPAID": None, "PAID": True, "CANCELLED": False}
        return PaymentStatus(paid=states[data["state"]])

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        try:
            r = await self.client.get(url=f"{self.endpoint}/v1/payments/{checking_id}")
            r.raise_for_status()
        except Exception:
            return PaymentStatus(paid=None)
        data = r.json()
        if "paid" not in data and "details" not in data:
            return PaymentStatus(paid=None)

        return PaymentStatus(
            paid=data["paid"],
            fee_msat=data["details"]["fee"],
            preimage=data["preimage"],
        )

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        raise NotImplementedError("paid_invoices_stream not implemented")
