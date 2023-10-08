# type: ignore
import secrets
from typing import Dict, Optional

import httpx

from ..core.settings import settings
from .base import (
    InvoiceResponse,
    PaymentQuote,
    PaymentResponse,
    PaymentStatus,
    StatusResponse,
    Wallet,
)


class StrikeUSDWallet(Wallet):
    """https://github.com/lnbits/lnbits"""

    def __init__(self):
        self.endpoint = "https://api.strike.me"

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
                f"Failed to connect to {self.endpoint} due to: {exc}", 0
            )

        try:
            data = r.json()
        except Exception:
            return StatusResponse(
                f"Failed to connect to {self.endpoint}, got: '{r.text[:200]}...'", 0
            )

        for balance in data:
            if balance["currency"] == "USD":
                return StatusResponse(None, balance["total"])

    async def create_invoice(
        self,
        amount: int,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[bytes] = None,
    ) -> InvoiceResponse:
        data: Dict = {"out": False, "amount": amount}
        if description_hash:
            data["description_hash"] = description_hash.hex()
        if unhashed_description:
            data["unhashed_description"] = unhashed_description.hex()

        data["memo"] = memo or ""
        payload = {
            "correlationId": secrets.token_hex(16),
            "description": "Invoice for order 123",
            "amount": {"amount": str(amount / 100), "currency": "USD"},
        }
        try:
            r = await self.client.post(url=f"{self.endpoint}/v1/invoices", json=payload)
            r.raise_for_status()
        except Exception:
            return InvoiceResponse(False, None, None, r.json()["detail"])
        ok, checking_id, payment_request, error_message = (
            True,
            None,
            None,
            None,
        )
        quote = r.json()
        invoice_id = quote.get("invoiceId")

        try:
            payload = {"descriptionHash": secrets.token_hex(32)}
            r2 = await self.client.post(
                f"{self.endpoint}/v1/invoices/{invoice_id}/quote", json=payload
            )
        except Exception:
            return InvoiceResponse(False, None, None, r.json()["detail"])
        ok, checking_id, payment_request, error_message = (
            True,
            None,
            None,
            None,
        )

        data2 = r2.json()
        payment_request = data2.get("lnInvoice")
        assert payment_request, "Did not receive an invoice"
        checking_id = invoice_id
        return InvoiceResponse(ok, checking_id, payment_request, error_message)

    async def get_invoice_quote(self, bolt11: str) -> PaymentQuote:
        try:
            r = await self.client.post(
                url=f"{self.endpoint}/v1/payment-quotes/lightning",
                json={"sourceCurrency": "USD", "lnInvoice": bolt11},
                timeout=None,
            )
            r.raise_for_status()
        except Exception:
            error_message = r.json()["data"]["message"]
            raise Exception(error_message)
        data = r.json()

        amount_cent = int(float(data.get("amount").get("amount")) * 100)
        quote = PaymentQuote(amount=amount_cent, id=data.get("paymentQuoteId"))
        return quote

    async def pay_invoice(self, bolt11: str, fee_limit_msat: int) -> PaymentResponse:
        try:
            r = await self.client.patch(
                url=f"{self.endpoint}/v1/payment-quotes/{bolt11}/execute",
                timeout=None,
            )
            r.raise_for_status()
        except Exception:
            error_message = r.json()["data"]["message"]
            return PaymentResponse(None, None, None, None, error_message)

        data = r.json()
        states = {"PENDING": None, "COMPLETED": True, "FAILED": False}
        if states[data.get("state")]:
            return PaymentResponse(True, "", 0, "")
        else:
            return PaymentResponse(False, "", 0, "")

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        try:
            r = await self.client.get(url=f"{self.endpoint}/v1/invoices/{checking_id}")
            r.raise_for_status()
        except Exception:
            return PaymentStatus(None)
        data = r.json()
        states = {"PENDING": None, "UNPAID": None, "PAID": True, "CANCELLED": False}
        return PaymentStatus(states[data["state"]])

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        try:
            r = await self.client.get(url=f"{self.endpoint}/v1/payments/{checking_id}")
            r.raise_for_status()
        except Exception:
            return PaymentStatus(None)
        data = r.json()
        if "paid" not in data and "details" not in data:
            return PaymentStatus(None)

        return PaymentStatus(data["paid"], data["details"]["fee"], data["preimage"])

    # async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
    #     url = f"{self.endpoint}/api/v1/payments/sse"

    #     while True:
    #         try:
    #             async with requests.stream("GET", url) as r:
    #                 async for line in r.aiter_lines():
    #                     if line.startswith("data:"):
    #                         try:
    #                             data = json.loads(line[5:])
    #                         except json.decoder.JSONDecodeError:
    #                             continue

    #                         if type(data) is not dict:
    #                             continue

    #                         yield data["payment_hash"]  # payment_hash

    #         except:
    #             pass

    #         print("lost connection to lnbits /payments/sse, retrying in 5 seconds")
    #         await asyncio.sleep(5)
