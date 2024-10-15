import secrets
from typing import AsyncGenerator, Dict, Optional, Union

import httpx
from pydantic import BaseModel

from ..core.base import Amount, MeltQuote, Unit
from ..core.models import PostMeltQuoteRequest
from ..core.settings import settings
from .base import (
    InvoiceResponse,
    LightningBackend,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    StatusResponse,
)

USDT = "USDT"


class StrikeAmount(BaseModel):
    amount: str
    currency: str


class StrikeRate(BaseModel):
    amount: str
    sourceCurrency: str
    targetCurrency: str


class StrikeCreateInvoiceResponse(BaseModel):
    invoiceId: str
    amount: StrikeAmount
    state: str
    description: str


class StrikePaymentQuoteResponse(BaseModel):
    lightningNetworkFee: StrikeAmount
    paymentQuoteId: str
    validUntil: str
    amount: StrikeAmount
    totalFee: StrikeAmount
    totalAmount: StrikeAmount


class InvoiceQuoteResponse(BaseModel):
    quoteId: str
    description: str
    lnInvoice: str
    expiration: str
    expirationInSec: int
    targetAmount: StrikeAmount
    sourceAmount: StrikeAmount
    conversionRate: StrikeRate


class StrikePaymentResponse(BaseModel):
    paymentId: str
    state: str
    result: str
    completed: Optional[str]
    delivered: Optional[str]
    amount: StrikeAmount
    totalFee: StrikeAmount
    lightningNetworkFee: StrikeAmount
    totalAmount: StrikeAmount
    lightning: Dict[str, StrikeAmount]


PAYMENT_RESULT_MAP = {
    "PENDING": PaymentResult.PENDING,
    "COMPLETED": PaymentResult.SETTLED,
    "FAILED": PaymentResult.FAILED,
}


INVOICE_RESULT_MAP = {
    "PENDING": PaymentResult.PENDING,
    "UNPAID": PaymentResult.PENDING,
    "PAID": PaymentResult.SETTLED,
    "CANCELLED": PaymentResult.FAILED,
}


class StrikeWallet(LightningBackend):
    """https://docs.strike.me/api/"""

    supported_units = {Unit.sat, Unit.usd, Unit.eur}
    supports_description: bool = False
    currency_map = {Unit.sat: "BTC", Unit.usd: "USD", Unit.eur: "EUR"}

    def fee_int(
        self, strike_quote: Union[StrikePaymentQuoteResponse, StrikePaymentResponse]
    ) -> int:
        fee_str = strike_quote.totalFee.amount
        if strike_quote.totalFee.currency == self.currency_map[Unit.sat]:
            fee = int(float(fee_str) * 1e8)
        elif strike_quote.totalFee.currency in [
            self.currency_map[Unit.usd],
            self.currency_map[Unit.eur],
        ]:
            fee = int(float(fee_str) * 100)
        return fee

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

        payload = {
            "correlationId": secrets.token_hex(16),
            "description": memo or "Invoice for order 123",
            "amount": {"amount": amount.to_float_string(), "currency": self.currency},
        }
        try:
            r = await self.client.post(url=f"{self.endpoint}/v1/invoices", json=payload)
            r.raise_for_status()
        except Exception:
            return InvoiceResponse(ok=False, error_message=r.json()["detail"])

        invoice = StrikeCreateInvoiceResponse.parse_obj(r.json())

        try:
            payload = {"descriptionHash": secrets.token_hex(32)}
            r2 = await self.client.post(
                f"{self.endpoint}/v1/invoices/{invoice.invoiceId}/quote", json=payload
            )
            r2.raise_for_status()
        except Exception:
            return InvoiceResponse(ok=False, error_message=r.json()["detail"])

        quote = InvoiceQuoteResponse.parse_obj(r2.json())
        return InvoiceResponse(
            ok=True, checking_id=invoice.invoiceId, payment_request=quote.lnInvoice
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
        strike_quote = StrikePaymentQuoteResponse.parse_obj(r.json())
        if strike_quote.amount.currency != self.currency_map[self.unit]:
            raise Exception(
                f"Expected currency {self.currency_map[self.unit]}, got {strike_quote.amount.currency}"
            )
        amount = Amount.from_float(float(strike_quote.amount.amount), self.unit)
        fee = self.fee_int(strike_quote)

        quote = PaymentQuoteResponse(
            amount=amount,
            checking_id=strike_quote.paymentQuoteId,
            fee=Amount(self.unit, fee),
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
                result=PaymentResult.FAILED, error_message=error_message
            )

        payment = StrikePaymentResponse.parse_obj(r.json())
        fee = self.fee_int(payment)
        return PaymentResponse(
            result=PAYMENT_RESULT_MAP[payment.state],
            checking_id=payment.paymentId,
            fee=Amount(self.unit, fee),
        )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        try:
            r = await self.client.get(url=f"{self.endpoint}/v1/invoices/{checking_id}")
            r.raise_for_status()
        except Exception as e:
            return PaymentStatus(result=PaymentResult.UNKNOWN, error_message=str(e))
        data = r.json()
        return PaymentStatus(result=INVOICE_RESULT_MAP[data.get("state")])

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        try:
            r = await self.client.get(url=f"{self.endpoint}/v1/payments/{checking_id}")
            r.raise_for_status()
            payment = StrikePaymentResponse.parse_obj(r.json())
            fee = self.fee_int(payment)
            return PaymentStatus(
                result=PAYMENT_RESULT_MAP[payment.state],
                fee=Amount(self.unit, fee),
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise exc
            return PaymentStatus(
                result=PaymentResult.UNKNOWN, error_message=exc.response.text
            )

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:  # type: ignore
        raise NotImplementedError("paid_invoices_stream not implemented")
