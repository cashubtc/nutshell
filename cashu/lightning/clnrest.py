import asyncio
import json
import os
import random
from typing import AsyncGenerator, Dict, Optional

import httpx
from bolt11 import (
    Bolt11Exception,
    decode,
)
from loguru import logger

from ..core.base import Amount, MeltQuote, Unit
from ..core.helpers import fee_reserve
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
    Unsupported,
)

# https://docs.corelightning.org/reference/lightning-pay
PAYMENT_RESULT_MAP = {
    "complete": PaymentResult.SETTLED,
    "pending": PaymentResult.PENDING,
    "failed": PaymentResult.FAILED,
}

# https://docs.corelightning.org/reference/lightning-listinvoices
INVOICE_RESULT_MAP = {
    "paid": PaymentResult.SETTLED,
    "unpaid": PaymentResult.PENDING,
    "expired": PaymentResult.FAILED,
}


class CLNRestWallet(LightningBackend):
    supported_units = {Unit.sat, Unit.msat}
    unit = Unit.sat
    supports_mpp = settings.mint_clnrest_enable_mpp
    supports_incoming_payment_stream: bool = True
    supports_description: bool = True

    def __init__(self, unit: Unit = Unit.sat, **kwargs):
        self.assert_unit_supported(unit)
        self.unit = unit
        rune_settings = settings.mint_clnrest_rune
        if not rune_settings:
            raise Exception("missing rune for clnrest")
        # load from file or use as is
        if os.path.exists(rune_settings):
            with open(rune_settings) as f:
                rune = f.read()
            rune = rune.strip()
        else:
            rune = rune_settings
        self.rune = rune

        url = settings.mint_clnrest_url
        if not url:
            raise Exception("missing url for clnrest")
        if not rune:
            raise Exception("missing rune for clnrest")

        self.url = url[:-1] if url.endswith("/") else url
        self.url = (
            f"https://{self.url}" if not self.url.startswith("http") else self.url
        )
        self.auth = {
            "rune": self.rune,
            "accept": "application/json",
        }

        self.cert = settings.mint_clnrest_cert or False
        self.client = httpx.AsyncClient(
            base_url=self.url, verify=self.cert, headers=self.auth
        )
        self.last_pay_index = 0

    async def cleanup(self):
        try:
            await self.client.aclose()
        except RuntimeError as e:
            logger.warning(f"Error closing wallet connection: {e}")

    async def status(self) -> StatusResponse:
        r = await self.client.post("/v1/listfunds", timeout=5)
        r.raise_for_status()
        if r.is_error or "message" in r.json():
            try:
                data = r.json()
                error_message = data["message"]
            except Exception:
                error_message = r.text
            return StatusResponse(
                error_message=(
                    f"Failed to connect to {self.url}, got: '{error_message}...'"
                ),
                balance=0,
            )

        data = r.json()
        if len(data) == 0:
            return StatusResponse(error_message="no data", balance=0)
        balance_msat = int(sum([c["our_amount_msat"] for c in data["channels"]]))
        return StatusResponse(balance=balance_msat)

    async def create_invoice(
        self,
        amount: Amount,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[bytes] = None,
        **kwargs,
    ) -> InvoiceResponse:
        self.assert_unit_supported(amount.unit)
        label = f"lbl{random.random()}"
        data: Dict = {
            "amount_msat": amount.to(Unit.msat, round="up").amount,
            "description": memo,
            "label": label,
        }
        if description_hash and not unhashed_description:
            raise Unsupported(
                "'description_hash' unsupported by CLNRestWallet, "
                "provide 'unhashed_description'"
            )

        if unhashed_description:
            data["description"] = unhashed_description.decode("utf-8")

        if kwargs.get("expiry"):
            data["expiry"] = kwargs["expiry"]

        if kwargs.get("preimage"):
            data["preimage"] = kwargs["preimage"]

        r = await self.client.post(
            "/v1/invoice",
            data=data,
        )

        if r.is_error or "message" in r.json():
            try:
                data = r.json()
                error_message = data["message"]
            except Exception:
                error_message = r.text

            return InvoiceResponse(
                ok=False,
                error_message=error_message,
            )

        data = r.json()
        assert "payment_hash" in data
        assert "bolt11" in data
        return InvoiceResponse(
            ok=True,
            checking_id=data["payment_hash"],
            payment_request=data["bolt11"],
        )

    async def pay_invoice(
        self, quote: MeltQuote, fee_limit_msat: int
    ) -> PaymentResponse:
        try:
            invoice = decode(quote.request)
        except Bolt11Exception as exc:
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message=str(exc),
            )

        if not invoice.amount_msat or invoice.amount_msat <= 0:
            error_message = "0 amount invoices are not allowed"
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message=error_message,
            )

        quote_amount_msat = Amount(Unit[quote.unit], quote.amount).to(Unit.msat).amount
        fee_limit_percent = fee_limit_msat / quote_amount_msat * 100
        post_data = {
            "bolt11": quote.request,
            "maxfeepercent": f"{fee_limit_percent:.11}",
            "exemptfee": 0,  # so fee_limit_percent is applied even on payments
            # with fee < 5000 millisatoshi (which is default value of exemptfee)
        }

        # Handle Multi-Mint payout where we must only pay part of the invoice amount
        logger.trace(f"{quote_amount_msat = }, {invoice.amount_msat = }")
        if quote_amount_msat != invoice.amount_msat:
            logger.trace("Detected Multi-Nut payment")
            if self.supports_mpp:
                post_data["partial_msat"] = quote_amount_msat
            else:
                error_message = "mint does not support MPP"
                logger.error(error_message)
                return PaymentResponse(
                    result=PaymentResult.FAILED, error_message=error_message
                )
        r = await self.client.post("/v1/pay", data=post_data, timeout=None)

        if r.is_error or "message" in r.json():
            try:
                data = r.json()
                error_message = str(data["message"])
            except Exception:
                error_message = r.text
            return PaymentResponse(
                result=PaymentResult.FAILED, error_message=error_message
            )

        data = r.json()

        checking_id = data["payment_hash"]
        preimage = data["payment_preimage"]
        fee_msat = data["amount_sent_msat"] - data["amount_msat"]

        return PaymentResponse(
            result=PAYMENT_RESULT_MAP[data["status"]],
            checking_id=checking_id,
            fee=Amount(unit=Unit.msat, amount=fee_msat) if fee_msat else None,
            preimage=preimage,
        )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        r = await self.client.post(
            "/v1/listinvoices",
            data={"payment_hash": checking_id},
        )
        try:
            r.raise_for_status()
            data = r.json()

            if r.is_error or "message" in data or data.get("invoices") is None:
                raise Exception("error in cln response")
            return PaymentStatus(
                result=INVOICE_RESULT_MAP[data["invoices"][0]["status"]],
            )
        except Exception as e:
            logger.error(f"Error getting invoice status: {e}")
            return PaymentStatus(result=PaymentResult.UNKNOWN, error_message=str(e))

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        r = await self.client.post(
            "/v1/listpays",
            data={"payment_hash": checking_id},
        )
        r.raise_for_status()
        data = r.json()

        if not data.get("pays"):
            # payment not found
            logger.error(f"payment not found: {data.get('pays')}")
            return PaymentStatus(
                result=PaymentResult.UNKNOWN, error_message="payment not found"
            )

        if r.is_error or "message" in data:
            message = data.get("message") or data
            raise Exception(f"error in clnrest response: {message}")

        pay = data["pays"][0]

        fee_msat, preimage = None, None
        if PAYMENT_RESULT_MAP[pay["status"]] == PaymentResult.SETTLED:
            fee_msat = -int(pay["amount_sent_msat"]) - int(pay["amount_msat"])
            preimage = pay["preimage"]

        return PaymentStatus(
            result=PAYMENT_RESULT_MAP[pay["status"]],
            fee=Amount(unit=Unit.msat, amount=fee_msat) if fee_msat else None,
            preimage=preimage,
        )

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        # call listinvoices to determine the last pay_index
        r = await self.client.post("/v1/listinvoices")
        r.raise_for_status()
        data = r.json()
        if r.is_error or "message" in data:
            raise Exception("error in cln response")
        self.last_pay_index = data["invoices"][-1]["pay_index"]
        while True:
            try:
                url = "/v1/waitanyinvoice"
                async with self.client.stream(
                    "POST",
                    url,
                    data={
                        "lastpay_index": self.last_pay_index,
                    },
                    timeout=None,
                ) as r:
                    async for line in r.aiter_lines():
                        inv = json.loads(line)
                        if "code" in inv and "message" in inv:
                            logger.error("Error in paid_invoices_stream:", inv)
                            raise Exception(inv["message"])
                        try:
                            paid = inv["status"] == "paid"
                            self.last_pay_index = inv["pay_index"]
                            if not paid:
                                continue
                        except Exception as e:
                            logger.error(f"Error in paid_invoices_stream: {e}")
                            continue
                        logger.trace(f"paid invoice: {inv}")
                        payment_hash = inv.get("payment_hash")
                        if payment_hash:
                            yield payment_hash

            except Exception as exc:
                logger.debug(
                    f"lost connection to clnrest invoices stream: '{exc}', "
                    "reconnecting..."
                )
                await asyncio.sleep(0.02)

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        invoice_obj = decode(melt_quote.request)
        assert invoice_obj.amount_msat, "invoice has no amount."
        assert invoice_obj.amount_msat > 0, "invoice has 0 amount."
        amount_msat = invoice_obj.amount_msat
        if melt_quote.is_mpp:
            amount_msat = (
                Amount(Unit[melt_quote.unit], melt_quote.mpp_amount)
                .to(Unit.msat)
                .amount
            )
        fees_msat = fee_reserve(amount_msat)
        fees = Amount(unit=Unit.msat, amount=fees_msat)
        amount = Amount(unit=Unit.msat, amount=amount_msat)
        return PaymentQuoteResponse(
            checking_id=invoice_obj.payment_hash,
            fee=fees.to(self.unit, round="up"),
            amount=amount.to(self.unit, round="up"),
        )
