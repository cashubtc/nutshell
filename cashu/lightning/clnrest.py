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
from pydantic import BaseModel

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

CLN_PAYMENT_STATUS_COMPLETE = "complete"
CLN_PAYMENT_STATUS_PENDING = "pending"
CLN_PAYMENT_STATUS_FAILED = "failed"

# https://docs.corelightning.org/reference/listpays
PAYMENT_RESULT_MAP = {
    CLN_PAYMENT_STATUS_COMPLETE: PaymentResult.SETTLED,
    CLN_PAYMENT_STATUS_PENDING: PaymentResult.PENDING,
    CLN_PAYMENT_STATUS_FAILED: PaymentResult.FAILED,
}

# https://docs.corelightning.org/reference/lightning-listinvoices
INVOICE_RESULT_MAP = {
    "paid": PaymentResult.SETTLED,
    "unpaid": PaymentResult.PENDING,
    "expired": PaymentResult.FAILED,
}


class CLNChannel(BaseModel):
    our_amount_msat: int | str
    amount_msat: int | str | None = None
    id: str | None = None
    funding_txid: str | None = None
    funding_output: int | None = None
    connected: bool | None = None
    state: str | None = None
    channel_id: str | None = None
    short_channel_id: str | None = None


class CLNListFundsResponse(BaseModel):
    channels: list[CLNChannel] = []
    outputs: list[dict] | None = None


class CLNInvoiceResponse(BaseModel):
    payment_hash: str
    bolt11: str | None = None
    bolt12: str | None = None
    expires_at: int | None = None
    label: str | None = None
    warning_capacity: str | None = None
    warning_offline: str | None = None
    warning_deadends: str | None = None
    warning_private_unused: str | None = None
    warning_mpp: str | None = None


class CLNXPayResponse(BaseModel):
    payment_preimage: str
    amount_msat: int | str
    amount_sent_msat: int | str
    destination: str | None = None
    payment_hash: str | None = None
    created_at: float | int | None = None
    parts: int | None = None
    status: str | None = None


class CLNInvoiceItem(BaseModel):
    label: str | None = None
    bolt11: str | None = None
    bolt12: str | None = None
    payment_hash: str | None = None
    amount_msat: int | str | None = None
    status: str
    pay_index: int | None = None
    amount_received_msat: int | str | None = None
    paid_at: int | None = None
    description: str | None = None
    expires_at: int | None = None
    payment_preimage: str | None = None


class CLNListInvoicesResponse(BaseModel):
    invoices: list[CLNInvoiceItem] = []


class CLNPayItem(BaseModel):
    payment_hash: str | None = None
    status: str
    destination: str | None = None
    amount_msat: int | str | None = None
    amount_sent_msat: int | str | None = None
    created_at: float | int | None = None
    preimage: str | None = None
    number_of_parts: int | None = None


class CLNListPaysResponse(BaseModel):
    pays: list[CLNPayItem] = []


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
            base_url=self.url,
            verify=self.cert,
            headers=self.auth,
            timeout=None,
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
                balance=Amount(self.unit, 0),
            )

        try:
            raw_data = r.json()
            funds = CLNListFundsResponse.model_validate(raw_data)
        except Exception:
            return StatusResponse(
                error_message=f"Invalid response from {self.url}: {r.text[:200]}",
                balance=Amount(self.unit, 0),
            )

        if len(funds.channels) == 0:
            return StatusResponse(error_message="no data", balance=Amount(self.unit, 0))
        balance_msat = int(sum([int(c.our_amount_msat) for c in funds.channels]))
        return StatusResponse(balance=Amount(self.unit, balance_msat // 1000))

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

        try:
            invoice_resp = CLNInvoiceResponse.model_validate(r.json())
        except Exception as e:
            return InvoiceResponse(
                ok=False,
                error_message=f"Invalid invoice response from {self.url}: {e}",
            )

        return InvoiceResponse(
            ok=True,
            checking_id=invoice_resp.payment_hash,
            payment_request=invoice_resp.bolt11,
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
        post_data = {
            "invstring": quote.request,
            "maxfee": fee_limit_msat,
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
        r = await self.client.post("/v1/xpay", data=post_data, timeout=None)

        if r.is_error or "message" in r.json():
            try:
                data = r.json()
                error_message = str(data["message"])
            except Exception:
                error_message = r.text
            return PaymentResponse(
                result=PaymentResult.FAILED, error_message=error_message
            )

        try:
            xpay_resp = CLNXPayResponse.model_validate(r.json())
        except Exception as e:
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message=f"Invalid payment response from {self.url}: {e}",
            )

        checking_id = invoice.payment_hash
        preimage = xpay_resp.payment_preimage
        fee_msat = int(xpay_resp.amount_sent_msat) - int(xpay_resp.amount_msat)

        return PaymentResponse(
            result=PaymentResult.SETTLED,
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
            if r.is_error or "message" in r.json():
                raise Exception("error in cln response")
            list_inv = CLNListInvoicesResponse.model_validate(r.json())
            if not list_inv.invoices:
                raise Exception("no invoices returned")
            return PaymentStatus(
                result=INVOICE_RESULT_MAP[list_inv.invoices[0].status],
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
        if r.is_error or "message" in r.json():
            try:
                message = r.json().get("message") or r.text
            except Exception:
                message = r.text
            raise Exception(f"error in clnrest response: {message}")

        list_pays = CLNListPaysResponse.model_validate(r.json())

        if not list_pays.pays:
            # payment not found
            logger.error(f"payment not found for checking_id: {checking_id}")
            return PaymentStatus(
                result=PaymentResult.UNKNOWN, error_message="payment not found"
            )

        pays = list_pays.pays
        pay = next(
            (p for p in pays if p.status == CLN_PAYMENT_STATUS_PENDING),
            None,
        )
        if pay is None:
            pay = next(
                (p for p in pays if p.status == CLN_PAYMENT_STATUS_COMPLETE),
                None,
            )
        if pay is None and all(
            p.status == CLN_PAYMENT_STATUS_FAILED for p in pays
        ):
            pay = pays[-1]
        if pay is None:
            return PaymentStatus(
                result=PaymentResult.UNKNOWN,
                error_message="unknown payment status",
            )

        fee_msat, preimage = None, None
        if PAYMENT_RESULT_MAP[pay.status] == PaymentResult.SETTLED:
            fee_msat = (
                int(pay.amount_sent_msat) - int(pay.amount_msat)
                if pay.amount_sent_msat is not None and pay.amount_msat is not None
                else None
            )
            preimage = pay.preimage

        return PaymentStatus(
            result=PAYMENT_RESULT_MAP[pay.status],
            fee=Amount(unit=Unit.msat, amount=fee_msat) if fee_msat else None,
            preimage=preimage,
        )

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        # call listinvoices to determine the last pay_index
        r = await self.client.post("/v1/listinvoices")
        r.raise_for_status()
        if r.is_error or "message" in r.json():
            raise Exception("error in cln response")
        list_inv = CLNListInvoicesResponse.model_validate(r.json())
        last_invoice_paid_invoice = next(
            (i for i in reversed(list_inv.invoices) if i.status == "paid"), None
        )
        last_pay_index = (
            last_invoice_paid_invoice.pay_index
            if last_invoice_paid_invoice and last_invoice_paid_invoice.pay_index is not None
            else 0
        )
        self.last_pay_index = last_pay_index

        retry_delay = 0
        max_retry_delay = settings.mint_retry_exponential_backoff_max_delay

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
                    # Reset retry delay on successful connection
                    retry_delay = 0
                    async for line in r.aiter_lines():
                        inv = json.loads(line)
                        if "code" in inv and "message" in inv:
                            logger.error("Error in paid_invoices_stream:", inv)
                            raise Exception(inv["message"])
                        try:
                            paid = inv["status"] == "paid"
                            if not paid:
                                continue
                            last_pay_index = inv.get("pay_index")
                            if not last_pay_index:
                                logger.error(f"missing pay_index in invoice: {inv}")
                                raise Exception("missing pay_index in invoice")
                            self.last_pay_index = last_pay_index
                        except Exception as e:
                            logger.error(f"Error in paid_invoices_stream: {e}")
                            continue
                        logger.trace(f"paid invoice: {inv}")
                        payment_hash = inv.get("payment_hash")
                        if payment_hash:
                            yield payment_hash

            except Exception as exc:
                logger.error(
                    f"lost connection to clnrest invoices stream: '{exc}', retrying in {retry_delay}"
                    " seconds"
                )
                await asyncio.sleep(retry_delay)

                # Exponential backoff
                retry_delay = max(
                    settings.mint_retry_exponential_backoff_base_delay,
                    min(retry_delay * 2, max_retry_delay),
                )

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        invoice_obj = decode(melt_quote.request)
        assert invoice_obj.amount_msat, "invoice has no amount."
        assert invoice_obj.amount_msat > 0, "invoice has 0 amount."
        amount_msat = (
            melt_quote.mpp_amount if melt_quote.is_mpp else (invoice_obj.amount_msat)
        )
        fees_msat = fee_reserve(amount_msat)
        fees = Amount(unit=Unit.msat, amount=fees_msat)
        amount = Amount(unit=Unit.msat, amount=amount_msat)
        return PaymentQuoteResponse(
            checking_id=invoice_obj.payment_hash,
            fee=fees.to(self.unit, round="up"),
            amount=amount.to(self.unit, round="up"),
        )
