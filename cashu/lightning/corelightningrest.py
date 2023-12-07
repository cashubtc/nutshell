import asyncio
import json
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
from ..core.settings import settings
from .base import (
    InvoiceResponse,
    LightningBackend,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentStatus,
    StatusResponse,
    Unsupported,
)
from .macaroon import load_macaroon


class CoreLightningRestWallet(LightningBackend):
    units = set([Unit.sat, Unit.msat])

    def __init__(self):
        macaroon = settings.mint_corelightning_rest_macaroon
        assert macaroon, "missing cln-rest macaroon"

        self.macaroon = load_macaroon(macaroon)

        url = settings.mint_corelightning_rest_url
        if not url:
            raise Exception("missing url for corelightning-rest")
        if not macaroon:
            raise Exception("missing macaroon for corelightning-rest")

        self.url = url[:-1] if url.endswith("/") else url
        self.url = (
            f"https://{self.url}" if not self.url.startswith("http") else self.url
        )
        self.auth = {
            "macaroon": self.macaroon,
            "encodingtype": "hex",
            "accept": "application/json",
        }

        self.cert = settings.mint_corelightning_rest_cert or False
        self.client = httpx.AsyncClient(verify=self.cert, headers=self.auth)
        self.last_pay_index = 0
        self.statuses = {
            "paid": True,
            "complete": True,
            "failed": False,
            "pending": None,
        }

    async def cleanup(self):
        try:
            await self.client.aclose()
        except RuntimeError as e:
            logger.warning(f"Error closing wallet connection: {e}")

    async def status(self) -> StatusResponse:
        r = await self.client.get(f"{self.url}/v1/channel/localremotebal", timeout=5)
        r.raise_for_status()
        if r.is_error or "error" in r.json():
            try:
                data = r.json()
                error_message = data["error"]
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
        balance_msat = int(data.get("localBalance") * 1000)
        return StatusResponse(error_message=None, balance=balance_msat)

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
            "amount": amount.to(Unit.msat, round="up").amount,
            "description": memo,
            "label": label,
        }
        if description_hash and not unhashed_description:
            raise Unsupported(
                "'description_hash' unsupported by CoreLightningRest, "
                "provide 'unhashed_description'"
            )

        if unhashed_description:
            data["description"] = unhashed_description.decode("utf-8")

        if kwargs.get("expiry"):
            data["expiry"] = kwargs["expiry"]

        if kwargs.get("preimage"):
            data["preimage"] = kwargs["preimage"]

        r = await self.client.post(
            f"{self.url}/v1/invoice/genInvoice",
            data=data,
        )

        if r.is_error or "error" in r.json():
            try:
                data = r.json()
                error_message = data["error"]
            except Exception:
                error_message = r.text

            return InvoiceResponse(
                ok=False,
                checking_id=None,
                payment_request=None,
                error_message=error_message,
            )

        data = r.json()
        assert "payment_hash" in data
        assert "bolt11" in data
        return InvoiceResponse(
            ok=True,
            checking_id=data["payment_hash"],
            payment_request=data["bolt11"],
            error_message=None,
        )

    async def pay_invoice(
        self, quote: MeltQuote, fee_limit_msat: int
    ) -> PaymentResponse:
        try:
            invoice = decode(quote.request)
        except Bolt11Exception as exc:
            return PaymentResponse(
                ok=False,
                checking_id=None,
                fee=None,
                preimage=None,
                error_message=str(exc),
            )

        if not invoice.amount_msat or invoice.amount_msat <= 0:
            error_message = "0 amount invoices are not allowed"
            return PaymentResponse(
                ok=False,
                checking_id=None,
                fee=None,
                preimage=None,
                error_message=error_message,
            )
        fee_limit_percent = fee_limit_msat / invoice.amount_msat * 100
        r = await self.client.post(
            f"{self.url}/v1/pay",
            data={
                "invoice": quote.request,
                "maxfeepercent": f"{fee_limit_percent:.11}",
                "exemptfee": 0,  # so fee_limit_percent is applied even on payments
                # with fee < 5000 millisatoshi (which is default value of exemptfee)
            },
            timeout=None,
        )

        if r.is_error or "error" in r.json():
            try:
                data = r.json()
                error_message = data["error"]
            except Exception:
                error_message = r.text
            return PaymentResponse(
                ok=False,
                checking_id=None,
                fee=None,
                preimage=None,
                error_message=error_message,
            )

        data = r.json()

        if data["status"] != "complete":
            return PaymentResponse(
                ok=False,
                checking_id=None,
                fee=None,
                preimage=None,
                error_message="payment failed",
            )

        checking_id = data["payment_hash"]
        preimage = data["payment_preimage"]
        fee_msat = data["msatoshi_sent"] - data["msatoshi"]

        return PaymentResponse(
            ok=self.statuses.get(data["status"]),
            checking_id=checking_id,
            fee=Amount(unit=Unit.msat, amount=fee_msat) if fee_msat else None,
            preimage=preimage,
            error_message=None,
        )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        r = await self.client.get(
            f"{self.url}/v1/invoice/listInvoices",
            params={"payment_hash": checking_id},
        )
        try:
            r.raise_for_status()
            data = r.json()

            if r.is_error or "error" in data or data.get("invoices") is None:
                raise Exception("error in cln response")
            return PaymentStatus(paid=self.statuses.get(data["invoices"][0]["status"]))
        except Exception as e:
            logger.error(f"Error getting invoice status: {e}")
            return PaymentStatus(paid=None)

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        r = await self.client.get(
            f"{self.url}/v1/pay/listPays",
            params={"payment_hash": checking_id},
        )
        try:
            r.raise_for_status()
            data = r.json()

            if r.is_error or "error" in data or not data.get("pays"):
                raise Exception("error in corelightning-rest response")

            pay = data["pays"][0]

            fee_msat, preimage = None, None
            if self.statuses[pay["status"]]:
                # cut off "msat" and convert to int
                fee_msat = -int(pay["amount_sent_msat"][:-4]) - int(
                    pay["amount_msat"][:-4]
                )
                preimage = pay["preimage"]

            return PaymentStatus(
                paid=self.statuses.get(pay["status"]),
                fee=Amount(unit=Unit.msat, amount=fee_msat) if fee_msat else None,
                preimage=preimage,
            )
        except Exception as e:
            logger.error(f"Error getting payment status: {e}")
            return PaymentStatus(paid=None)

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        while True:
            try:
                url = f"{self.url}/v1/invoice/waitAnyInvoice/{self.last_pay_index}"
                async with self.client.stream("GET", url, timeout=None) as r:
                    async for line in r.aiter_lines():
                        inv = json.loads(line)
                        if "error" in inv and "message" in inv["error"]:
                            logger.error("Error in paid_invoices_stream:", inv)
                            raise Exception(inv["error"]["message"])
                        try:
                            paid = inv["status"] == "paid"
                            self.last_pay_index = inv["pay_index"]
                            if not paid:
                                continue
                        except Exception:
                            continue
                        logger.trace(f"paid invoice: {inv}")
                        # NOTE: use payment_hash when corelightning-rest returns it
                        # when using waitAnyInvoice
                        # payment_hash = inv["payment_hash"]
                        # yield payment_hash
                        # hack to return payment_hash if the above shouldn't work
                        r = await self.client.get(
                            f"{self.url}/v1/invoice/listInvoices",
                            params={"label": inv["label"]},
                        )
                        paid_invoce = r.json()
                        logger.trace(f"paid invoice: {paid_invoce}")
                        assert self.statuses[
                            paid_invoce["invoices"][0]["status"]
                        ], "streamed invoice not paid"
                        assert "invoices" in paid_invoce, "no invoices in response"
                        assert len(paid_invoce["invoices"]), "no invoices in response"
                        yield paid_invoce["invoices"][0]["payment_hash"]

            except Exception as exc:
                logger.debug(
                    f"lost connection to corelightning-rest invoices stream: '{exc}', "
                    "reconnecting..."
                )
                await asyncio.sleep(0.02)

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
