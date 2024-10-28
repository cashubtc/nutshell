# type: ignore
import asyncio
import json
from typing import AsyncGenerator, Optional

import httpx
from bolt11 import (
    decode,
)

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
)


class LNbitsWallet(LightningBackend):
    """https://github.com/lnbits/lnbits"""

    supported_units = {Unit.sat}
    unit = Unit.sat
    supports_incoming_payment_stream: bool = True
    supports_description: bool = True

    def __init__(self, unit: Unit = Unit.sat, **kwargs):
        self.assert_unit_supported(unit)
        self.unit = unit
        self.endpoint = settings.mint_lnbits_endpoint
        self.client = httpx.AsyncClient(
            verify=not settings.debug,
            headers={"X-Api-Key": settings.mint_lnbits_key},
        )

    async def status(self) -> StatusResponse:
        try:
            r = await self.client.get(url=f"{self.endpoint}/api/v1/wallet", timeout=15)
            r.raise_for_status()
            data: dict = r.json()
        except Exception as exc:
            return StatusResponse(
                error_message=f"Failed to connect to {self.endpoint} due to: {exc}",
                balance=0,
            )
        if data.get("detail"):
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
            data = r.json()
        except httpx.HTTPStatusError:
            return InvoiceResponse(
                ok=False, error_message=f"HTTP status: {r.reason_phrase}"
            )
        except Exception as exc:
            return InvoiceResponse(ok=False, error_message=str(exc))
        if data.get("detail"):
            return InvoiceResponse(ok=False, error_message=data["detail"])

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
            data: dict = r.json()
        except httpx.HTTPStatusError:
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message=f"HTTP status: {r.reason_phrase}",
            )
        except Exception as exc:
            return PaymentResponse(result=PaymentResult.FAILED, error_message=str(exc))
        if data.get("detail"):
            return PaymentResponse(
                result=PaymentResult.FAILED, error_message=data["detail"]
            )

        checking_id = data.get("payment_hash")
        if not checking_id:
            return PaymentResponse(
                result=PaymentResult.UNKNOWN, error_message="No payment_hash received"
            )

        # we do this to get the fee and preimage
        payment: PaymentStatus = await self.get_payment_status(checking_id)

        return PaymentResponse(
            result=payment.result,
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
            data: dict = r.json()
        except Exception as e:
            return PaymentStatus(result=PaymentResult.UNKNOWN, error_message=str(e))
        data: dict = r.json()
        if data.get("detail"):
            return PaymentStatus(
                result=PaymentResult.UNKNOWN, error_message=data["detail"]
            )

        if data["paid"]:
            result = PaymentResult.SETTLED
        elif not data["paid"] and data["details"]["pending"]:
            result = PaymentResult.PENDING
        elif not data["paid"] and not data["details"]["pending"]:
            result = PaymentResult.FAILED
        else:
            result = PaymentResult.UNKNOWN

        return PaymentStatus(
            result=result,
            fee=Amount(unit=Unit.msat, amount=abs(data["details"]["fee"])),
            preimage=data["preimage"],
        )

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        try:
            r = await self.client.get(
                url=f"{self.endpoint}/api/v1/payments/{checking_id}"
            )
            r.raise_for_status()
            data = r.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code != 404:
                raise e
            return PaymentStatus(
                result=PaymentResult.UNKNOWN, error_message=e.response.text
            )
        except Exception as e:
            return PaymentStatus(result=PaymentResult.UNKNOWN, error_message=str(e))

        if "paid" not in data and "details" not in data:
            return PaymentStatus(
                result=PaymentResult.UNKNOWN, error_message="invalid response"
            )

        if data["paid"]:
            result = PaymentResult.SETTLED
        elif not data["paid"] and data["details"]["pending"]:
            result = PaymentResult.PENDING
        elif not data["paid"] and not data["details"]["pending"]:
            result = PaymentResult.FAILED
        else:
            result = PaymentResult.UNKNOWN

        return PaymentStatus(
            result=result,
            fee=Amount(unit=Unit.msat, amount=abs(data["details"]["fee"])),
            preimage=data.get("preimage"),
        )

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        invoice_obj = decode(melt_quote.request)
        assert invoice_obj.amount_msat, "invoice has no amount."
        amount_msat = int(invoice_obj.amount_msat)
        fees_msat = fee_reserve(amount_msat)
        fees = Amount(unit=Unit.msat, amount=fees_msat)
        amount = Amount(unit=Unit.msat, amount=amount_msat)
        return PaymentQuoteResponse(
            checking_id=invoice_obj.payment_hash,
            fee=fees.to(self.unit, round="up"),
            amount=amount.to(self.unit, round="up"),
        )

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        url = f"{self.endpoint}/api/v1/payments/sse"

        try:
            sse_headers = self.client.headers.copy()
            sse_headers.update(
                {
                    "accept": "text/event-stream",
                    "cache-control": "no-cache",
                    "connection": "keep-alive",
                }
            )
            async with self.client.stream(
                "GET",
                url,
                content="text/event-stream",
                timeout=None,
                headers=sse_headers,
            ) as r:
                sse_trigger = False
                async for line in r.aiter_lines():
                    # The data we want to listen to is of this shape:
                    # event: payment-received
                    # data: {.., "payment_hash" : "asd"}
                    if line.startswith("event: payment-received"):
                        sse_trigger = True
                        continue
                    elif sse_trigger and line.startswith("data:"):
                        data = json.loads(line[len("data:") :])
                        sse_trigger = False
                        yield data["payment_hash"]
                    else:
                        sse_trigger = False

        except (OSError, httpx.ReadError, httpx.ConnectError, httpx.ReadTimeout):
            pass

        await asyncio.sleep(1)
