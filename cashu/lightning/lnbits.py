# type: ignore
from typing import Dict, Optional

import aiohttp

from ..core.settings import settings
from .base import (
    InvoiceResponse,
    PaymentResponse,
    PaymentStatus,
    StatusResponse,
    Wallet,
)


class LNbitsWallet(Wallet):
    """https://github.com/lnbits/lnbits"""

    def __init__(self):
        self.endpoint = settings.mint_lnbits_endpoint

        key = settings.mint_lnbits_key
        self.key = {"X-Api-Key": key}
        if settings.debug:
            connector = aiohttp.TCPConnector(ssl=False)
        else:
            connector = None
        self.s = aiohttp.ClientSession(connector=connector)
        # self.s.auth = ("user", "pass")
        self.s.headers.update({"X-Api-Key": key})

    async def status(self) -> StatusResponse:
        try:
            r = await self.s.get(url=f"{self.endpoint}/api/v1/wallet", timeout=15)
            r.raise_for_status()
        except Exception as exc:
            return StatusResponse(
                f"Failed to connect to {self.endpoint} due to: {exc}", 0
            )

        try:
            data = await r.json()
        except:
            return StatusResponse(
                f"Failed to read from {self.endpoint}, got non-JSON or empty reponse", 0
            )
        if "detail" in data:
            return StatusResponse(f"LNbits error: {data['detail']}", 0)
        return StatusResponse(None, data["balance"])

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
        try:
            r = await self.s.post(url=f"{self.endpoint}/api/v1/payments", json=data)
        except:
            return InvoiceResponse(False, None, None, "Request error.")
        try:
            r.raise_for_status()
        except:
            data = await r.json()
            return InvoiceResponse(False, None, None, data["detail"])

        ok, checking_id, payment_request, error_message = (
            True,
            None,
            None,
            None,
        )

        data = await r.json()
        checking_id, payment_request = data["checking_id"], data["payment_request"]

        return InvoiceResponse(ok, checking_id, payment_request, error_message)

    async def pay_invoice(self, bolt11: str, fee_limit_msat: int) -> PaymentResponse:
        try:
            r = await self.s.post(
                url=f"{self.endpoint}/api/v1/payments",
                json={"out": True, "bolt11": bolt11},
                timeout=None,
            )
        except:
            return PaymentResponse(None, None, None, None, "Request error.")
        try:
            r.raise_for_status()
        except:
            error_message = (await r.json())["detail"]
            return PaymentResponse(None, None, None, None, error_message)
        if r.status > 299:
            return PaymentResponse(None, None, None, None, f"HTTP status: {r.reason}")
        data = await r_json()

        if "detail" in data:
            return PaymentResponse(None, None, None, None, data["detail"])

        ok, checking_id, fee_msat, preimage, error_message = (
            True,
            None,
            None,
            None,
            None,
        )

        checking_id = data["payment_hash"]

        # we do this to get the fee and preimage
        payment: PaymentStatus = await self.get_payment_status(checking_id)

        return PaymentResponse(ok, checking_id, payment.fee_msat, payment.preimage)

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        try:
            r = await self.s.get(
                url=f"{self.endpoint}/api/v1/payments/{checking_id}",
                headers=self.key,
            )
            r.raise_for_status()
        except:
            return PaymentStatus(None)

        data = await r.json()
        if data.get("detail"):
            return PaymentStatus(None)
        return PaymentStatus(data["paid"])

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        try:
            r = await self.s.get(
                url=f"{self.endpoint}/api/v1/payments/{checking_id}", headers=self.key
            )
            r.raise_for_status()
        except:
            return PaymentStatus(None)

        data = await r.json()
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
