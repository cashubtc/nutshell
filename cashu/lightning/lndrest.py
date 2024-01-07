import asyncio
import base64
import hashlib
import json
from typing import AsyncGenerator, Dict, Optional

import httpx
from bolt11 import (
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
)
from .macaroon import load_macaroon


class LndRestWallet(LightningBackend):
    """https://api.lightning.community/rest/index.html#lnd-rest-api-reference"""

    units = set([Unit.sat, Unit.msat])

    def __init__(self):
        endpoint = settings.mint_lnd_rest_endpoint
        cert = settings.mint_lnd_rest_cert

        macaroon = (
            settings.mint_lnd_rest_macaroon
            or settings.mint_lnd_rest_admin_macaroon
            or settings.mint_lnd_rest_invoice_macaroon
        )

        if not endpoint:
            raise Exception("cannot initialize lndrest: no endpoint")

        if not macaroon:
            raise Exception("cannot initialize lndrest: no macaroon")

        if not cert:
            logger.warning(
                "no certificate for lndrest provided, this only works if you have a"
                " publicly issued certificate"
            )

        endpoint = endpoint[:-1] if endpoint.endswith("/") else endpoint
        endpoint = (
            f"https://{endpoint}" if not endpoint.startswith("http") else endpoint
        )
        self.endpoint = endpoint
        self.macaroon = load_macaroon(macaroon)

        # if no cert provided it should be public so we set verify to True
        # and it will still check for validity of certificate and fail if its not valid
        # even on startup
        self.cert = cert or True

        self.auth = {"Grpc-Metadata-macaroon": self.macaroon}
        self.client = httpx.AsyncClient(
            base_url=self.endpoint, headers=self.auth, verify=self.cert
        )

    async def status(self) -> StatusResponse:
        try:
            r = await self.client.get("/v1/balance/channels")
            r.raise_for_status()
        except (httpx.ConnectError, httpx.RequestError) as exc:
            return StatusResponse(
                error_message=f"Unable to connect to {self.endpoint}. {exc}",
                balance=0,
            )

        try:
            data = r.json()
            if r.is_error:
                raise Exception
        except Exception:
            return StatusResponse(error_message=r.text[:200], balance=0)

        return StatusResponse(error_message=None, balance=int(data["balance"]) * 1000)

    async def create_invoice(
        self,
        amount: Amount,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[bytes] = None,
        **kwargs,
    ) -> InvoiceResponse:
        self.assert_unit_supported(amount.unit)
        data: Dict = {
            "value": amount.to(Unit.sat).amount,
            "private": True,
            "memo": memo or "",
        }
        if kwargs.get("expiry"):
            data["expiry"] = kwargs["expiry"]
        if description_hash:
            data["description_hash"] = base64.b64encode(description_hash).decode(
                "ascii"
            )
        elif unhashed_description:
            data["description_hash"] = base64.b64encode(
                hashlib.sha256(unhashed_description).digest()
            ).decode("ascii")

        try:
            r = await self.client.post(url="/v1/invoices", json=data)
        except Exception as e:
            raise Exception(f"failed to create invoice: {e}")

        if r.is_error:
            error_message = r.text
            try:
                error_message = r.json()["error"]
            except Exception:
                pass
            return InvoiceResponse(
                ok=False,
                checking_id=None,
                payment_request=None,
                error_message=error_message,
            )

        data = r.json()
        payment_request = data["payment_request"]
        payment_hash = base64.b64decode(data["r_hash"]).hex()
        checking_id = payment_hash

        return InvoiceResponse(
            ok=True,
            checking_id=checking_id,
            payment_request=payment_request,
            error_message=None,
        )

    async def pay_invoice(
        self, quote: MeltQuote, fee_limit_msat: int
    ) -> PaymentResponse:
        # set the fee limit for the payment
        lnrpcFeeLimit = dict()
        lnrpcFeeLimit["fixed_msat"] = f"{fee_limit_msat}"

        r = await self.client.post(
            url="/v1/channels/transactions",
            json={"payment_request": quote.request, "fee_limit": lnrpcFeeLimit},
            timeout=None,
        )

        if r.is_error or r.json().get("payment_error"):
            error_message = r.json().get("payment_error") or r.text
            return PaymentResponse(
                ok=False,
                checking_id=None,
                fee=None,
                preimage=None,
                error_message=error_message,
            )

        data = r.json()
        checking_id = base64.b64decode(data["payment_hash"]).hex()
        fee_msat = int(data["payment_route"]["total_fees_msat"])
        preimage = base64.b64decode(data["payment_preimage"]).hex()
        return PaymentResponse(
            ok=True,
            checking_id=checking_id,
            fee=Amount(unit=Unit.msat, amount=fee_msat) if fee_msat else None,
            preimage=preimage,
            error_message=None,
        )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        r = await self.client.get(url=f"/v1/invoice/{checking_id}")

        if r.is_error or not r.json().get("settled"):
            # this must also work when checking_id is not a hex recognizable by lnd
            # it will return an error and no "settled" attribute on the object
            return PaymentStatus(paid=None)

        return PaymentStatus(paid=True)

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        """
        This routine checks the payment status using routerpc.TrackPaymentV2.
        """
        # convert checking_id from hex to base64 and some LND magic
        try:
            checking_id = base64.urlsafe_b64encode(bytes.fromhex(checking_id)).decode(
                "ascii"
            )
        except ValueError:
            return PaymentStatus(paid=None)

        url = f"/v2/router/track/{checking_id}"

        # check payment.status:
        # https://api.lightning.community/?python=#paymentpaymentstatus
        statuses = {
            "UNKNOWN": None,
            "IN_FLIGHT": None,
            "SUCCEEDED": True,
            "FAILED": False,
        }

        async with self.client.stream("GET", url, timeout=None) as r:
            async for json_line in r.aiter_lines():
                try:
                    line = json.loads(json_line)
                    if line.get("error"):
                        logger.error(
                            line["error"]["message"]
                            if "message" in line["error"]
                            else line["error"]
                        )
                        return PaymentStatus(paid=None)
                    payment = line.get("result")
                    if payment is not None and payment.get("status"):
                        return PaymentStatus(
                            paid=statuses[payment["status"]],
                            fee=(
                                Amount(unit=Unit.msat, amount=payment.get("fee_msat"))
                                if payment.get("fee_msat")
                                else None
                            ),
                            preimage=payment.get("payment_preimage"),
                        )
                    else:
                        return PaymentStatus(paid=None)
                except Exception:
                    continue

        return PaymentStatus(paid=None)

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        while True:
            try:
                url = "/v1/invoices/subscribe"
                async with self.client.stream("GET", url, timeout=None) as r:
                    async for line in r.aiter_lines():
                        try:
                            inv = json.loads(line)["result"]
                            if not inv["settled"]:
                                continue
                        except Exception:
                            continue

                        payment_hash = base64.b64decode(inv["r_hash"]).hex()
                        yield payment_hash
            except Exception as exc:
                logger.error(
                    f"lost connection to lnd invoices stream: '{exc}', retrying in 5"
                    " seconds"
                )
                await asyncio.sleep(5)

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
