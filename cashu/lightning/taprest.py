import asyncio
import base64
import hashlib
import json
from typing import AsyncGenerator, Dict, Optional
import math

import bolt11
import httpx
from bolt11 import (
    TagChar,
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
)
from .macaroon import load_macaroon

PAYMENT_RESULT_MAP = {
    "UNKNOWN": PaymentResult.UNKNOWN,
    "IN_FLIGHT": PaymentResult.PENDING,
    "INITIATED": PaymentResult.PENDING,
    "SUCCEEDED": PaymentResult.SETTLED,
    "FAILED": PaymentResult.FAILED,
}
INVOICE_RESULT_MAP = {
    "OPEN": PaymentResult.PENDING,
    "SETTLED": PaymentResult.SETTLED,
    "CANCELED": PaymentResult.FAILED,
    "ACCEPTED": PaymentResult.PENDING,
}

MAX_ROUTE_RETRIES = 50
TEMPORARY_CHANNEL_FAILURE_ERROR = "TEMPORARY_CHANNEL_FAILURE"


class TapRestWallet(LightningBackend):
    """https://api.lightning.community/rest/index.html#lnd-rest-api-reference"""

    supports_incoming_payment_stream = True
    supported_units = {Unit.thb}
    supports_description: bool = True
    unit = Unit.thb

    def __init__(self, unit: Unit = Unit.thb, **kwargs):
        self.assert_unit_supported(unit)
        self.unit = unit
        endpoint = settings.mint_tap_rest_endpoint
        cert = settings.mint_tap_rest_cert
        cert_verify = settings.mint_tap_rest_cert_verify

        macaroon_lnd = settings.mint_tap_rest_lnd_macaroon
        macaroon_tap = settings.mint_tap_rest_tap_macaroon
            

        if not endpoint:
            raise Exception("cannot initialize TapRestWallet: no endpoint")

        if not macaroon_lnd or not macaroon_tap:
            raise Exception("cannot initialize TapRestWallet: no macaroon")

        if not cert:
            logger.warning(
                "no certificate for TapRestWallet provided, this only works if you have a"
                " publicly issued certificate"
            )

        if not cert_verify:
            logger.warning("certificate validation will be disabled for LndRestWallet")

        endpoint = endpoint[:-1] if endpoint.endswith("/") else endpoint
        endpoint = (
            f"https://{endpoint}" if not endpoint.startswith("http") else endpoint
        )
        self.endpoint = endpoint
        self.macaroon_lnd = load_macaroon(macaroon_lnd)
        self.macaroon_tap = load_macaroon(macaroon_tap)

        # if no cert provided it should be public so we set verify to True
        # and it will still check for validity of certificate and fail if its not valid
        # even on startup
        self.cert = cert or True

        # disable cert verify if choosen
        if not cert_verify:
            self.cert = False

        self.auth = {"Grpc-Metadata-macaroon": self.macaroon_lnd}
        self.client = httpx.AsyncClient(
            base_url=self.endpoint, headers=self.auth, verify=self.cert
        )

        self.client_tap = httpx.AsyncClient(
            base_url=self.endpoint, headers={"Grpc-Metadata-macaroon": self.macaroon_tap}, verify=self.cert
        )

    async def status(self) -> StatusResponse:
        try:
            r = await self.client.get("/v1/balance/channels")
            r.raise_for_status()
        except (httpx.ConnectError, httpx.RequestError) as exc:
            return StatusResponse(
                error_message=f"Unable to connect to {self.endpoint}. {exc}",
                balance=Amount(self.unit, 0),
            )

        try:
            data = r.json()
            if r.is_error:
                raise Exception
        except Exception:
            return StatusResponse(
                error_message=r.text[:200], balance=Amount(self.unit, 0)
            )

        return StatusResponse(
            error_message=None, balance=Amount(self.unit, int(data["balance"]))
        )

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
            "asset_id": base64.b64encode(bytes.fromhex(settings.mint_tap_rest_asset_id)).decode('utf-8'),
            "asset_amount": amount.amount * 100,
            "invoice_request": {
                "memo": memo or "",
            },
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
            r = await self.client_tap.post(url="/v1/taproot-assets/channels/invoice", json=data)
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

        data = r.json()["invoice_result"]
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
        invoice = bolt11.decode(quote.request)

        url="/v1/taproot-assets/channels/send-payment"

        # set the fee limit for the payment
        fee_limit = fee_reserve(int(invoice.amount_msat))
        data: Dict = {
            "asset_id": base64.b64encode(bytes.fromhex(settings.mint_tap_rest_asset_id)).decode('utf-8'),
            "peer_pubkey": base64.b64encode(bytes.fromhex(settings.mint_tap_rest_peer_pubkey)).decode('utf-8'),
            "payment_request": {
                "payment_request": quote.request,
                "fee_limit_msat": fee_limit
            }
        }

        async with self.client_tap.stream("POST", url, json=data, timeout=30) as r:
            async for json_line in r.aiter_lines():
                line = json.loads(json_line)
                if line.get("error"):
                    message = (
                        line["error"]["message"]
                        if "message" in line["error"]
                        else line["error"]
                    )
                    logger.error(f"LND get_payment_status error: {message}")
                    return PaymentResponse(
                        result=PaymentResult.FAILED, error_message=message
                    )

                payment_result = line["result"].get("payment_result")
                if payment_result and payment_result["status"] == "SUCCEEDED":
                    logger.debug(f'Result: {line["result"]["payment_result"]}')
                    checking_id = payment_result["payment_hash"]
                    fee_msat = int(payment_result["fee_sat"])
                    preimage = payment_result["payment_preimage"]

                    return PaymentResponse(
                        result=PaymentResult.SETTLED,
                        checking_id=checking_id,
                        fee= Amount(unit=self.unit, amount=quote.fee_reserve),
                        preimage=preimage,
                    )
        
        return PaymentResponse(result=PaymentResult.UNKNOWN, error_message="timeout")


    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        r = await self.client.get(url=f"/v1/invoice/{checking_id}")

        if r.is_error:
            logger.error(f"Couldn't get invoice status: {r.text}")
            return PaymentStatus(result=PaymentResult.UNKNOWN, error_message=r.text)

        data = None
        try:
            data = r.json()
        except json.JSONDecodeError as e:
            logger.error(f"Incomprehensible response: {e}")
            return PaymentStatus(result=PaymentResult.UNKNOWN, error_message=str(e))
        if not data or not data.get("state"):
            return PaymentStatus(
                result=PaymentResult.UNKNOWN, error_message="no invoice state"
            )
        return PaymentStatus(
            result=INVOICE_RESULT_MAP[data["state"]],
        )

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        """
        This routine checks the payment status using routerpc.TrackPaymentV2.
        """
        # convert checking_id from hex to base64 and some LND magic
        checking_id = base64.urlsafe_b64encode(bytes.fromhex(checking_id)).decode(
            "ascii"
        )
        url = f"/v2/router/track/{checking_id}"
        async with self.client.stream("GET", url, timeout=None) as r:
            async for json_line in r.aiter_lines():
                try:
                    line = json.loads(json_line)

                    # check for errors
                    if line.get("error"):
                        message = (
                            line["error"]["message"]
                            if "message" in line["error"]
                            else line["error"]
                        )
                        logger.error(f"LND get_payment_status error: {message}")
                        return PaymentStatus(
                            result=PaymentResult.UNKNOWN, error_message=message
                        )

                    payment = line.get("result")

                    # payment exists
                    if payment is not None and payment.get("status"):
                        preimage = (
                            payment.get("payment_preimage")
                            if payment.get("payment_preimage") != "0" * 64
                            else None
                        )
                        return PaymentStatus(
                            result=PAYMENT_RESULT_MAP[payment["status"]],
                            fee=(
                                Amount(unit=self.unit, amount=0)
                            ),
                            preimage=preimage,
                        )
                    else:
                        return PaymentStatus(
                            result=PaymentResult.UNKNOWN,
                            error_message="no payment status",
                        )
                except Exception:
                    continue

        return PaymentStatus(result=PaymentResult.UNKNOWN, error_message="timeout")

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

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        data: Dict = {
            "asset_id": base64.b64encode(bytes.fromhex(settings.mint_tap_rest_asset_id)).decode('utf-8'),
            "pay_req_string": melt_quote.request
        }
        try:
            r = await self.client_tap.post(url="/v1/taproot-assets/channels/invoice/decode", json=data)
            r.raise_for_status()
        except Exception as e:
            raise Exception(f"failed to decode invoice: {e}")
        
        data = r.json()
        amount_cent = int(data["asset_amount"])
        fees_cent = fee_reserve(amount_cent)

        invoice_obj = decode(melt_quote.request)

        return PaymentQuoteResponse(
            checking_id=invoice_obj.payment_hash,
            fee=Amount(unit=self.unit, amount=fees_cent//100),
            amount=Amount(unit=self.unit, amount=amount_cent//100),
        )
