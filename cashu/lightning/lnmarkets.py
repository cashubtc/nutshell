import base64
import hashlib
import hmac
import json
import os
import re
import time
from enum import Enum
from math import ceil
from typing import Dict, Optional, Union

import httpx
from bolt11 import decode
from loguru import logger

from ..core.base import Amount, MeltQuote, Unit
from ..core.errors import CashuError
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

SAT_MAX_FEE_PERCENT = 1  # 1% of the amount in satoshis
SAT_MIN_FEE_SAT = 101  # 101 satoshis


class Method(Enum):
    POST = 1
    GET = 2
    DELETE = 3
    PUT = 4

    def __str__(self):
        return self.name


def raise_if_err(r):
    if r.status_code != 200:
        if 400 <= r.status_code < 500:
            error_message = r.json()["message"]
        else:
            error_message = r.text
        logger.error(error_message)
        raise CashuError(error_message)


class LNMarketsWallet(LightningBackend):
    """https://docs.lnmarkets.com/api"""

    supports_mpp = False
    supports_incoming_payment_stream = False
    supported_units = set([Unit.usd, Unit.sat])

    def __init__(self, unit: Unit, **kwargs):
        self.assert_unit_supported(unit)
        self.unit = unit
        self.endpoint = settings.mint_lnmarkets_rest_url or "https://api.lnmarkets.com"

        if (
            re.match(r"^https?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9.-]+)*$", self.endpoint)
            is None
        ):
            raise Exception("Invalid API endpoint")

        access_key = settings.mint_lnmarkets_rest_access_key
        secret = settings.mint_lnmarkets_rest_secret
        passphrase = settings.mint_lnmarkets_rest_passphrase

        if not access_key:
            raise Exception("No LNMarkets API access key provided")
        if not secret:
            raise Exception("No LNMarkets API secret provided")
        if not passphrase:
            raise Exception("No LNMarkets API passphrase provided")

        # You can specify paths instead
        if os.path.exists(access_key):
            with open(access_key, "r") as f:
                access_key = f.read()
        if os.path.exists(secret):
            with open(secret, "r") as f:
                secret = f.read()
        if os.path.exists(passphrase):
            with open(passphrase, "r") as f:
                passphrase = f.read()

        self.secret = secret
        self.headers: Dict[str, Union[str, int]] = {
            "LNM-ACCESS-KEY": access_key,
            "LNM-ACCESS-PASSPHRASE": passphrase,
        }

        self.client = httpx.AsyncClient(verify=not settings.debug)

    async def get_request_headers(self, method: Method, path: str, data: dict) -> dict:
        timestamp = time.time_ns() // 10**6  # timestamp in milliseconds
        params = ""
        if method == Method.GET:
            for key, value in data.items():
                params += f"&{key}={value}"
            params = params.strip("&")
        elif method == Method.POST:
            params = json.dumps(data, separators=(",", ":"))
        else:
            raise Exception("Method not allowed. Something is wrong with the code.")

        signature = base64.b64encode(
            hmac.new(
                self.secret.encode("utf-8"),
                f"{timestamp}{str(method)}{path}{params}".encode("utf-8"),  # bytes from utf-8 string
                hashlib.sha256,
            ).digest()
        )
        headers = self.headers.copy()
        headers["LNM-ACCESS-TIMESTAMP"] = str(timestamp)
        headers["LNM-ACCESS-SIGNATURE"] = signature.decode("utf-8")
        if method == Method.POST:
            headers["Content-Type"] = "application/json"
        return headers

    async def status(self) -> StatusResponse:
        headers = await self.get_request_headers(Method.GET, "/v2/user", {})
        try:
            r = await self.client.get(
                url=f"{self.endpoint}/v2/user", timeout=15, headers=headers
            )
            raise_if_err(r)
        except CashuError as exc:
            return StatusResponse(
                error_message=f"Failed to connect to {self.endpoint} due to: {exc.detail}",
                balance=0,
            )

        try:
            data: dict = r.json()
        except Exception:
            logger.error(f"Received invalid response from {self.endpoint}: {r.text}")
            return StatusResponse(
                error_message=(
                    f"Received invalid response from {self.endpoint}: {r.text}"
                ),
                balance=0,
            )

        if self.unit == Unit.usd:
            return StatusResponse(
                error_message=None, balance=data["synthetic_usd_balance"]
            )
        return StatusResponse(error_message=None, balance=data["balance"])

    async def create_invoice(
        self,
        amount: Amount,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
    ) -> InvoiceResponse:
        self.assert_unit_supported(amount.unit)

        data = None
        path = None
        if self.unit == Unit.usd:
            # We do this trick to avoid messing up the signature.
            amount_usd = float(amount.to_float_string())
            amount_usd = (
                int(amount_usd) if float(int(amount_usd)) == amount_usd else amount_usd
            )
            data = {"amount": amount_usd, "currency": "usd"}
            path = "/v2/user/deposit/susd"
        else:
            data = {"amount": amount.amount}
            path = "/v2/user/deposit"

        logger.debug(f"{data = } {path = }")
        assert data and path
        headers = await self.get_request_headers(Method.POST, path, data)
        try:
            r = await self.client.post(
                url=f"{self.endpoint}{path}",
                json=data,
                headers=headers,
            )
            raise_if_err(r)
        except CashuError as e:
            return InvoiceResponse(
                ok=False,
                error_message=f"Error while creating invoice: {e.detail}",
            )

        data = None
        try:
            data = r.json()
        except Exception:
            logger.error(f"Received invalid response from {self.endpoint}: {r.text}")
            return InvoiceResponse(
                ok=False,
                error_message=(
                    f"Received invalid response from {self.endpoint}: {r.text}"
                ),
            )

        checking_id, payment_request = data["depositId"], data["paymentRequest"]
        assert isinstance(checking_id, str) and isinstance(payment_request, str)

        return InvoiceResponse(
            ok=True,
            checking_id=checking_id,
            payment_request=payment_request,
        )

    async def pay_invoice(
        self, quote: MeltQuote, fee_limit_msat: int
    ) -> PaymentResponse:
        self.assert_unit_supported(Unit[quote.unit])

        data = {"invoice": quote.request}
        path = "/v2/user/withdraw"
        futures_ticker_path = "/v2/futures/ticker"
        btc_price = 0.0

        # * If USD, we set the `quote_id` of the request to the checking_id
        # * If USD, we fetch the ticker price for conversion.
        #   This is a TEMPORARY measure until we can get the correct return fee
        #   from LNMarkets
        if self.unit == Unit.usd:
            data["quote_id"] = quote.checking_id
            price_data = None
            try:
                r = await self.client.get(
                    url=f"{self.endpoint}{futures_ticker_path}"
                )
                raise_if_err(r)
                price_data = r.json()
            except (CashuError, json.JSONDecodeError) as e:
                if isinstance(e, CashuError):
                    return PaymentResponse(
                        result=PaymentResult.FAILED,
                        error_message=f"payment failed: {e.detail}"
                    )
                elif isinstance(e, json.JSONDecodeError):
                    return PaymentResponse(
                        result=PaymentResult.FAILED, 
                        error_message=f"payment failed: {str(e)}"
                    )
            btc_price = float(price_data["lastPrice"])
        
        headers = await self.get_request_headers(Method.POST, path, data)
        try:
            r = await self.client.post(
                url=f"{self.endpoint}{path}",
                json=data,
                headers=headers,
                timeout=None,
            )
            raise_if_err(r)
        except CashuError as e:
            return PaymentResponse(
                result=PaymentResult.UNKNOWN,
                error_message=f"payment might have failed: {e.detail}"
            )

        try:
            data = r.json()
        except Exception:
            logger.error(f"payment might have failed: {r.text}")
            return PaymentResponse(
                result=PaymentResult.UNKNOWN,
                error_message=f"payment might have failed: {r.text}"
            )

        # lnmarkets does not provide a payment_preimage :(
        checking_id = data["id"]
        fee_paid = int(data["fee"])
        
        # if USD, we need to convert the returned fee: sat -> cents
        if self.unit == Unit.usd:
            fee_paid_usd = fee_paid / 1e8 * btc_price   # sat -> usd
            fee_paid = ceil(fee_paid_usd * 100)         # usd -> cents
        return PaymentResponse(
            result=PaymentResult.PENDING,
            checking_id=checking_id,
            fee=Amount(unit=self.unit, amount=fee_paid),
        )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        path = f"/v2/user/deposit/{checking_id}"
        headers = await self.get_request_headers(Method.GET, path, {})
        try:
            r = await self.client.get(
                url=f"{self.endpoint}{path}",
                headers=headers,
                timeout=None,
            )
            raise_if_err(r)
        except CashuError:
            return PaymentStatus(result=PaymentResult.UNKNOWN)

        data = None
        try:
            data = r.json()
        except Exception:
            logger.error(f"get invoice status unsuccessful: {r.text}")
            return PaymentStatus(result=PaymentResult.UNKNOWN)
        return PaymentStatus(result=PaymentResult.SETTLED if data["success"] else PaymentResult.PENDING)

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        path = f"/v2/user/withdrawals/{checking_id}"
        data: dict = {}
        headers = await self.get_request_headers(Method.GET, path, data)

        try:
            r = await self.client.get(
                url=f"{self.endpoint}{path}",
                headers=headers,
                timeout=None,
            )
            raise_if_err(r)
        except CashuError:
            return PaymentStatus(result=PaymentResult.UNKNOWN)

        try:
            data = r.json()
        except Exception:
            logger.error(f"getting invoice status unsuccessful: {r.text}")
            return PaymentStatus(result=PaymentResult.UNKNOWN)

        logger.debug(f"payment status: {data}")
        if "success" not in data:
            return PaymentStatus(result=PaymentResult.UNKNOWN)

        if data["success"]:
            return PaymentStatus(
                result=PaymentResult.SETTLED, 
                fee=Amount(unit=Unit.sat, amount=int(data["fee"]))
            )
        else:
            # TIMEOUT 30 seconds 
            now = int(time.time())
            payment_timestamp = int(data["ts"]) // 1000
            if 0 <= (now - payment_timestamp) < 30:
                return PaymentStatus(result=PaymentResult.PENDING)
            else:
                return PaymentStatus(result=PaymentResult.FAILED)

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        self.assert_unit_supported(Unit[melt_quote.unit])
        invoice_obj = decode(melt_quote.request)
        assert invoice_obj.amount_msat, "invoice has no amount."
        amount_msat = int(invoice_obj.amount_msat)
        amount = Amount(unit=Unit.msat, amount=amount_msat)

        # SAT: the max fee is reportedly max(100, 0.5% * amount_sat)
        if self.unit == Unit.sat:
            amount_sat = amount.to(Unit.sat).amount
            max_fee = max(SAT_MIN_FEE_SAT, ceil(SAT_MAX_FEE_PERCENT / 100 * amount_sat))
            return PaymentQuoteResponse(
                checking_id=invoice_obj.payment_hash,
                fee=Amount(self.unit, max_fee),
                amount=amount.to(self.unit, round="up"),
            )
        # sUSD
        elif self.unit == Unit.usd:
            # We request a quote to pay a precise amount of sats from the usd balance, then calculate
            # the usd amount and usd fee reserve
            data = {"amount": amount.to(Unit.sat).amount, "currency": "btc"}
            path = "/v2/user/withdraw/susd"
            headers = await self.get_request_headers(Method.POST, path, data)

            r = await self.client.post(
                f"{self.endpoint}{path}",
                json=data,
                headers=headers,
                timeout=None,
            )
            raise_if_err(r)

            data = r.json()
            fee_reserve_usd = float(data["fee_reserve"])
            amount_usd = float(data["amount"])
            return PaymentQuoteResponse(
                checking_id=data["quote_id"],
                fee=Amount.from_float(fee_reserve_usd, self.unit),
                amount=Amount.from_float(amount_usd, self.unit),
            )
        else:
            raise NotImplementedError()

    async def paid_invoices_stream(self):
        raise NotImplementedError("paid_invoices_stream not implemented")
