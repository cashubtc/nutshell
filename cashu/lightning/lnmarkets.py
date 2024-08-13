import base64
import hashlib
import hmac
import json
import os
import re
import time
from enum import Enum
from typing import Dict, Optional, Union

import httpx
from bolt11 import decode
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
    PaymentStatus,
    StatusResponse,
)


class Method(Enum):
    POST = 1
    GET = 2
    DELETE = 3
    PUT = 4

    def __str__(self):
        return self.name

class LNMarketsWallet(LightningBackend):
    """https://docs.lnmarkets.com/api"""
    supports_mpp = False
    supports_incoming_payment_stream = False
    supported_units = set([Unit.usd])

    def __init__(self, unit: Unit, **kwargs):
        self.assert_unit_supported(unit)
        self.unit = unit
        self.endpoint = settings.mint_lnmarkets_rest_url or "https://api.lnmarkets.com"

        if re.match(r"^https?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9.-]+)*$", self.endpoint) is None:
            raise Exception("Invalid API endpoint")
        
        access_key = settings.mint_lnmarkets_rest_access_key
        secret = settings.mint_lnmarkets_rest_secret
        passphrase = settings.mint_lnmarkets_rest_passphrase

        if not access_key:
            raise Exception("No API access key provided")
        if not secret:
            raise Exception("No API secret provided")
        if not passphrase:
            raise Exception("No API passphrase provided")

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
            "LNM-ACCESS-PASSPHRASE": passphrase
        }

        self.client = httpx.AsyncClient(
            verify=not settings.debug
        )

    async def get_request_headers(self, method: Method, path: str, data: dict) -> dict:
        timestamp = time.time_ns() // 10**6   # timestamp in milliseconds
        params = ""
        if method == Method.GET:
            for key, value in data.items():
                params += f"&{key}={value}"
            params = params.strip("&")
        elif method == Method.POST:
            params = json.dumps(data, separators=(",", ":"))
        else:
            raise Exception("Method not allowed. Something is wrong with the code.")

        signature = base64.b64encode(hmac.new(
            self.secret.encode(),
            f"{timestamp}{str(method)}{path}{params}".encode(), # bytes from utf-8 string
            hashlib.sha256,
        ).digest())
        logger.debug(f"{timestamp}{str(method)}{path}{params}")
        headers = self.headers.copy()
        headers["LNM-ACCESS-TIMESTAMP"] = str(timestamp)
        headers["LNM-ACCESS-SIGNATURE"] = signature.decode()
        if method == Method.POST:
            headers["Content-Type"] = "application/json"
        logger.debug(f"{headers = }")
        return headers

    async def status(self) -> StatusResponse:
        headers = await self.get_request_headers(Method.GET, "/v2/user", {})
        try:
            r = await self.client.get(url=f"{self.endpoint}/v2/user", timeout=15, headers=headers)
            r.raise_for_status()
        except Exception as exc:
            logger.error(f"Failed to connect to {self.endpoint} due to: {exc}")
            return StatusResponse(
                error_message=f"Failed to connect to {self.endpoint} due to: {exc}",
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
        if "detail" in data:
            return StatusResponse(
                error_message=f"LNMarkets error: {data['detail']}", balance=0
            )

        if self.unit == Unit.usd:
            return StatusResponse(error_message=None, balance=data["synthetic_usd_balance"])
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
            # We do this trick to avoid messing it up.
            amount_usd = float(amount.to_float_string())
            amount_usd = int(amount_usd) if float(int(amount_usd)) == amount_usd else amount_usd
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
            r.raise_for_status()
        except Exception as e:
            logger.error("Error while creating invoice: "+str(e))
            return InvoiceResponse(
                ok=False,
                error_message="Error while creating invoice: "+str(e),
            )

        data = None
        try:
            data = r.json()
        except Exception:
            logger.error( f"Received invalid response from {self.endpoint}: {r.text}")
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
        if self.unit == Unit.usd:
            data["quote_id"] = quote.checking_id

        headers = await self.get_request_headers(Method.POST, path, data)
        try:
            r = await self.client.post(
                url=f"{self.endpoint}{path}",
                json=data,
                headers=headers,
                timeout=None,
            )
            r.raise_for_status()
        except Exception as e:
            logger.error(f"LNMarkets withdrawal unsuccessful: {str(e)}")
            return PaymentResponse(error_message=f"LNMarkets withdrawal unsuccessful: {str(e)}")

        try:
            data = r.json()
        except Exception:
            logger.error(f"LNMarkets withdrawal unsuccessful: {r.text}")
            return PaymentResponse(error_message=f"LNMarkets withdrawal unsuccessful: {r.text}")
        
        # payment_preimage = ??
        # no payment preimage by lnmarkets :(
        checking_id = data["id"]
        return PaymentResponse(
            ok=True,
            checking_id=checking_id,
            fee=Amount(unit=Unit.usd, amount=quote.fee_reserve),
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
            r.raise_for_status()
        except Exception as e:
            logger.error(f"get invoice status unsuccessful: {str(e)}")
            return PaymentStatus(paid=None)
        
        data = None
        try:
            data = r.json()
        except Exception:
            logger.error(f"get invoice status unsuccessful: {r.text}")
            return PaymentStatus(paid=None)
        return PaymentStatus(paid=data["success"])

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
            r.raise_for_status()
        except Exception as e:
            logger.error(f"getting invoice status unsuccessful: {str(e)}")
            return PaymentStatus(paid=None)

        try:
            data = r.json()
        except Exception:
            logger.error(f"getting invoice status unsuccessful: {r.text}")
            return PaymentStatus(paid=None)
        
        logger.debug(f"payment status: {data}")
        if not data["success"]:
            return PaymentStatus(paid=None)

        return PaymentStatus(
            paid=data["success"],
            fee=Amount(unit=Unit.sat, amount=int(data["fee"])),
        )

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        self.assert_unit_supported(Unit[melt_quote.unit])
        invoice_obj = decode(melt_quote.request)
        assert invoice_obj.amount_msat, "invoice has no amount."
        amount_msat = int(invoice_obj.amount_msat)
        fees_msat = fee_reserve(amount_msat)
        fees = Amount(unit=Unit.msat, amount=fees_msat)
        amount = Amount(unit=Unit.msat, amount=amount_msat)
        # SAT -- unfortunately, there is no way of asking the fee_reserve to lnmarkets beforehand in this case.
        if self.unit == Unit.sat:
            return PaymentQuoteResponse(
                checking_id=invoice_obj.payment_hash,
                fee=fees.to(self.unit, round="up"),
                amount=amount.to(self.unit, round="up"),
            )
        # sUSD
        else:
            # We get the current rate
            path = "/v2/futures/ticker"
            headers = await self.get_request_headers(Method.GET, path, {})

            # We let any eventual exception crash the request
            r = await self.client.get(f"{self.endpoint}{path}",
                headers=headers,
                timeout=None,
            )
            r.raise_for_status()
            
            data = r.json()
            price = data["bidPrice"] # BTC/USD
            price = float(price) / 10**8
            logger.debug(f"bid price: {price} sat/USD")
            amount_usd = round(float(amount.to(Unit.sat).amount) * price, 2)
            logger.debug(f"amount USD: {amount_usd}")

            # We request a quote to pay a precise amount of sats from the usd balance, then calculate
            # the usd amount and usd fee reserve
            data = {"amount": amount.to(Unit.sat).amount, "currency": "btc"}
            path = "/v2/user/withdraw/susd"
            headers = await self.get_request_headers(Method.POST, path, data)

            r = await self.client.post(f"{self.endpoint}{path}",
                json=data,
                headers=headers,
                timeout=None,
            )
            r.raise_for_status()

            # calculate fee based on returned sat `fee_reserve`
            data = r.json()
            fee_reserve_usd = round(float(data["fee_reserve"]) * price, 2)
            return PaymentQuoteResponse(
                checking_id=data["quote_id"],
                fee=Amount.from_float(fee_reserve_usd, self.unit),
                amount=Amount.from_float(amount_usd, self.unit)
            )

    async def paid_invoices_stream(self):
        raise NotImplementedError("paid_invoices_stream not implemented")