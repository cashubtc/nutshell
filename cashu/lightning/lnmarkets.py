import hashlib
import hmac
import json
from base64 import b64encode
from typing import AsyncGenerator, Optional

import httpx
from bolt11 import Bolt11Exception, decode
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
)


class LNMarketsDepositResponse(BaseModel):
    depositId: str
    paymentRequest: str

class LNMarketsDeposit(BaseModel):
    id: str
    createdAt: str
    amount: int
    paymentHash: str
    settledAt: Optional[str] = None
    comment: Optional[str] = None

class LNMarketsWithdrawal(BaseModel):
    id: str
    amount: int
    paymentHash: str
    status: str
    fee: int
    createdAt: str

class LNMarketsWithdrawResponse(BaseModel):
    id: str
    paymentHash: str
    amount: int
    maxFees: int

PAYMENT_RESULT_MAP = {
    "PENDING": PaymentResult.PENDING,
    "COMPLETED": PaymentResult.SETTLED,
    "FAILED": PaymentResult.FAILED,
}

INVOICE_RESULT_MAP = {
    "processing": PaymentResult.PENDING,
    "processed": PaymentResult.SETTLED,
    "failed": PaymentResult.FAILED,
}

class LNMarketsWallet(LightningBackend):
    """
    LN Markets Lightning Backend

    API Endpoints:
    - Production: https://api.lnmarkets.com/v3
    - Testnet: https://api.testnet4.lnmarkets.com/v3

    Limitations:
    - Minimum Lightning invoice/payment: 1,000 sats
    - Maximum Lightning invoice/payment: 10,000,000 sats
    """

    MIN_LIGHTNING_SATS = 1_000
    MAX_LIGHTNING_SATS = 10_000_000

    supported_units = {Unit.sat}
    supports_description: bool = False
    currency_map = {Unit.sat: "BTC"}


    def __init__(self, unit: Unit, **kwargs):
        self.assert_unit_supported(unit)
        self.unit = unit

        self.endpoint = settings.mint_lnmarkets_endpoint
        self.api_key = settings.mint_lnmarkets_key
        self.api_secret = settings.mint_lnmarkets_secret
        self.api_passphrase = settings.mint_lnmarkets_passphrase

        self.currency = self.currency_map[self.unit]

        self.client = httpx.AsyncClient(
            verify=not settings.debug,
            timeout=30.0,
        )

    def _generate_signature(self, timestamp: str, method: str, path: str, data: str = "") -> str:
        payload = f"{timestamp}{method.lower()}{path}{data}"

        hashed = hmac.new(
            bytes(self.api_secret, 'utf-8'),
            bytes(payload, 'utf-8'),
            hashlib.sha256
        ).digest()

        return b64encode(hashed).decode('utf-8')

    def _get_headers(self, method: str, path: str, data: str = "") -> dict:
      from datetime import datetime

      timestamp = str(int(datetime.now().timestamp() * 1000))

      signature = self._generate_signature(timestamp, method, path, data)

      return {
          "Content-Type": "application/json",
          "LNM-ACCESS-KEY": self.api_key,
          "LNM-ACCESS-PASSPHRASE": self.api_passphrase,
          "LNM-ACCESS-TIMESTAMP": timestamp,
          "LNM-ACCESS-SIGNATURE": signature,
      }

    async def status(self) -> StatusResponse:
        path = "/account"

        try:
            headers = self._get_headers("GET", f"/v3{path}", "")

            r = await self.client.get(
            url=f"{self.endpoint}{path}",
            headers=headers,
            timeout=15
            )
            r.raise_for_status()

        except Exception as exc:
            return StatusResponse(
                error_message=f"Failed to connect to {self.endpoint} due to: {exc}",
                balance=Amount(self.unit, 0),
            )

        try:
            data = r.json()
        except Exception:
            return StatusResponse(
                error_message=(
                    f"Failed to parse response from {self.endpoint}, got: '{r.text[:200]}...'"
                ),
                balance=Amount(self.unit, 0),
            )

        try:
            if self.unit == Unit.sat:
       
                balance_value = data["balance"]
                return StatusResponse(
                    error_message=None,
                    balance=Amount(self.unit, balance_value),
                )
            else:
                return StatusResponse(
                    error_message=f"Unsupported unit: {self.unit}",
                    balance=Amount(self.unit, 0),
                )
        except KeyError as e:
            return StatusResponse(
                error_message=f"Missing field in response: {e}",
                balance=Amount(self.unit, 0),
            )


    async def create_invoice(
        self,
        amount: Amount,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[bytes] = None,
    ) -> InvoiceResponse:
        self.assert_unit_supported(amount.unit)

        amount_sats = amount.amount

        if amount_sats < self.MIN_LIGHTNING_SATS:
            return InvoiceResponse(
                ok=False,
                error_message=f"Amount {amount_sats} sats is below minimum {self.MIN_LIGHTNING_SATS} sats"
            )
        if amount_sats > self.MAX_LIGHTNING_SATS:
            return InvoiceResponse(
                ok=False,
                error_message=f"Amount {amount_sats} sats exceeds maximum {self.MAX_LIGHTNING_SATS} sats"
            )

        path = "/account/deposit/lightning"
        payload = {
            "amount": amount_sats,
            "comment": memo or "Cashu deposit"
        }

        if description_hash:
            payload["descriptionHash"] = description_hash.hex()

        data = json.dumps(payload, separators=(',', ':'), sort_keys=True)
        headers = self._get_headers("POST", f"/v3{path}", data)

        try:
            r = await self.client.post(
                url=f"{self.endpoint}{path}",
                content=data,
                headers=headers,
                timeout=30
            )
            r.raise_for_status()

            deposit = LNMarketsDepositResponse.parse_obj(r.json())

            return InvoiceResponse(
                ok=True,
                checking_id=deposit.depositId,
                payment_request=deposit.paymentRequest
            )

        except Exception as e:
            error_msg = str(e)
            try:
                if hasattr(e, 'response') and hasattr(e.response, 'json'):
                    error_data = e.response.json()
                    error_msg = error_data.get("message", str(e))
            except Exception:
                pass

            return InvoiceResponse(
                ok=False,
                error_message=f"Failed to create invoice: {error_msg}"
            )

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:

        try:
            invoice_obj = decode(melt_quote.request)

            if invoice_obj.amount_msat is None:
                raise Exception("Invoice has no amount")

            amount_msat = int(invoice_obj.amount_msat)
            amount_sats = amount_msat // 1000

            if amount_sats < self.MIN_LIGHTNING_SATS:
                logger.warning(
                    f"Amount {amount_sats} sats is below minimum {self.MIN_LIGHTNING_SATS} sats for Lightning payments."
                )
                raise Exception(
                    f"Amount must be {self.MIN_LIGHTNING_SATS} sats or more for Lightning payments."
                )

            fees_msat = fee_reserve(amount_msat)

            return PaymentQuoteResponse(
                checking_id=invoice_obj.payment_hash,
                amount=Amount(Unit.msat, amount_msat).to(self.unit, round="up"),
                fee=Amount(Unit.msat, fees_msat).to(self.unit, round="up"),
            )

        except Bolt11Exception as e:
            raise Exception(f"Failed to decode invoice: {str(e)}")
        except Exception as e:
            raise Exception(f"Failed to get payment quote: {str(e)}")

    async def pay_invoice(self, quote: MeltQuote, fee_limit_msat: int) -> PaymentResponse:
        path = "/account/withdraw/lightning"
        payload = {
            "invoice": quote.request
        }

        data = json.dumps(payload, separators=(',', ':'), sort_keys=True)
        headers = self._get_headers("POST", f"/v3{path}", data)

        try:
            r = await self.client.post(
                url=f"{self.endpoint}{path}",
                content=data,
                headers=headers,
                timeout=30
            )
            r.raise_for_status()

            withdraw = LNMarketsWithdrawResponse.parse_obj(r.json())
            logger.info(f"LN Markets withdrawal initiated: {withdraw.id}")

            return PaymentResponse(
                result=PaymentResult.PENDING,
                checking_id=withdraw.id,
                fee=Amount(self.unit, withdraw.maxFees),
                preimage=None
            )

        except httpx.HTTPStatusError as e:
            error_msg = str(e)
            error_code = None

            try:
                if hasattr(e, 'response') and hasattr(e.response, 'json'):
                    error_data = e.response.json()
                    error_msg = error_data.get("message", str(e))
                    error_code = error_data.get("code")

                    logger.warning(f"LN Markets payment failed: {error_msg} (code: {error_code})")

                    if "circular" in error_msg.lower() or "yourself" in error_msg.lower():
                        return PaymentResponse(
                            result=PaymentResult.FAILED,
                            error_message="Cannot pay to another LN Markets account via invoice"
                        )
            except Exception:
                pass

            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message=f"Failed to initiate payment: {error_msg}"
            )

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Unexpected error in pay_invoice: {error_msg}")
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message=f"Failed to initiate payment: {error_msg}"
            )


    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        path = "/account/deposits/lightning"

        try:
            headers = self._get_headers("GET", f"/v3{path}", "")

            r = await self.client.get(
                url=f"{self.endpoint}{path}",
                headers=headers,
                timeout=15
            )
            r.raise_for_status()

            deposits_data = r.json()

            for deposit_data in deposits_data:
                deposit = LNMarketsDeposit.parse_obj(deposit_data)

                if deposit.id == checking_id:
                    if deposit.settledAt is not None:
                        return PaymentStatus(result=PaymentResult.SETTLED)
                    else:
                        return PaymentStatus(result=PaymentResult.PENDING)

            return PaymentStatus(result=PaymentResult.PENDING)

        except Exception as e:
            return PaymentStatus(
                result=PaymentResult.UNKNOWN,
                error_message=f"Failed to get invoice status: {str(e)}"
            )

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        logger.debug(f"Checking payment status for: {checking_id}")
        path = "/account/withdrawals/lightning"

        try:
            headers = self._get_headers("GET", f"/v3{path}", "")

            r = await self.client.get(
                url=f"{self.endpoint}{path}",
                headers=headers,
                timeout=15
            )
            r.raise_for_status()

            withdrawals_data = r.json()

            for withdrawal_data in withdrawals_data:
                withdrawal = LNMarketsWithdrawal.parse_obj(withdrawal_data)

                if withdrawal.id == checking_id:
                    logger.info(f"Found withdrawal {checking_id} with status: {withdrawal.status}")
                    if withdrawal.status == "processed":
                        return PaymentStatus(
                            result=PaymentResult.SETTLED,
                            fee=Amount(self.unit, withdrawal.fee) if withdrawal.fee else None
                        )
                    elif withdrawal.status == "processing":
                        return PaymentStatus(result=PaymentResult.PENDING)
                    elif withdrawal.status == "failed":
                        return PaymentStatus(
                            result=PaymentResult.FAILED,
                            error_message="Withdrawal failed"
                        )
                    else:
                        return PaymentStatus(
                            result=PaymentResult.UNKNOWN,
                            error_message=f"Unknown status: {withdrawal.status}"
                        )

            logger.warning(f"Payment {checking_id} not found in LN Markets withdrawals")
            return PaymentStatus(
                result=PaymentResult.UNKNOWN,
                error_message=f"Payment {checking_id} not found"
            )

        except Exception as e:
            logger.error(f"Error checking payment status: {str(e)}")
            return PaymentStatus(
                result=PaymentResult.UNKNOWN,
                error_message=f"Failed to get payment status: {str(e)}"
            )


    def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        raise NotImplementedError("paid_invoices_stream not implemented")
