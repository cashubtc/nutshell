import asyncio
import json
from typing import AsyncGenerator, Optional

import httpx
from bolt11 import decode
from loguru import logger

from ..core.base import Amount, MeltQuote, Unit
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


class RestWallet(LightningBackend):
    """REST Lightning Wallet

    This wallet communicates with a custom REST API server
    for Lightning Network operations.
    """

    supported_units = {Unit.sat, Unit.msat, Unit.usd, Unit.eur}
    unit = Unit.sat
    supports_incoming_payment_stream: bool = True
    supports_description: bool = True

    def __init__(self, unit: Unit = Unit.sat, **kwargs):
        self.assert_unit_supported(unit)
        self.unit = unit

        # Get REST service endpoint from settings
        self.endpoint = settings.mint_rest_endpoint
        if not self.endpoint:
            raise Exception("MINT_REST_ENDPOINT is not configured")

        # Remove trailing slash if present
        self.endpoint = self.endpoint.rstrip("/")

        # Setup HTTP client with optional API key authentication
        headers = {"Content-Type": "application/json"}
        if settings.mint_rest_api_key:
            headers["Authorization"] = f"Bearer {settings.mint_rest_api_key}"

        self.client = httpx.AsyncClient(
            verify=False,  # For development with self-signed certificates
            headers=headers,
            timeout=httpx.Timeout(60.0)  # 60 second timeout for Lightning operations
        )

    async def status(self) -> StatusResponse:
        """Get wallet status and balance"""
        try:
            r = await self.client.get(f"{self.endpoint}/api/lightning/status")
            r.raise_for_status()
            data = r.json()

            return StatusResponse(
                error_message=data.get("error_message"),
                balance=Amount(self.unit, data["balance_amount"])
            )
        except httpx.TimeoutException:
            return StatusResponse(
                error_message="Timeout connecting to REST wallet service",
                balance=Amount(self.unit, 0)
            )
        except Exception as exc:
            logger.error(f"Failed to get wallet status: {exc}")
            return StatusResponse(
                error_message=f"Failed to connect to REST wallet: {exc}",
                balance=Amount(self.unit, 0)
            )

    async def create_invoice(
        self,
        amount: Amount,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[bytes] = None,
        **kwargs,
    ) -> InvoiceResponse:
        """Create a Lightning invoice"""
        self.assert_unit_supported(amount.unit)

        payload = {
            "amount": amount.amount,
            "unit": amount.unit.name,
            "memo": memo,
            "description_hash": description_hash.hex() if description_hash else None,
            "unhashed_description": unhashed_description.hex() if unhashed_description else None,
        }

        # Add optional parameters
        if kwargs.get("expiry"):
            payload["expiry"] = kwargs["expiry"]

        try:
            r = await self.client.post(
                f"{self.endpoint}/api/lightning/invoice",
                json=payload
            )
            r.raise_for_status()
            data = r.json()

            return InvoiceResponse(
                ok=data["ok"],
                checking_id=data.get("checking_id"),
                payment_request=data.get("payment_request"),
                error_message=data.get("error_message")
            )
        except Exception as exc:
            logger.error(f"Failed to create invoice: {exc}")
            return InvoiceResponse(
                ok=False,
                error_message=f"Failed to create invoice: {exc}"
            )

    async def pay_invoice(
        self, quote: MeltQuote, fee_limit_msat: int
    ) -> PaymentResponse:
        """Pay a Lightning invoice"""
        payload = {
            "bolt11": quote.request,
            "fee_limit_msat": fee_limit_msat,
            "amount": quote.amount,
            "unit": quote.unit
        }

        try:
            r = await self.client.post(
                f"{self.endpoint}/api/lightning/pay",
                json=payload,
                timeout=None  # Lightning payments can take time
            )
            r.raise_for_status()
            data = r.json()

            # Map REST response to Python enum
            result_map = {
                "SETTLED": PaymentResult.SETTLED,
                "FAILED": PaymentResult.FAILED,
                "PENDING": PaymentResult.PENDING,
                "UNKNOWN": PaymentResult.UNKNOWN
            }

            return PaymentResponse(
                result=result_map.get(data["result"], PaymentResult.UNKNOWN),
                checking_id=data.get("checking_id"),
                fee=Amount(unit=Unit[data["fee_unit"]], amount=data["fee_amount"]) if data.get("fee_amount") else None,
                preimage=data.get("preimage"),
                error_message=data.get("error_message")
            )
        except Exception as exc:
            logger.error(f"Failed to pay invoice: {exc}")
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message=f"Failed to pay invoice: {exc}"
            )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        """Get status of a created invoice"""
        try:
            r = await self.client.get(
                f"{self.endpoint}/api/lightning/invoice/{checking_id}/status"
            )
            r.raise_for_status()
            data = r.json()

            result_map = {
                "SETTLED": PaymentResult.SETTLED,
                "FAILED": PaymentResult.FAILED,
                "PENDING": PaymentResult.PENDING,
                "UNKNOWN": PaymentResult.UNKNOWN
            }

            return PaymentStatus(
                result=result_map.get(data["result"], PaymentResult.UNKNOWN),
                fee=Amount(unit=Unit[data["fee_unit"]], amount=data["fee_amount"]) if data.get("fee_amount") else None,
                preimage=data.get("preimage"),
                error_message=data.get("error_message")
            )
        except Exception as exc:
            logger.error(f"Failed to get invoice status: {exc}")
            return PaymentStatus(
                result=PaymentResult.UNKNOWN,
                error_message=f"Failed to get invoice status: {exc}"
            )

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        """Get status of an outgoing payment"""
        try:
            r = await self.client.get(
                f"{self.endpoint}/api/lightning/payment/{checking_id}/status"
            )
            r.raise_for_status()
            data = r.json()

            result_map = {
                "SETTLED": PaymentResult.SETTLED,
                "FAILED": PaymentResult.FAILED,
                "PENDING": PaymentResult.PENDING,
                "UNKNOWN": PaymentResult.UNKNOWN
            }

            return PaymentStatus(
                result=result_map.get(data["result"], PaymentResult.UNKNOWN),
                fee=Amount(unit=Unit[data["fee_unit"]], amount=data["fee_amount"]) if data.get("fee_amount") else None,
                preimage=data.get("preimage"),
                error_message=data.get("error_message")
            )
        except Exception as exc:
            logger.error(f"Failed to get payment status: {exc}")
            return PaymentStatus(
                result=PaymentResult.UNKNOWN,
                error_message=f"Failed to get payment status: {exc}"
            )

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        """Get a quote for paying an invoice"""
        payload = {
            "bolt11": melt_quote.request,
            "unit": melt_quote.unit if hasattr(melt_quote, 'unit') else self.unit.name,
            "mpp_amount": melt_quote.mpp_amount if melt_quote.is_mpp else None
        }

        try:
            r = await self.client.post(
                f"{self.endpoint}/api/lightning/quote",
                json=payload
            )
            r.raise_for_status()
            data = r.json()

            return PaymentQuoteResponse(
                checking_id=data["checking_id"],
                amount=Amount(unit=Unit[data["amount_unit"]], amount=data["amount"]),
                fee=Amount(unit=Unit[data["fee_unit"]], amount=data["fee"])
            )
        except Exception as exc:
            logger.error(f"Failed to get payment quote: {exc}")
            # Fallback: decode invoice locally for basic quote
            invoice_obj = decode(melt_quote.request)
            assert invoice_obj.amount_msat, "invoice has no amount."
            amount_msat = int(invoice_obj.amount_msat)

            # Simple fee calculation as fallback
            fee_msat = max(1000, amount_msat // 1000)  # 0.1% fee minimum 1 sat

            return PaymentQuoteResponse(
                checking_id=invoice_obj.payment_hash,
                amount=Amount(unit=Unit.msat, amount=amount_msat).to(self.unit, round="up"),
                fee=Amount(unit=Unit.msat, amount=fee_msat).to(self.unit, round="up")
            )

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        """Stream of paid invoice payment hashes"""
        retry_delay = 0
        max_retry_delay = settings.mint_retry_exponential_backoff_max_delay

        while True:
            try:
                # Use Server-Sent Events (SSE) for real-time updates
                headers = self.client.headers.copy()
                headers.update({
                    "Accept": "text/event-stream",
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive"
                })

                async with self.client.stream(
                    "GET",
                    f"{self.endpoint}/api/lightning/invoices/stream",
                    headers=headers,
                    timeout=None
                ) as response:
                    response.raise_for_status()
                    retry_delay = 0  # Reset on successful connection

                    async for line in response.aiter_lines():
                        if line.startswith("data:"):
                            try:
                                data_str = line[5:]  # Remove "data:" prefix
                                if data_str.strip():
                                    data = json.loads(data_str)
                                    if data.get("event") == "invoice_paid":
                                        payment_hash = data.get("payment_hash")
                                        if payment_hash:
                                            yield payment_hash
                            except json.JSONDecodeError:
                                continue
                            except Exception as e:
                                logger.warning(f"Error processing SSE data: {e}")
                                continue

            except Exception as exc:
                logger.error(
                    f"Lost connection to REST wallet invoice stream: '{exc}', retrying in {retry_delay} seconds"
                )
                await asyncio.sleep(retry_delay)

                # Exponential backoff
                retry_delay = max(
                    settings.mint_retry_exponential_backoff_base_delay,
                    min(retry_delay * 2, max_retry_delay)
                )