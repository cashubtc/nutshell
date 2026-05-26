import asyncio
import os
from typing import Any, AsyncGenerator, Dict, Optional

import bolt11
import httpx

from cashu.core.base import Amount, MeltQuote, Unit
from cashu.core.models import PostMeltQuoteRequest
from cashu.core.settings import settings
from cashu.lightning.base import (
    InvoiceResponse,
    LightningBackend,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    StatusResponse,
)


class SparkL2Wallet(LightningBackend):
    """
    Spark L2 Wallet backend.
    Communicates with the local Node.js bridge which wraps the Spark TypeScript SDK.
    """

    supported_units = {Unit.sat, Unit.msat}
    supports_mpp = False
    supports_incoming_payment_stream = True
    supports_description = True

    def __init__(self, unit: Unit, **kwargs):
        self.assert_unit_supported(unit)
        self.unit = unit
        
        # Read from config or defaults
        host = getattr(settings, "mint_spark_bridge_host", "127.0.0.1")
        port = getattr(settings, "mint_spark_bridge_port", 8426)
        self.base_url = f"http://{host}:{port}"
        
        self.client = httpx.AsyncClient(base_url=self.base_url)

    async def _ensure_bridge_running(self):
        try:
            await self.client.get("/status", timeout=1)
            # If we get a response (even 400 not initialized), it's running.
        except httpx.RequestError:
            import subprocess
            bridge_dir = os.path.join(os.path.dirname(__file__), "sparkl2_bridge")
            # Try to start it
            try:
                subprocess.Popen(["npm", "start"], cwd=bridge_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                await asyncio.sleep(3) # Wait for it to start
            except Exception as e:
                print(f"Warning: Failed to start Spark L2 bridge automatically: {e}")

    async def status(self) -> StatusResponse:
        await self._ensure_bridge_running()
        try:
            # Initialize the bridge if necessary
            if settings.mint_private_key:
                await self.client.post("/init", json={
                    "seed": settings.mint_private_key,
                    "network": getattr(settings, "mint_spark_network", "TESTNET")
                }, timeout=15)
            
            r = await self.client.get("/status", timeout=5)
            r.raise_for_status()
            data = r.json()
            balance_sats = data.get("balanceSats", 0)
            balance = Amount(Unit.sat, balance_sats)
            if self.unit == Unit.msat:
                balance = Amount(Unit.msat, balance_sats * 1000)
            return StatusResponse(balance=balance)
        except Exception as e:
            return StatusResponse(
                error_message=f"Failed to connect to Spark bridge: {str(e)}",
                balance=Amount(self.unit, 0),
            )

    async def create_invoice(
        self,
        amount: Amount,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        **kwargs,
    ) -> InvoiceResponse:
        self.assert_unit_supported(amount.unit)
        amount_sats = amount.to(Unit.sat, round="up").amount
        
        payload: Dict[str, Any] = {
            "amountSats": amount_sats,
            "memo": memo,
        }
        if description_hash:
            payload["descriptionHash"] = description_hash.hex()
            # Spark SDK doesn't allow both memo and descriptionHash
            payload.pop("memo", None)

        try:
            r = await self.client.post("/invoice", json=payload, timeout=10)
            r.raise_for_status()
            data = r.json()
            return InvoiceResponse(
                ok=True,
                checking_id=data["id"],
                payment_request=data["invoice"],
            )
        except Exception as e:
            return InvoiceResponse(
                ok=False,
                error_message=f"Failed to create invoice: {str(e)}"
            )

    async def pay_invoice(
        self, quote: MeltQuote, fee_limit_msat: int
    ) -> PaymentResponse:
        try:
            payload = {
                "invoice": quote.request,
                "maxFeeSats": fee_limit_msat // 1000
            }
            r = await self.client.post("/pay", json=payload, timeout=30)
            r.raise_for_status()
            data = r.json()
            
            return PaymentResponse(
                result=PaymentResult.PENDING,
                checking_id=data["id"],
            )
        except Exception as e:
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message=f"Payment failed: {str(e)}"
            )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        try:
            r = await self.client.get(f"/invoice/status/{checking_id}", timeout=5)
            r.raise_for_status()
            data = r.json()
            
            status_str = data.get("status", "")
            if status_str in ("LIGHTNING_RECEIVE_SUCCEEDED", "CLAIMED", "PAID"):
                return PaymentStatus(result=PaymentResult.SETTLED)
            elif status_str in ("EXPIRED", "FAILED"):
                return PaymentStatus(result=PaymentResult.FAILED)
            else:
                return PaymentStatus(result=PaymentResult.PENDING)
                
        except Exception as e:
            return PaymentStatus(result=PaymentResult.UNKNOWN, error_message=str(e))

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        try:
            r = await self.client.get(f"/pay/status/{checking_id}", timeout=5)
            r.raise_for_status()
            data = r.json()
            
            status_str = data.get("status", "")
            preimage = data.get("preimage")
            fee_sats = data.get("feeSats")
            
            fee_amount = None
            if fee_sats is not None:
                fee_amount = Amount(Unit.sat, fee_sats)
                if self.unit == Unit.msat:
                    fee_amount = Amount(Unit.msat, fee_sats * 1000)

            if status_str in ("LIGHTNING_PAYMENT_SUCCEEDED", "TRANSFER_COMPLETED"):
                return PaymentStatus(
                    result=PaymentResult.SETTLED,
                    preimage=preimage,
                    fee=fee_amount
                )
            elif status_str in ("LIGHTNING_PAYMENT_FAILED", "TRANSFER_FAILED", "USER_SWAP_RETURN_FAILED", "PREIMAGE_PROVIDING_FAILED"):
                return PaymentStatus(result=PaymentResult.FAILED)
            else:
                return PaymentStatus(result=PaymentResult.PENDING)
                
        except Exception as e:
            return PaymentStatus(result=PaymentResult.UNKNOWN, error_message=str(e))

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        try:
            payload = {"invoice": melt_quote.request}
            r = await self.client.post("/pay/quote", json=payload, timeout=5)
            r.raise_for_status()
            data = r.json()
            
            fee_sats = data.get("feeSats", 0)
            fee_amount = Amount(Unit.sat, fee_sats)
            if self.unit == Unit.msat:
                fee_amount = Amount(Unit.msat, fee_sats * 1000)
                
            # Normally parsed from invoice, but we need amount.
            # Usually the Mint handles invoice parsing via decode_invoice. 
            # So amount is handled outside, but get_payment_quote requires checking_id and amount
            
            invoice_obj = bolt11.decode(melt_quote.request)
            amount_msat = int(invoice_obj.amount_msat) if invoice_obj.amount_msat else 0
            amount_unit = Amount(Unit.msat, amount_msat)
            
            if self.unit == Unit.sat:
                fee_amount = Amount(Unit.sat, fee_amount.to(Unit.sat, round="up").amount)
                amount_unit = Amount(Unit.sat, amount_unit.to(Unit.sat, round="up").amount)

            return PaymentQuoteResponse(
                checking_id=invoice_obj.payment_hash,
                fee=fee_amount,
                amount=amount_unit,
            )
        except Exception as e:
            raise Exception(f"Failed to get payment quote: {str(e)}")

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        while True:
            try:
                async with self.client.stream("GET", "/stream", timeout=None) as r:
                    async for line in r.aiter_lines():
                        if line.startswith("data:"):
                            try:
                                import json
                                data = json.loads(line[5:].strip())
                                # Assuming the bridge emits the full event object
                                # The event structure might have 'id' or 'transferId'
                                checking_id = data.get("id") or data.get("transferId") or data.get("paymentHash")
                                if checking_id:
                                    yield checking_id
                            except Exception:
                                pass
            except Exception:
                await asyncio.sleep(5)
