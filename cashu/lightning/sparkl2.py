import asyncio
import os
from typing import AsyncGenerator, Optional

import bolt11
import breez_sdk_spark
from loguru import logger

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


class _SdkEventListener(breez_sdk_spark.EventListener):
    def __init__(self, wallet: "SparkL2Wallet"):
        self.wallet = wallet

    async def on_event(self, event: breez_sdk_spark.SdkEvent):
        # We only care about incoming payments
        if isinstance(event, breez_sdk_spark.SdkEvent.PAYMENT_SUCCEEDED):
            payment = event.payment
            if not payment:
                return

            # Only track incoming payments
            if payment.payment_type == breez_sdk_spark.PaymentType.RECEIVE:
                # The payment.details will contain the invoice if it's a lightning payment
                # We extract the checking_id (payment hash)
                details = payment.details
                if details and details.is_lightning():
                    htlc = details.htlc_details
                    if htlc and htlc.payment_hash:
                        await self.wallet.payment_queue.put(htlc.payment_hash)
                # If it's a spark payment (on-chain/deposit/etc), we might not have a simple payment hash
                # but for bolt11 invoices created via this backend, it will be lightning.


class SparkL2Wallet(LightningBackend):
    """
    Spark L2 Wallet backend.
    Uses the official Breez Spark SDK for Python (`breez-sdk-spark`).
    """

    supported_units = {Unit.sat, Unit.msat}
    supports_mpp = False
    supports_incoming_payment_stream = True
    supports_description = True

    def __init__(self, unit: Unit, **kwargs):
        self.assert_unit_supported(unit)
        self.unit = unit
        self.sdk: Optional[breez_sdk_spark.BreezSdk] = None
        self.payment_queue: asyncio.Queue[str] = asyncio.Queue()
        self.listener: Optional[_SdkEventListener] = None

    def _get_total_fee_sats(self, payment_method: breez_sdk_spark.SendPaymentMethod) -> int:
        if payment_method.is_bolt11_invoice():
            pm = payment_method
            fee_sats = pm.lightning_fee_sats or 0
            spark_fee = pm.spark_transfer_fee_sats or 0
            return fee_sats + spark_fee
        elif payment_method.is_spark_invoice():
            pm = payment_method
            return int(pm.fee)
        elif payment_method.is_spark_address():
            pm = payment_method
            return int(pm.fee)
        elif payment_method.is_bitcoin_address():
            pm = payment_method
            fq = pm.fee_quote
            fees = []
            for speed in [fq.speed_fast, fq.speed_medium, fq.speed_slow]:
                if speed:
                    fees.append(speed.user_fee_sat + speed.l1_broadcast_fee_sat)
            return max(fees) if fees else 0
        else:
            return 0

    async def _ensure_sdk(self):
        if self.sdk is not None:
            return
            
        if not settings.mint_spark_mnemonic:
            raise Exception("MINT_SPARK_MNEMONIC is required to initialize SparkL2Wallet. Please set a 12, 15, 18, 21, or 24-word seed phrase in your environment.")

        # Initialize the Breez SDK
        seed = breez_sdk_spark.Seed.MNEMONIC(
            mnemonic=settings.mint_spark_mnemonic, 
            passphrase=None
        )
        
        network_str = getattr(settings, "mint_spark_network", "TESTNET").upper()
        if network_str == "MAINNET":
            network = breez_sdk_spark.Network.MAINNET
        elif network_str == "REGTEST":
            network = breez_sdk_spark.Network.REGTEST
        elif network_str == "SIGNET":
            network = breez_sdk_spark.Network.SIGNET
        else:
            network = breez_sdk_spark.Network.TESTNET
            
        config = breez_sdk_spark.default_config(network)
        if settings.mint_spark_api_key:
            config.api_key = settings.mint_spark_api_key

        # Use a safe storage directory specific to this mint
        storage_dir = os.path.join(settings.cashu_dir, "sparkl2_data")
        os.makedirs(storage_dir, exist_ok=True)

        try:
            self.sdk = await breez_sdk_spark.connect(
                request=breez_sdk_spark.ConnectRequest(
                    config=config, 
                    seed=seed, 
                    storage_dir=storage_dir
                )
            )
                
            self.listener = _SdkEventListener(self)
            await self.sdk.add_event_listener(self.listener)
            
            logger.info("Breez Spark SDK initialized successfully.")
            
        except Exception as e:
            logger.error(f"Failed to initialize Breez Spark SDK: {e}")
            raise Exception(f"Failed to initialize Breez Spark SDK: {e}")

    async def status(self) -> StatusResponse:
        try:
            await self._ensure_sdk()
            
            if not self.sdk:
                return StatusResponse(
                    error_message="Spark SDK not initialized",
                    balance=Amount(self.unit, 0),
                )
                
            req = breez_sdk_spark.GetInfoRequest(ensure_synced=False)
            info = await self.sdk.get_info(req)
                
            balance_sats = info.balance_sats
            balance = Amount(Unit.sat, balance_sats)
            if self.unit == Unit.msat:
                balance = Amount(Unit.msat, balance_sats * 1000)
            return StatusResponse(balance=balance)
        except Exception as e:
            return StatusResponse(
                error_message=f"Failed to get status from Spark SDK: {str(e)}",
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
        await self._ensure_sdk()
        
        amount_sats = amount.to(Unit.sat, round="up").amount
        
        if not self.sdk:
            raise Exception("SDK not initialized")
        
        try:
            # We want to create a bolt11 invoice
            req = breez_sdk_spark.ReceivePaymentRequest(
                payment_method=breez_sdk_spark.ReceivePaymentMethod.BOLT11_INVOICE(
                    description=(memo or "") if not description_hash else "",
                    amount_sats=amount_sats,
                    expiry_secs=None,
                    payment_hash=None
                )
            )
            
            res = await self.sdk.receive_payment(req)
                
            # The response contains the invoice string
            invoice = res.payment_request
            
            # The payment hash is our checking ID
            invoice_obj = bolt11.decode(invoice)
            
            return InvoiceResponse(
                ok=True,
                checking_id=invoice_obj.payment_hash,
                payment_request=invoice,
            )
        except Exception as e:
            logger.error(f"Failed to create invoice: {str(e)}")
            return InvoiceResponse(
                ok=False,
                error_message=f"Failed to create invoice: {str(e)}"
            )

    async def pay_invoice(
        self, quote: MeltQuote, fee_limit_msat: int
    ) -> PaymentResponse:
        await self._ensure_sdk()
        if not self.sdk:
            raise Exception("SDK not initialized")
            
        try:
            # The Spark SDK has prepare_send_payment -> send_payment flow
            prepare_req = breez_sdk_spark.PrepareSendPaymentRequest(
                payment_request=quote.request,
                amount=None, # Already in invoice
                fee_policy=None # Can pass fee limits here if supported
            )
            
            prepare_res = await self.sdk.prepare_send_payment(prepare_req)
                
            if prepare_res.payment_method.is_bitcoin_address():
                return PaymentResponse(
                    result=PaymentResult.FAILED,
                    error_message="On-chain bitcoin payments are not supported by this mint"
                )

            # Ensure fee is within limits
            total_fee_sats = self._get_total_fee_sats(prepare_res.payment_method)
            
            if total_fee_sats * 1000 > fee_limit_msat:
                return PaymentResponse(
                    result=PaymentResult.FAILED,
                    error_message=f"Fee estimate ({total_fee_sats} sats) exceeds limit ({fee_limit_msat // 1000} sats)"
                )
                
            send_req = breez_sdk_spark.SendPaymentRequest(
                prepare_response=prepare_res
            )
            
            send_res = await self.sdk.send_payment(send_req)
                
            payment = send_res.payment
            fee_amount = None
            if payment.fees is not None:
                if self.unit == Unit.msat:
                    fee_amount = Amount(Unit.msat, payment.fees * 1000)
                else:
                    fee_amount = Amount(Unit.sat, payment.fees)

            preimage = None
            if payment.details and payment.details.is_lightning():
                htlc = payment.details.htlc_details
                if htlc:
                    preimage = htlc.preimage
                    
            if payment.status == breez_sdk_spark.PaymentStatus.COMPLETED:
                result = PaymentResult.SETTLED
            elif payment.status == breez_sdk_spark.PaymentStatus.FAILED:
                result = PaymentResult.FAILED
            else:
                result = PaymentResult.PENDING

            return PaymentResponse(
                result=result,
                checking_id=payment.id,
                fee=fee_amount,
                preimage=preimage,
            )
        except Exception as e:
            return PaymentResponse(
                result=PaymentResult.PENDING,
                error_message=f"Payment failed or unknown: {str(e)}"
            )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        # checking_id is the payment hash
        await self._ensure_sdk()
        if not self.sdk:
            raise Exception("SDK not initialized")
            
        try:
            # We must list payments and find the receive payment by hash
            # Breez SDK provides list_payments but it might be inefficient.
            # However, for Spark L2 it's local.
            req = breez_sdk_spark.ListPaymentsRequest(
                type_filter=None,
                status_filter=None,
                asset_filter=None,
            )
            
            res = await self.sdk.list_payments(req)
                
            for p in res.payments:
                if p.payment_type == breez_sdk_spark.PaymentType.RECEIVE:
                    if p.details and p.details.is_lightning():
                        htlc = p.details.htlc_details
                        if htlc and htlc.payment_hash == checking_id:
                            if p.status == breez_sdk_spark.PaymentStatus.COMPLETED:
                                return PaymentStatus(result=PaymentResult.SETTLED)
                            elif p.status == breez_sdk_spark.PaymentStatus.FAILED:
                                return PaymentStatus(result=PaymentResult.FAILED)
                                
            # If not found in recent, assume pending
            return PaymentStatus(result=PaymentResult.PENDING)
                
        except Exception as e:
            return PaymentStatus(result=PaymentResult.UNKNOWN, error_message=str(e))

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        await self._ensure_sdk()
        if not self.sdk:
            raise Exception("SDK not initialized")
            
        try:
            req = breez_sdk_spark.GetPaymentRequest(payment_id=checking_id)
            res = await self.sdk.get_payment(req)
                
            if not res or not res.payment:
                return PaymentStatus(result=PaymentResult.UNKNOWN, error_message="Payment not found")
                
            payment = res.payment
            fee_sats = payment.fees
            fee_amount = None
            if fee_sats is not None:
                fee_amount = Amount(Unit.sat, fee_sats)
                if self.unit == Unit.msat:
                    fee_amount = Amount(Unit.msat, fee_sats * 1000)

            preimage = None
            if payment.details and payment.details.is_lightning():
                htlc = payment.details.htlc_details
                if htlc:
                    preimage = htlc.preimage

            if payment.status == breez_sdk_spark.PaymentStatus.COMPLETED:
                return PaymentStatus(
                    result=PaymentResult.SETTLED,
                    preimage=preimage,
                    fee=fee_amount
                )
            elif payment.status == breez_sdk_spark.PaymentStatus.FAILED:
                return PaymentStatus(result=PaymentResult.FAILED)
            else:
                return PaymentStatus(result=PaymentResult.PENDING)
                
        except Exception as e:
            return PaymentStatus(result=PaymentResult.UNKNOWN, error_message=str(e))

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        await self._ensure_sdk()
        if not self.sdk:
            raise Exception("SDK not initialized")
            
        try:
            prepare_req = breez_sdk_spark.PrepareSendPaymentRequest(
                payment_request=melt_quote.request,
                amount=None, 
                fee_policy=None
            )
            
            prepare_res = await self.sdk.prepare_send_payment(prepare_req)
            
            if prepare_res.payment_method.is_bitcoin_address():
                raise Exception("On-chain bitcoin payments are not supported by this mint")
            
            total_fee_sats = self._get_total_fee_sats(prepare_res.payment_method)
            
            fee_amount = Amount(Unit.sat, total_fee_sats)
            if self.unit == Unit.msat:
                fee_amount = Amount(Unit.msat, total_fee_sats * 1000)
                
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
        await self._ensure_sdk()
        while True:
            checking_id = await self.payment_queue.get()
            yield checking_id
