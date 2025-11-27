from __future__ import annotations

import asyncio
import inspect
from typing import AsyncGenerator, Optional

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
    PaymentResult,
    PaymentStatus,
    StatusResponse,
    Unsupported,
)

try:
    from breez_sdk_spark import (
        BreezSdk,
        ConnectRequest,
        EventListener,
        GetInfoRequest,
        ListPaymentsRequest,
        Network,
        PaymentMethod,
        PaymentType,
        PrepareSendPaymentRequest,
        ReceivePaymentMethod,
        ReceivePaymentRequest,
        SdkEvent,
        Seed,
        SendPaymentOptions,
        SendPaymentRequest,
        connect,
        default_config,
    )
    from breez_sdk_spark import (
        PaymentStatus as SparkPaymentStatus,
    )
    from breez_sdk_spark import breez_sdk_spark as spark_bindings
except ImportError as exc:  # pragma: no cover - optional dependency
    logger.warning("Breez Spark SDK not available - Spark backend disabled: %s", exc)
    BreezSdk = None  # type: ignore[assignment]
    EventListener = object  # type: ignore[assignment]
    PaymentMethod = None
    PaymentType = None
    SparkPaymentStatus = None
    spark_bindings = None


def _register_sdk_event_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Inform the Spark SDK which asyncio loop to talk to."""
    if spark_bindings is None:  # pragma: no cover - SDK missing
        return
    try:
        spark_bindings._uniffi_get_event_loop = lambda: loop
    except Exception as exc:  # pragma: no cover - defensive measure
        logger.debug(f"Could not patch Spark SDK event loop: {exc}")


def _extract_invoice_id(payment) -> Optional[str]:
    """Normalize the identifier reported by the SDK."""
    details = getattr(payment, "details", None)
    payment_hash = getattr(payment, "payment_hash", None)
    if payment_hash:
        return str(payment_hash).lower()

    if details:
        details_hash = getattr(details, "payment_hash", None)
        if details_hash:
            return str(details_hash).lower()

        invoice = getattr(details, "invoice", None) or getattr(
            getattr(details, "bolt11_invoice", None), "bolt11", None
        )
        if invoice:
            try:
                invoice_obj = decode(invoice)
                if invoice_obj.payment_hash:
                    return invoice_obj.payment_hash.lower()
            except Exception:
                return invoice.lower()

    return None


def _payment_fee_sats(payment) -> Optional[int]:
    for attr in ("fee_sats", "fees", "fee"):
        fee = getattr(payment, attr, None)
        if fee is not None:
            try:
                return max(int(fee), 0)
            except (TypeError, ValueError):
                try:
                    return max(int(str(fee)), 0)
                except (TypeError, ValueError):
                    continue

    details = getattr(payment, "details", None)
    if details and hasattr(details, "fees"):
        try:
            return max(int(details.fees), 0)
        except (TypeError, ValueError):
            pass
    return None


def _payment_preimage(payment) -> Optional[str]:
    preimage = getattr(payment, "preimage", None)
    if preimage:
        return preimage
    details = getattr(payment, "details", None)
    if details and hasattr(details, "preimage"):
        return getattr(details, "preimage") or None
    return None


def _is_lightning_payment(payment) -> bool:
    method = getattr(payment, "method", None)
    lightning_method = getattr(PaymentMethod, "LIGHTNING", None) if PaymentMethod else None
    if lightning_method is None or method is None:
        return True
    return method == lightning_method


SPARK_PAYMENT_RESULT_MAP = {}
if SparkPaymentStatus is not None:
    SPARK_PAYMENT_RESULT_MAP = {
        SparkPaymentStatus.COMPLETED: PaymentResult.SETTLED,
        getattr(SparkPaymentStatus, "SETTLED", SparkPaymentStatus.COMPLETED): PaymentResult.SETTLED,
        SparkPaymentStatus.FAILED: PaymentResult.FAILED,
        SparkPaymentStatus.PENDING: PaymentResult.PENDING,
    }


class SparkEventListener(EventListener):  # type: ignore[misc]
    """Push settled payments into an asyncio queue."""

    def __init__(self, queue: asyncio.Queue[str], loop: asyncio.AbstractEventLoop):
        super().__init__()
        self.queue = queue
        self.loop = loop

    async def on_event(self, event: SdkEvent) -> None:  # pragma: no cover - SDK callback
        payment = getattr(event, "payment", None)
        if payment is None:
            return

        payment_type = getattr(payment, "payment_type", None)
        receive_type = getattr(PaymentType, "RECEIVE", None) if PaymentType else None
        if receive_type and payment_type and payment_type != receive_type:
            return
        if not _is_lightning_payment(payment):
            return

        status = getattr(payment, "status", None)
        if status not in SPARK_PAYMENT_RESULT_MAP:
            return

        checking_id = _extract_invoice_id(payment)
        if not checking_id:
            return

        def _enqueue() -> None:
            try:
                self.queue.put_nowait(checking_id)
            except asyncio.QueueFull:
                logger.warning("Spark event queue full, dropping payment notification")

        if self.loop.is_closed():
            return
        self.loop.call_soon_threadsafe(_enqueue)


class SparkWallet(LightningBackend):
    """Lightning backend that talks to the Breez Spark SDK."""

    supported_units = {Unit.sat, Unit.msat}
    supports_description = True
    supports_incoming_payment_stream = True
    supports_mpp = False
    unit = Unit.sat

    def __init__(self, unit: Unit = Unit.sat, **kwargs):
        if BreezSdk is None:
            raise Unsupported("breez-sdk-spark is required for SparkWallet")

        self.assert_unit_supported(unit)
        self.unit = unit

        assert settings.mint_spark_api_key, "MINT_SPARK_API_KEY not set"
        assert settings.mint_spark_mnemonic, "MINT_SPARK_MNEMONIC not set"

        network_name = getattr(settings, "mint_spark_network", "mainnet").lower()
        self.network = (
            Network.MAINNET if network_name == "mainnet" else Network.TESTNET
        )
        self.storage_dir = getattr(settings, "mint_spark_storage_dir", "data/spark")
        self.connection_timeout = getattr(
            settings, "mint_spark_connection_timeout", 30
        )
        self.max_retry_attempts = getattr(settings, "mint_spark_retry_attempts", 3)

        self._sdk: Optional[BreezSdk] = None
        self._listener_id: Optional[str] = None
        self._listener: Optional[SparkEventListener] = None
        self._event_queue: Optional[asyncio.Queue[str]] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._lock = asyncio.Lock()

    async def cleanup(self) -> None:
        await self._reset_sdk()

    async def status(self) -> StatusResponse:
        try:
            sdk = await self._sdk_instance()
            info = await sdk.get_info(request=GetInfoRequest(ensure_synced=True))
            return StatusResponse(
                error_message=None, balance=Amount(Unit.sat, info.balance_sats)
            )
        except Exception as exc:
            logger.error(f"Spark status error: {exc}")
            return StatusResponse(
                error_message=f"Failed to connect to Spark SDK: {exc}",
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
        try:
            sdk = await self._sdk_instance()
            payment_method = ReceivePaymentMethod.BOLT11_INVOICE(
                description=memo or "",
                amount_sats=amount.to(Unit.sat).amount,
            )
            request = ReceivePaymentRequest(payment_method=payment_method)
            response = await sdk.receive_payment(request=request)

            invoice = decode(response.payment_request)
            checking_id = invoice.payment_hash or response.payment_request.lower()
            return InvoiceResponse(
                ok=True,
                checking_id=checking_id.lower(),
                payment_request=response.payment_request,
            )
        except Exception as exc:
            logger.error(f"Spark invoice creation failed: {exc}")
            return InvoiceResponse(ok=False, error_message=str(exc))

    async def pay_invoice(
        self, quote: MeltQuote, fee_limit_msat: int
    ) -> PaymentResponse:
        try:
            sdk = await self._sdk_instance()
            prepare_request = PrepareSendPaymentRequest(
                payment_request=quote.request,
                amount=None,
            )
            prepare_response = await sdk.prepare_send_payment(
                request=prepare_request
            )

            options = SendPaymentOptions.BOLT11_INVOICE(
                prefer_spark=False, completion_timeout_secs=30
            )
            request = SendPaymentRequest(
                prepare_response=prepare_response, options=options
            )
            response = await sdk.send_payment(request=request)
            payment = response.payment

            result = self._map_payment_status(payment)
            fee_sats = _payment_fee_sats(payment)
            preimage = _payment_preimage(payment)
            checking_id = (
                quote.checking_id
                or _extract_invoice_id(payment)
                or getattr(payment, "payment_hash", None)
            )

            return PaymentResponse(
                result=result,
                checking_id=checking_id,
                fee=Amount(Unit.sat, fee_sats) if fee_sats is not None else None,
                preimage=preimage,
            )
        except Exception as exc:
            logger.error(f"Spark payment failed: {exc}")
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message=f"Payment failed: {exc}",
            )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        return await self._get_payment_status(checking_id, PaymentType.RECEIVE if PaymentType else None)

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        return await self._get_payment_status(checking_id, PaymentType.SEND if PaymentType else None)

    async def _get_payment_status(
        self, checking_id: str, payment_type: Optional[PaymentType]
    ) -> PaymentStatus:
        try:
            payment = await self._find_payment(checking_id, payment_type)
            if not payment:
                return PaymentStatus(
                    result=PaymentResult.PENDING,
                    error_message="Payment not found yet",
                )

            result = self._map_payment_status(payment)
            fee_sats = _payment_fee_sats(payment)
            preimage = _payment_preimage(payment)
            return PaymentStatus(
                result=result,
                fee=Amount(Unit.sat, fee_sats) if fee_sats is not None else None,
                preimage=preimage,
            )
        except Exception as exc:
            logger.error(f"Spark status check failed: {exc}")
            return PaymentStatus(result=PaymentResult.UNKNOWN, error_message=str(exc))

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        invoice_obj = decode(melt_quote.request)
        assert invoice_obj.amount_msat, "invoice has no amount."

        amount_msat = int(invoice_obj.amount_msat)
        fees_msat = fee_reserve(amount_msat)

        try:
            sdk = await self._sdk_instance()
            prepare_response = await sdk.prepare_send_payment(
                request=PrepareSendPaymentRequest(
                    payment_request=melt_quote.request, amount=None
                )
            )

            estimated_fee = getattr(prepare_response, "fees_sats", None) or getattr(
                prepare_response, "fees", None
            )
            if estimated_fee:
                buffered_fee_sats = int(int(estimated_fee) * 1.2)
                fees_msat = max(buffered_fee_sats, 1) * 1000
        except Exception as exc:
            logger.debug(f"Spark fee estimation failed, using default reserve: {exc}")

        fees = Amount(unit=Unit.msat, amount=fees_msat)
        amount = Amount(unit=Unit.msat, amount=amount_msat)
        return PaymentQuoteResponse(
            checking_id=invoice_obj.payment_hash,
            fee=fees.to(self.unit, round="up"),
            amount=amount.to(self.unit, round="up"),
        )

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        base_delay = settings.mint_retry_exponential_backoff_base_delay
        max_delay = settings.mint_retry_exponential_backoff_max_delay
        retry_delay = base_delay

        while True:
            try:
                await self._sdk_instance()
                assert self._event_queue is not None
                checking_id = await asyncio.wait_for(
                    self._event_queue.get(), timeout=30
                )

                status = await self.get_invoice_status(checking_id)
                if status.settled:
                    retry_delay = base_delay
                    yield checking_id
                else:
                    logger.debug(
                        "Spark stream saw unsettled payment %s, skipping",
                        checking_id[:20],
                    )
            except asyncio.TimeoutError:
                if not await self._check_connectivity():
                    await self._reset_sdk()
                continue
            except Exception as exc:
                logger.error(f"Spark payment stream error: {exc}")
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, max_delay)

    async def _sdk_instance(self) -> BreezSdk:
        if self._sdk:
            return self._sdk

        async with self._lock:
            if self._sdk:
                return self._sdk
            self._sdk = await self._connect_sdk_with_retry()
        return self._sdk

    async def _connect_sdk_with_retry(self) -> BreezSdk:
        attempt = 0
        last_exc: Optional[Exception] = None
        while attempt < self.max_retry_attempts:
            try:
                return await self._connect_sdk()
            except Exception as exc:
                last_exc = exc
                delay = 2**attempt
                logger.warning(
                    f"Spark SDK connect attempt {attempt + 1} failed: {exc}; retrying in {delay}s"
                )
                await asyncio.sleep(delay)
                attempt += 1
        assert last_exc is not None
        raise last_exc

    async def _connect_sdk(self) -> BreezSdk:
        loop = asyncio.get_running_loop()
        _register_sdk_event_loop(loop)

        config = default_config(network=self.network)
        config.api_key = settings.mint_spark_api_key

        seed = Seed.MNEMONIC(
            mnemonic=settings.mint_spark_mnemonic, passphrase=None
        )
        sdk = await asyncio.wait_for(
            connect(
                request=ConnectRequest(
                    config=config, seed=seed, storage_dir=self.storage_dir
                )
            ),
            timeout=self.connection_timeout,
        )

        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1024)
        self._listener = SparkEventListener(queue, loop)
        self._listener_id = await _await_if_needed(
            sdk.add_event_listener(listener=self._listener)
        )
        self._event_queue = queue
        self._loop = loop
        return sdk

    async def _reset_sdk(self) -> None:
        sdk, listener_id = self._sdk, self._listener_id
        self._sdk = None
        self._listener_id = None
        try:
            if sdk and listener_id:
                await _await_if_needed(sdk.remove_event_listener(id=listener_id))
            if sdk:
                await _await_if_needed(sdk.disconnect())
        except Exception as exc:  # pragma: no cover - defensive cleanup
            logger.warning(f"Spark cleanup failed: {exc}")
        finally:
            self._listener = None
            self._event_queue = None
            self._loop = None

    async def _check_connectivity(self) -> bool:
        if not self._sdk:
            return False
        try:
            await asyncio.wait_for(
                self._sdk.get_info(request=GetInfoRequest(ensure_synced=None)),
                timeout=5.0,
            )
            return True
        except Exception:
            return False

    async def _find_payment(
        self, checking_id: str, payment_type: Optional[PaymentType]
    ):
        sdk = await self._sdk_instance()
        request = (
            ListPaymentsRequest(type_filter=[payment_type])
            if payment_type
            else ListPaymentsRequest()
        )
        response = await sdk.list_payments(request=request)
        normalized_id = checking_id.lower()
        for payment in response.payments:
            if payment_type and getattr(payment, "payment_type", None) != payment_type:
                continue
            if not _is_lightning_payment(payment):
                continue
            invoice_id = _extract_invoice_id(payment)
            if invoice_id and invoice_id == normalized_id:
                return payment
        return None

    def _map_payment_status(self, payment) -> PaymentResult:
        status = getattr(payment, "status", None)
        if status in SPARK_PAYMENT_RESULT_MAP:
            return SPARK_PAYMENT_RESULT_MAP[status]

        status_str = str(status).lower()
        if any(token in status_str for token in ("complete", "settled", "success")):
            return PaymentResult.SETTLED
        if any(token in status_str for token in ("fail", "cancel", "expire")):
            return PaymentResult.FAILED
        if "pending" in status_str or "process" in status_str:
            return PaymentResult.PENDING
        return PaymentResult.UNKNOWN


async def _await_if_needed(value):
    if inspect.isawaitable(value):
        return await value
    return value
