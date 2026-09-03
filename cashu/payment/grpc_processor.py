from __future__ import annotations

import json
from pathlib import Path
from typing import Any, AsyncGenerator, Optional

import grpc

from ..core.base import Amount, MeltQuote, MintQuote, Unit
from ..core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from ..lightning.base import (
    InvoiceResponse,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    StatusResponse,
)
from .base import PaymentMethodPlugin, PaymentMethodSettings
from .grpc import payment_processor_pb2 as pb
from .grpc import payment_processor_pb2_grpc as pb_grpc

CDK_VERSION_HEADER = "x-cdk-protocol-version"
CDK_PAYMENT_PROCESSOR_PROTOCOL_VERSION = "4.0.0"


def _amount(amount: Amount) -> pb.AmountMessage:
    return pb.AmountMessage(value=amount.amount, unit=amount.unit.name)


def _identifier_to_json(identifier: pb.PaymentIdentifier) -> str:
    data: dict[str, Any] = {"type": int(identifier.type)}
    value = identifier.WhichOneof("value")
    if value:
        data[value] = getattr(identifier, value)
    return json.dumps(data, separators=(",", ":"))


def _identifier_from_json(value: str) -> pb.PaymentIdentifier:
    data = json.loads(value)
    identifier = pb.PaymentIdentifier()
    identifier.type = int(data.get("type", 0))  # type: ignore[assignment]
    if data.get("hash") is not None:
        identifier.hash = data["hash"]
    elif data.get("id") is not None:
        identifier.id = data["id"]
    return identifier


def _extra_json(model: Any) -> Optional[str]:
    extras = getattr(model, "model_extra", None)
    return json.dumps(extras) if extras else None


def _extra(value: str) -> dict[str, Any]:
    if not value:
        return {}
    decoded = json.loads(value)
    if not isinstance(decoded, dict):
        raise ValueError("CDK payment processor extra_json must contain an object")
    return decoded


def _result(state: int) -> PaymentResult:
    if state in (pb.QUOTE_STATE_PAID, pb.QUOTE_STATE_ISSUED):
        return PaymentResult.SETTLED
    if state == pb.QUOTE_STATE_PENDING:
        return PaymentResult.PENDING
    if state == pb.QUOTE_STATE_FAILED:
        return PaymentResult.FAILED
    return PaymentResult.UNKNOWN


class GrpcPaymentProcessor(PaymentMethodPlugin):
    """CDK v4 payment-processor client exposed as a Nutshell payment method."""

    requires_quote_id = True
    supports_balance = False

    def __init__(self, method: str, unit: Unit, config: dict[str, Any]):
        self.method = method
        self.unit = unit
        self.config = config
        self._channel: Optional[grpc.aio.Channel] = None
        self._stub: Optional[pb_grpc.CdkPaymentProcessorStub] = None
        self._settings: Optional[pb.SettingsResponse] = None

    def create_backend(self, unit: Unit, config: dict[str, Any]) -> Any:
        return self

    @property
    def _metadata(self) -> tuple[tuple[str, str], ...]:
        return ((CDK_VERSION_HEADER, CDK_PAYMENT_PROCESSOR_PROTOCOL_VERSION),)

    @property
    def stub(self) -> pb_grpc.CdkPaymentProcessorStub:
        if self._stub is None:
            raise RuntimeError("GrpcPaymentProcessor has not been started")
        return self._stub

    async def start(self, backend: Any) -> None:
        if backend is not self:
            await backend.start(backend)
            return
        if self._channel is not None:
            return
        target = str(self.config.get("endpoint") or self.config.get("address") or "")
        target = target.removeprefix("http://").removeprefix("https://")
        if not target:
            raise ValueError("GrpcPaymentProcessor requires endpoint or address")
        if ":" not in target and self.config.get("port"):
            target = f"{target}:{self.config['port']}"

        if self.config.get("allow_insecure", False):
            self._channel = grpc.aio.insecure_channel(target)
        else:
            tls_dir = self.config.get("tls_dir")
            ca_path = self.config.get("tls_ca") or (
                Path(tls_dir) / "ca.pem" if tls_dir else None
            )
            cert_path = self.config.get("tls_cert") or (
                Path(tls_dir) / "client.pem" if tls_dir else None
            )
            key_path = self.config.get("tls_key") or (
                Path(tls_dir) / "client.key" if tls_dir else None
            )
            if not (ca_path and cert_path and key_path):
                raise ValueError(
                    "GrpcPaymentProcessor requires mTLS credentials or allow_insecure=true"
                )
            credentials = grpc.ssl_channel_credentials(
                root_certificates=Path(ca_path).read_bytes(),
                private_key=Path(key_path).read_bytes(),
                certificate_chain=Path(cert_path).read_bytes(),
            )
            options = []
            if self.config.get("tls_server_name"):
                options.append(
                    ("grpc.ssl_target_name_override", self.config["tls_server_name"])
                )
            self._channel = grpc.aio.secure_channel(target, credentials, options)
        self._stub = pb_grpc.CdkPaymentProcessorStub(self._channel)
        processor_settings = await self.stub.GetSettings(
            pb.EmptyRequest(), metadata=self._metadata
        )
        self._settings = processor_settings
        if processor_settings.unit and processor_settings.unit != self.unit.name:
            raise ValueError(
                f"CDK processor unit '{processor_settings.unit}' does not match '{self.unit.name}'"
            )

    async def stop(self, backend: Any) -> None:
        if backend is not self:
            await backend.stop(backend)
            return
        if self._channel is not None:
            await self._channel.close()
        self._channel = None
        self._stub = None

    def settings_for(self, backend: Any, unit: Unit) -> PaymentMethodSettings:
        processor: GrpcPaymentProcessor = backend
        settings = processor._settings
        options: dict[str, Any] = {}
        if settings and self.method == "bolt11" and settings.HasField("bolt11"):
            options["description"] = settings.bolt11.invoice_description
        if settings and self.method == "bolt12" and settings.HasField("bolt12"):
            options["amountless"] = settings.bolt12.amountless
        if settings and self.method in settings.custom:
            options.update(_extra(settings.custom[self.method]))
        return PaymentMethodSettings(method_name=self.method, options=options or None)

    def supports_description(self, backend: Any) -> bool:
        processor: GrpcPaymentProcessor = backend
        if self.method != "bolt11":
            return True
        return bool(
            processor._settings and processor._settings.bolt11.invoice_description
        )

    def supports_mpp(self, backend: Any) -> bool:
        processor: GrpcPaymentProcessor = backend
        return bool(
            self.method == "bolt11"
            and processor._settings
            and processor._settings.bolt11.mpp
        )

    def supports_incoming_payment_stream(self, backend: Any) -> bool:
        return True

    async def status(self, backend: Any) -> StatusResponse:
        processor: GrpcPaymentProcessor = backend
        return StatusResponse(balance=Amount(unit=processor.unit, amount=0))

    def quote_expiry(self, payment_request: str) -> Optional[int]:
        return None

    async def create_incoming_payment(
        self,
        backend: Any,
        request: PostMintQuoteRequest,
        quote_id: Optional[str] = None,
    ) -> InvoiceResponse:
        processor: GrpcPaymentProcessor = backend
        if not quote_id:
            raise ValueError("CDK CreatePayment requires a quote id")
        amount = (
            _amount(Amount(unit=Unit[request.unit], amount=request.amount))
            if request.amount is not None
            else None
        )
        if self.method == "bolt11":
            if amount is None:
                raise ValueError("bolt11 mint quotes require an amount")
            options = pb.IncomingPaymentOptions(
                bolt11=pb.Bolt11IncomingPaymentOptions(
                    description=request.description, amount=amount
                )
            )
        elif self.method == "bolt12":
            bolt12 = pb.Bolt12IncomingPaymentOptions(
                description=request.description,
            )
            if amount is not None:
                bolt12.amount.CopyFrom(amount)
            options = pb.IncomingPaymentOptions(bolt12=bolt12)
        elif self.method == "onchain":
            options = pb.IncomingPaymentOptions(
                onchain=pb.OnchainIncomingPaymentOptions(quote_id=quote_id)
            )
        else:
            custom = pb.CustomIncomingPaymentOptions(
                description=request.description,
                extra_json=_extra_json(request),
                quote_id=quote_id,
                pubkey=request.pubkey,
            )
            if amount is not None:
                custom.amount.CopyFrom(amount)
            options = pb.IncomingPaymentOptions(custom=custom)
        response = await processor.stub.CreatePayment(
            pb.CreatePaymentRequest(options=options), metadata=processor._metadata
        )
        extras = _extra(response.extra_json)
        if response.HasField("expiry"):
            extras["expiry"] = response.expiry
        return InvoiceResponse(
            ok=True,
            checking_id=_identifier_to_json(response.request_identifier),
            payment_request=response.request,
            **extras,
        )

    async def get_incoming_payment_status(
        self, backend: Any, quote: MintQuote
    ) -> PaymentStatus:
        processor: GrpcPaymentProcessor = backend
        response = await processor.stub.CheckIncomingPayment(
            pb.CheckIncomingPaymentRequest(
                request_identifier=_identifier_from_json(quote.checking_id)
            ),
            metadata=processor._metadata,
        )
        paid = sum(
            payment.payment_amount.value
            for payment in response.payments
            if payment.payment_amount.unit == quote.unit
        )
        fully_paid = paid > 0 and (quote.amount == 0 or paid >= quote.amount)
        return PaymentStatus(
            result=(
                PaymentResult.SETTLED
                if fully_paid
                else PaymentResult.PENDING
                if paid
                else PaymentResult.UNKNOWN
            ),
            amount_paid=Amount(Unit[quote.unit], paid) if paid else None,
        )

    async def quote_outgoing_payment(
        self,
        backend: Any,
        request: PostMeltQuoteRequest,
        quote_id: Optional[str] = None,
    ) -> PaymentQuoteResponse:
        processor: GrpcPaymentProcessor = backend
        if not quote_id:
            raise ValueError("CDK GetPaymentQuote requires a quote id")
        request_type = {
            "bolt11": pb.OUTGOING_PAYMENT_REQUEST_TYPE_BOLT11_INVOICE,
            "bolt12": pb.OUTGOING_PAYMENT_REQUEST_TYPE_BOLT12_OFFER,
            "onchain": pb.OUTGOING_PAYMENT_REQUEST_TYPE_ONCHAIN,
        }.get(self.method, pb.OUTGOING_PAYMENT_REQUEST_TYPE_CUSTOM)
        amount = (
            _amount(Amount(Unit[request.unit], request.amount))
            if request.amount is not None
            else None
        )
        melt_options = None
        if request.options and request.options.mpp:
            amount = pb.AmountMessage(
                value=request.options.mpp.amount, unit=request.unit
            )
            melt_options = pb.MeltOptions(mpp=pb.Mpp(amount=request.options.mpp.amount))
        response = await processor.stub.GetPaymentQuote(
            pb.PaymentQuoteRequest(
                request=request.request,
                unit=request.unit,
                options=melt_options,
                request_type=request_type,
                extra_json=_extra_json(request),
                quote_id=quote_id,
                amount=amount,
            ),
            metadata=processor._metadata,
        )
        return PaymentQuoteResponse(
            checking_id=_identifier_to_json(response.request_identifier),
            amount=Amount(Unit[response.amount.unit], response.amount.value),
            fee=Amount(Unit[response.fee.unit], response.fee.value),
            **_extra(response.extra_json),
        )

    def _outgoing_options(
        self, quote: MeltQuote, fee_limit: Amount
    ) -> pb.OutgoingPaymentVariant:
        max_fee = _amount(fee_limit)
        if self.method == "bolt11":
            return pb.OutgoingPaymentVariant(
                bolt11=pb.Bolt11OutgoingPaymentOptions(
                    bolt11=quote.request, max_fee_amount=max_fee, quote_id=quote.quote
                )
            )
        if self.method == "bolt12":
            return pb.OutgoingPaymentVariant(
                bolt12=pb.Bolt12OutgoingPaymentOptions(
                    offer=quote.request, max_fee_amount=max_fee, quote_id=quote.quote
                )
            )
        if self.method == "onchain":
            return pb.OutgoingPaymentVariant(
                onchain=pb.OnchainOutgoingPaymentOptions(
                    address=quote.request,
                    amount=_amount(Amount(Unit[quote.unit], quote.amount)),
                    max_fee_amount=max_fee,
                    quote_id=quote.quote,
                )
            )
        return pb.OutgoingPaymentVariant(
            custom=pb.CustomOutgoingPaymentOptions(
                offer=quote.request,
                amount=_amount(Amount(Unit[quote.unit], quote.amount)),
                max_fee_amount=max_fee,
                extra_json=json.dumps(quote.method_data) if quote.method_data else None,
                quote_id=quote.quote,
            )
        )

    def _payment_response(
        self, response: pb.MakePaymentResponse, amount: int
    ) -> PaymentResponse:
        spent = response.total_spent.value
        unit = Unit[response.total_spent.unit or self.unit.name]
        return PaymentResponse(
            result=_result(response.status),
            checking_id=_identifier_to_json(response.payment_identifier),
            fee=Amount(unit, max(0, spent - amount)),
            preimage=response.payment_proof
            if response.HasField("payment_proof")
            else None,
            **_extra(response.extra_json),
        )

    async def execute_outgoing_payment(
        self, backend: Any, quote: MeltQuote, fee_limit: Amount
    ) -> PaymentResponse:
        processor: GrpcPaymentProcessor = backend
        response = await processor.stub.MakePayment(
            pb.MakePaymentRequest(
                payment_options=processor._outgoing_options(quote, fee_limit),
                unit=quote.unit,
            ),
            metadata=processor._metadata,
        )
        return processor._payment_response(response, quote.amount)

    async def get_outgoing_payment_status(
        self, backend: Any, quote: MeltQuote
    ) -> PaymentStatus:
        processor: GrpcPaymentProcessor = backend
        response = await processor.stub.CheckOutgoingPayment(
            pb.CheckOutgoingPaymentRequest(
                request_identifier=_identifier_from_json(quote.checking_id)
            ),
            metadata=processor._metadata,
        )
        payment = processor._payment_response(response, quote.amount)
        return PaymentStatus(
            result=payment.result,
            fee=payment.fee,
            preimage=payment.preimage,
            **(response and _extra(response.extra_json)),
        )

    async def incoming_payment_stream(self, backend: Any) -> AsyncGenerator[str, None]:
        processor: GrpcPaymentProcessor = backend
        stream = processor.stub.WaitPaymentEvent(
            pb.EmptyRequest(), metadata=processor._metadata
        )
        async for event in stream:
            if event.HasField("payment_received"):
                yield _identifier_to_json(event.payment_received.payment_identifier)
