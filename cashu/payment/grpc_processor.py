from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any, AsyncGenerator, Optional

import bolt11
import grpc
from pydantic import BaseModel

from ..core.base import Amount, MeltQuote, MintQuote, Unit
from ..core.errors import AmountlessInvoiceNotSupportedError, QuoteExpiredError
from ..core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from ..lightning.base import (
    InvoiceResponse,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    PaymentStatusResult,
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
    value = identifier.WhichOneof("value")
    if (
        identifier.type not in pb.PaymentIdentifierType.values()
        or not identifier.type
        or not value
        or not getattr(identifier, value)
    ):
        raise ValueError("processor returned an invalid payment identifier")
    data: dict[str, Any] = {"type": int(identifier.type)}
    value = identifier.WhichOneof("value")
    if value:
        data[value] = getattr(identifier, value)
    return json.dumps(data, separators=(",", ":"))


def _identifier_from_json(value: str, *, bolt11: bool = False) -> pb.PaymentIdentifier:
    if bolt11 and re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return pb.PaymentIdentifier(
            type=pb.PAYMENT_IDENTIFIER_TYPE_PAYMENT_HASH, hash=value.lower()
        )
    try:
        data = json.loads(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            "incompatible backend identifier; reconcile the quote with its original backend before switching"
        ) from exc
    if not isinstance(data, dict):
        raise ValueError("invalid stored payment identifier")
    identifier = pb.PaymentIdentifier()
    identifier.type = int(data.get("type", 0))  # type: ignore[assignment]
    if data.get("hash") is not None:
        identifier.hash = data["hash"]
    elif data.get("id") is not None:
        identifier.id = data["id"]
    _identifier_to_json(identifier)
    return identifier


def _with_extras(model: BaseModel, extras: dict[str, Any]) -> Any:
    # Pydantic stores extension fields separately from the typed response.
    assert model.model_extra is not None
    model.model_extra.update(
        {
            k: v
            for k, v in extras.items()
            if k not in type(model).model_fields and not k.startswith("_")
        }
    )
    return model


def _convert(amount: Amount, unit: Unit, *, round: str = "down") -> Amount:
    if amount.unit != unit and {amount.unit, unit} != {Unit.sat, Unit.msat}:
        raise ValueError(
            f"cannot convert processor unit {amount.unit.name} to {unit.name}"
        )
    return amount.to(unit, round=round)


def _extra_json(model: Any) -> Optional[str]:
    extras = dict(getattr(model, "model_extra", None) or {})
    if isinstance(model, PostMeltQuoteRequest) and model.options:
        # Standard options have dedicated protobuf fields. Custom options retain
        # their nesting for the processor to validate through extra_json.
        custom_options = model.options.model_dump(
            exclude={"mpp", "amountless"}, exclude_unset=True
        )
        if custom_options:
            extras["options"] = custom_options
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
    if state == pb.QUOTE_STATE_UNPAID:
        return PaymentResult.PENDING
    if state == pb.QUOTE_STATE_FAILED:
        return PaymentResult.FAILED
    return PaymentResult.ERROR


class GrpcPaymentProcessor(PaymentMethodPlugin):
    """CDK v4 payment-processor client exposed as a Nutshell payment method."""

    requires_quote_id = True
    supports_balance = False

    def __init__(self, method: str, unit: Unit, config: dict[str, Any]):
        self.method = method
        for capability in (
            "allows_partial_mint",
            "allows_repeated_payments",
            "allows_amountless_mint",
        ):
            value = config.get(capability, False)
            if not isinstance(value, bool):
                raise ValueError(f"{capability} must be a boolean")
            setattr(self, capability, value)
        if method == "bolt11" and self.allows_repeated_payments:
            raise ValueError("bolt11 does not support repeated payments")
        if not isinstance(config.get("allow_insecure", False), bool):
            raise ValueError("allow_insecure must be a boolean")
        for flag in ("mint_enabled", "melt_enabled"):
            if not isinstance(config.get(flag, True), bool):
                raise ValueError(f"{flag} must be a boolean")
        self.rpc_timeout = float(config.get("rpc_timeout", 30))
        self.payment_timeout = float(config.get("payment_timeout", 120))
        if not all(
            math.isfinite(v) and v > 0 for v in (self.rpc_timeout, self.payment_timeout)
        ):
            raise ValueError("processor deadlines must be positive finite seconds")
        self.unit = unit
        self.native_unit = unit
        self.config = config
        self._channel: Optional[grpc.aio.Channel] = None
        self._stub: Optional[pb_grpc.CdkPaymentProcessorStub] = None
        self._settings: Optional[pb.SettingsResponse] = None

    def create_backend(self, unit: Unit, config: dict[str, Any]) -> Any:
        return GrpcPaymentProcessor(self.method, unit, config)

    def supports_reusable_requests(self, backend: Any) -> bool:
        return self.method in {"bolt12", "onchain"} or (
            self.method != "bolt11" and backend.allows_repeated_payments
        )

    def _native(self, amount: Amount, *, exact: bool = True) -> Amount:
        converted = _convert(amount, self.native_unit)
        if exact and _convert(converted, amount.unit).amount != amount.amount:
            raise ValueError(
                "amount cannot be represented in the processor's native unit"
            )
        return converted

    def supports_partial_mint(self, backend: Any) -> bool:
        return backend.allows_partial_mint

    def supports_repeated_payments(self, backend: Any) -> bool:
        return self.method != "bolt11" and backend.allows_repeated_payments

    def supports_amountless_mint(self, backend: Any) -> bool:
        return backend.allows_amountless_mint

    def supports_internal_settlement(self, backend: Any) -> bool:
        # Other rails need their own amount and settlement rules.
        return self.method == "bolt11"

    def canonicalize_request(self, request: str) -> str:
        # Match the legacy BOLT11 invoice lookup while preserving other rails.
        return request.lower() if self.method == "bolt11" else request

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

        options = [
            ("grpc.keepalive_time_ms", 30000),
            ("grpc.keepalive_timeout_ms", 10000),
        ]
        if self.config.get("allow_insecure", False):
            self._channel = grpc.aio.insecure_channel(target, options=options)
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
            if self.config.get("tls_server_name"):
                options.append(
                    ("grpc.ssl_target_name_override", self.config["tls_server_name"])
                )
            self._channel = grpc.aio.secure_channel(target, credentials, options)
        self._stub = pb_grpc.CdkPaymentProcessorStub(self._channel)
        try:
            processor_settings = await self.stub.GetSettings(
                pb.EmptyRequest(), metadata=self._metadata, timeout=self.rpc_timeout
            )
            self.native_unit = Unit[processor_settings.unit or self.unit.name]
            _convert(Amount(self.native_unit, 0), self.unit)
            self._settings = processor_settings
        except BaseException:
            await self.stop(self)
            raise

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
        return PaymentMethodSettings(
            method_name=self.method,
            mint_options=options or None,
            melt_options=(
                {"amountless": bool(settings.bolt12.amountless)}
                if settings and self.method == "bolt12" and settings.HasField("bolt12")
                else None
            ),
            **{
                key: processor.config[key]
                for key in (
                    "min_amount",
                    "max_amount",
                    "mint_min_amount",
                    "mint_max_amount",
                    "melt_min_amount",
                    "melt_max_amount",
                    "mint_enabled",
                    "melt_enabled",
                )
                if key in processor.config
            },
        )

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

    def validate_payment_request(self, backend: Any, request: str) -> Optional[int]:
        if self.method == "bolt11":
            invoice = bolt11.decode(request)
            if not invoice.amount_msat:
                raise AmountlessInvoiceNotSupportedError("invoice has no amount.")
            if invoice.has_expired():
                raise QuoteExpiredError("invoice expired")
            return invoice.expiry_time
        return self.quote_expiry(request)

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
            _amount(
                processor._native(
                    Amount(unit=Unit[request.unit], amount=request.amount)
                )
            )
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
            pb.CreatePaymentRequest(options=options),
            metadata=processor._metadata,
            timeout=processor.rpc_timeout,
        )
        extras = _extra(response.extra_json)
        if response.HasField("expiry"):
            extras["expiry"] = response.expiry
        return _with_extras(
            InvoiceResponse(
                ok=True,
                checking_id=_identifier_to_json(response.request_identifier),
                payment_request=response.request,
            ),
            extras,
        )

    async def get_incoming_payment_status(
        self, backend: Any, quote: MintQuote
    ) -> PaymentStatus:
        processor: GrpcPaymentProcessor = backend
        response = await processor.stub.CheckIncomingPayment(
            pb.CheckIncomingPaymentRequest(
                request_identifier=_identifier_from_json(
                    quote.checking_id, bolt11=self.method == "bolt11"
                )
            ),
            metadata=processor._metadata,
            timeout=processor.rpc_timeout,
        )
        amounts = [
            Amount(Unit[p.payment_amount.unit], p.payment_amount.value)
            for p in response.payments
        ]
        for amount in amounts:
            _convert(amount, Unit[quote.unit])
        total_unit = (
            Unit.msat if Unit[quote.unit] in {Unit.sat, Unit.msat} else Unit[quote.unit]
        )
        total = sum(_convert(amount, total_unit).amount for amount in amounts)
        paid = _convert(Amount(total_unit, total), Unit[quote.unit]).amount
        fully_paid = paid > 0 and (quote.amount == 0 or paid >= quote.amount)
        return PaymentStatus(
            result=(
                PaymentStatusResult.SETTLED
                if fully_paid
                else PaymentStatusResult.PENDING
                if paid
                else PaymentStatusResult.NOT_FOUND
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
            _amount(processor._native(Amount(Unit[request.unit], request.amount)))
            if request.amount is not None
            else None
        )
        melt_options = None
        if request.options and request.options.mpp:
            amount = _amount(
                processor._native(Amount(Unit.msat, request.options.mpp.amount))
            )
            melt_options = pb.MeltOptions(mpp=pb.Mpp(amount=request.options.mpp.amount))
        amountless_msat = self.amountless_payment_amount(request)
        if amountless_msat is not None:
            melt_options = pb.MeltOptions(
                amountless=pb.Amountless(amount_msat=amountless_msat)
            )
        onchain_options = None
        if self.method == "onchain":
            if amount is None:
                raise ValueError("onchain melt quotes require an amount")
            onchain_options = pb.OnchainOutgoingPaymentOptions(
                address=request.request, amount=amount, quote_id=quote_id
            )
        response = await processor.stub.GetPaymentQuote(
            pb.PaymentQuoteRequest(
                request=request.request,
                unit=processor.native_unit.name,
                options=melt_options,
                request_type=request_type,
                extra_json=_extra_json(request),
                quote_id=quote_id,
                amount=amount,
                onchain_options=onchain_options,
            ),
            metadata=processor._metadata,
            timeout=processor.rpc_timeout,
        )
        priced = _with_extras(
            PaymentQuoteResponse(
                checking_id=_identifier_to_json(response.request_identifier),
                amount=_convert(
                    Amount(Unit[response.amount.unit], response.amount.value),
                    Unit[request.unit],
                    round="up",
                ),
                fee=_convert(
                    Amount(Unit[response.fee.unit], response.fee.value),
                    Unit[request.unit],
                    round="up",
                ),
            ),
            _extra(response.extra_json),
        )
        if request.options and request.options.mpp:
            priced.model_extra["_mpp_amount_msat"] = request.options.mpp.amount
        return priced

    def amountless_payment_amount(self, request: PostMeltQuoteRequest) -> Optional[int]:
        if self.method != "bolt12":
            if request.options and request.options.amountless:
                raise ValueError("amountless melt options require bolt12")
            return None
        if Unit[request.unit] not in {Unit.sat, Unit.msat}:
            raise ValueError("bolt12 amountless payments require sat or msat")
        explicit = request.options.amountless if request.options else None
        amount_msat = (
            Amount(Unit[request.unit], request.amount).to(Unit.msat).amount
            if request.amount is not None
            else None
        )
        if explicit:
            if amount_msat is not None and amount_msat != explicit.amount_msat:
                raise ValueError("conflicting amountless payment amounts")
            return explicit.amount_msat
        return amount_msat

    def _outgoing_options(
        self, quote: MeltQuote, fee_limit: Amount
    ) -> pb.OutgoingPaymentVariant:
        max_fee = _amount(self._native(fee_limit, exact=False))
        if self.method == "bolt11":
            melt_options = None
            if quote.unit in {Unit.sat.name, Unit.msat.name}:
                invoice = bolt11.decode(quote.request)
                amount_msat = int(
                    quote.method_data.get(
                        "_mpp_amount_msat",
                        Amount(Unit[quote.unit], quote.amount).to(Unit.msat).amount,
                    )
                )
                if invoice.amount_msat and amount_msat < invoice.amount_msat:
                    # Reconstruct MPP from the persisted quote so retries and
                    # restarts cannot turn a partial quote into a full payment.
                    melt_options = pb.MeltOptions(mpp=pb.Mpp(amount=amount_msat))
            return pb.OutgoingPaymentVariant(
                bolt11=pb.Bolt11OutgoingPaymentOptions(
                    bolt11=quote.request,
                    max_fee_amount=max_fee,
                    quote_id=quote.quote,
                    melt_options=melt_options,
                )
            )
        if self.method == "bolt12":
            return pb.OutgoingPaymentVariant(
                bolt12=pb.Bolt12OutgoingPaymentOptions(
                    offer=quote.request,
                    max_fee_amount=max_fee,
                    quote_id=quote.quote,
                    melt_options=pb.MeltOptions(
                        amountless=pb.Amountless(amount_msat=quote.amountless_msat)
                    )
                    if quote.amountless_msat is not None
                    else None,
                )
            )
        if self.method == "onchain":
            return pb.OutgoingPaymentVariant(
                onchain=pb.OnchainOutgoingPaymentOptions(
                    address=quote.request,
                    amount=_amount(
                        self._native(Amount(Unit[quote.unit], quote.amount))
                    ),
                    max_fee_amount=max_fee,
                    quote_id=quote.quote,
                )
            )
        return pb.OutgoingPaymentVariant(
            custom=pb.CustomOutgoingPaymentOptions(
                offer=quote.request,
                amount=_amount(self._native(Amount(Unit[quote.unit], quote.amount))),
                max_fee_amount=max_fee,
                extra_json=json.dumps(quote.method_data) if quote.method_data else None,
                quote_id=quote.quote,
            )
        )

    def _payment_response(
        self, response: pb.MakePaymentResponse, quote: MeltQuote
    ) -> PaymentResponse:
        unit = Unit[response.total_spent.unit or self.native_unit.name]
        spent = Amount(unit, response.total_spent.value)
        principal_unit = Unit.msat if unit in {Unit.sat, Unit.msat} else unit
        spent_exact = _convert(spent, principal_unit)
        principal = _convert(Amount(Unit[quote.unit], quote.amount), principal_unit)
        fee = _convert(
            Amount(principal_unit, max(0, spent_exact.amount - principal.amount)),
            Unit[quote.unit],
            round="up",
        )
        checking_id = (
            _identifier_to_json(response.payment_identifier)
            if response.HasField("payment_identifier")
            else quote.checking_id
        )
        return _with_extras(
            PaymentResponse(
                result=_result(response.status),
                checking_id=checking_id,
                fee=fee,
                preimage=response.payment_proof
                if response.HasField("payment_proof")
                else None,
            ),
            _extra(response.extra_json),
        )

    async def execute_outgoing_payment(
        self, backend: Any, quote: MeltQuote, fee_limit: Amount
    ) -> PaymentResponse:
        processor: GrpcPaymentProcessor = backend
        response = await processor.stub.MakePayment(
            pb.MakePaymentRequest(
                payment_options=processor._outgoing_options(quote, fee_limit),
                unit=processor.native_unit.name,
            ),
            metadata=processor._metadata,
            timeout=processor.payment_timeout,
        )
        return processor._payment_response(response, quote)

    async def get_outgoing_payment_status(
        self, backend: Any, quote: MeltQuote
    ) -> PaymentStatus:
        processor: GrpcPaymentProcessor = backend
        response = await processor.stub.CheckOutgoingPayment(
            pb.CheckOutgoingPaymentRequest(
                request_identifier=_identifier_from_json(
                    quote.checking_id, bolt11=self.method == "bolt11"
                )
            ),
            metadata=processor._metadata,
            timeout=processor.rpc_timeout,
        )
        payment = processor._payment_response(response, quote)
        return _with_extras(
            PaymentStatus(
                result=PaymentStatusResult[payment.result.name],
                fee=payment.fee,
                preimage=payment.preimage,
            ),
            _extra(response.extra_json),
        )

    async def incoming_payment_stream(self, backend: Any) -> AsyncGenerator[str, None]:
        processor: GrpcPaymentProcessor = backend
        stream = processor.stub.WaitPaymentEvent(
            pb.EmptyRequest(), metadata=processor._metadata
        )
        async for event in stream:
            if event.HasField("payment_received"):
                yield _identifier_to_json(event.payment_received.payment_identifier)
