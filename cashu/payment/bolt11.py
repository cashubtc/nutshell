from __future__ import annotations

from typing import Any, Optional

import bolt11

from ..core.base import Amount, MeltQuote, MintQuote, Unit
from ..core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from ..lightning.base import (
    InvoiceResponse,
    LightningBackend,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentStatus,
)
from .base import PaymentMethodPlugin, PaymentMethodSettings


class Bolt11PaymentMethod(PaymentMethodPlugin):
    method = "bolt11"

    def supports_internal_settlement(self, backend: Any) -> bool:
        return True

    def validate_mint_quote_request(self, payload: Any) -> PostMintQuoteRequest:
        request = super().validate_mint_quote_request(payload)
        if request.amount is None:
            raise ValueError("bolt11 mint quotes require an amount")
        return request

    def supports_description(self, backend: LightningBackend) -> bool:
        return backend.supports_description

    def supports_mpp(self, backend: LightningBackend) -> bool:
        return backend.supports_mpp

    def supports_incoming_payment_stream(self, backend: LightningBackend) -> bool:
        return backend.supports_incoming_payment_stream

    def settings_for(self, backend: Any, unit: Unit) -> PaymentMethodSettings:
        return PaymentMethodSettings(
            method_name="bolt11",
            options={"description": bool(backend.supports_description)},
        )

    async def start(self, backend: LightningBackend) -> None:
        await backend.startup()

    async def stop(self, backend: LightningBackend) -> None:
        await backend.cleanup()

    def canonicalize_request(self, request: str) -> str:
        # BOLT11 is bech32 and therefore case-insensitive. Mixed-case strings are
        # invalid; normalizing preserves Nutshell's historical storage behavior.
        return request.lower()

    async def create_incoming_payment(
        self,
        backend: Any,
        request: PostMintQuoteRequest,
        quote_id: Optional[str] = None,
    ) -> InvoiceResponse:
        if request.amount is None:
            raise ValueError("bolt11 mint quotes require an amount")
        return await backend.create_invoice(
            amount=Amount(unit=Unit[request.unit], amount=request.amount),
            memo=request.description,
        )

    async def get_incoming_payment_status(
        self, backend: Any, quote: MintQuote
    ) -> PaymentStatus:
        return await backend.get_invoice_status(quote.checking_id)

    async def quote_outgoing_payment(
        self,
        backend: Any,
        request: PostMeltQuoteRequest,
        quote_id: Optional[str] = None,
    ) -> PaymentQuoteResponse:
        return await backend.get_payment_quote(melt_quote=request)

    def get_payment_checking_id(
        self, backend: LightningBackend, quote: MeltQuote
    ) -> str:
        return backend.get_payment_checking_id(quote)

    async def execute_outgoing_payment(
        self, backend: Any, quote: MeltQuote, fee_limit: Amount
    ) -> PaymentResponse:
        fee_limit_msat = fee_limit.to(Unit.msat).amount
        return await backend.pay_invoice(quote, fee_limit_msat)

    async def get_outgoing_payment_status(
        self, backend: Any, quote: MeltQuote
    ) -> PaymentStatus:
        return await backend.get_payment_status(quote.checking_id)

    def validate_payment_request(
        self, backend: LightningBackend, request: str
    ) -> Optional[int]:
        return backend.validate_payment_request(request)

    def quote_expiry(self, payment_request: str) -> Optional[int]:
        invoice = bolt11.decode(payment_request)
        if invoice.expiry is None:
            return None
        return invoice.date + invoice.expiry


bolt11_payment_method = Bolt11PaymentMethod()
