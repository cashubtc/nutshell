from __future__ import annotations

from typing import Any, Optional

import bolt11

from ..core.base import Amount, MeltQuote, MintQuote, Unit
from ..core.errors import TransactionError
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

    def canonicalize_request(self, request: str) -> str:
        # BOLT11 is bech32 and therefore case-insensitive. Mixed-case strings are
        # invalid; normalizing preserves Nutshell's historical storage behavior.
        return request.lower()

    async def create_incoming_payment(
        self, backend: Any, request: PostMintQuoteRequest
    ) -> InvoiceResponse:
        return await backend.create_invoice(
            amount=Amount(unit=Unit[request.unit], amount=request.amount),
            memo=request.description,
        )

    async def get_incoming_payment_status(
        self, backend: Any, quote: MintQuote
    ) -> PaymentStatus:
        return await backend.get_invoice_status(quote.checking_id)

    async def quote_outgoing_payment(
        self, backend: Any, request: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        return await backend.get_payment_quote(melt_quote=request)

    async def execute_outgoing_payment(
        self, backend: Any, quote: MeltQuote, fee_limit: Amount
    ) -> PaymentResponse:
        fee_limit_msat = fee_limit.to(Unit.msat).amount
        return await backend.pay_invoice(quote, fee_limit_msat)

    async def get_outgoing_payment_status(
        self, backend: Any, quote: MeltQuote
    ) -> PaymentStatus:
        return await backend.get_payment_status(quote.checking_id)

    def quote_expiry(self, payment_request: str) -> Optional[int]:
        invoice = bolt11.decode(payment_request)
        if invoice.expiry is None:
            return None
        return invoice.date + invoice.expiry

    def validate_internal_settlement(
        self, mint_quote: MintQuote, melt_quote: MeltQuote
    ) -> None:
        invoice = bolt11.decode(melt_quote.request)
        if not invoice.amount_msat:
            raise TransactionError("invoice has no amount.")
        super().validate_internal_settlement(mint_quote, melt_quote)


bolt11_payment_method = Bolt11PaymentMethod()
