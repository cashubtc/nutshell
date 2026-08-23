from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, AsyncGenerator, Optional

from pydantic import BaseModel, ConfigDict, Field

from ..core.base import Amount, MeltQuote, MintQuote, Unit
from ..core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from ..lightning.base import (
    InvoiceResponse,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentStatus,
    StatusResponse,
)


class PaymentMethodSettings(BaseModel):
    """NUT-04/NUT-05 settings advertised for a method-unit pair."""

    model_config = ConfigDict(extra="allow")

    method_name: Optional[str] = None
    min_amount: Optional[int] = Field(default=None, ge=0)
    max_amount: Optional[int] = Field(default=None, ge=0)
    options: Optional[dict[str, Any]] = None
    mint_enabled: bool = True
    melt_enabled: bool = True


class PaymentMethodPlugin(ABC):
    """Protocol boundary between Cashu quote orchestration and a payment rail.

    Method-specific parsing, canonicalization, fee conventions and proofs belong
    here.  The ledger only handles Cashu accounting and proof state transitions.
    """

    method: str
    mint_quote_request_model: type[BaseModel] = PostMintQuoteRequest
    melt_quote_request_model: type[BaseModel] = PostMeltQuoteRequest
    allows_partial_mint: bool = False

    def create_backend(self, unit: Unit, config: dict[str, Any]) -> Any:
        """Construct a configured mint backend for this method.

        Third-party plugins override this hook. BOLT11 remains configured through
        its historical environment variables for backwards compatibility.
        """
        raise NotImplementedError(
            f"payment method '{self.method}' does not provide a backend factory"
        )

    def validate_mint_quote_request(self, payload: Any) -> PostMintQuoteRequest:
        return self.mint_quote_request_model.model_validate(payload)  # type: ignore[return-value]

    def validate_melt_quote_request(self, payload: Any) -> PostMeltQuoteRequest:
        return self.melt_quote_request_model.model_validate(payload)  # type: ignore[return-value]

    def settings_for(self, backend: Any, unit: Unit) -> PaymentMethodSettings:
        return PaymentMethodSettings(method_name=self.method)

    def supports_description(self, backend: Any) -> bool:
        return False

    def supports_mpp(self, backend: Any) -> bool:
        return False

    def supports_incoming_payment_stream(self, backend: Any) -> bool:
        return False

    def canonicalize_request(self, request: str) -> str:
        return request

    @abstractmethod
    async def create_incoming_payment(
        self, backend: Any, request: PostMintQuoteRequest
    ) -> InvoiceResponse:
        """Create payment instructions for a mint quote."""

    @abstractmethod
    async def get_incoming_payment_status(
        self, backend: Any, quote: MintQuote
    ) -> PaymentStatus:
        """Return the current incoming payment status."""

    @abstractmethod
    async def quote_outgoing_payment(
        self, backend: Any, request: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        """Price an outgoing payment for a melt quote."""

    @abstractmethod
    async def execute_outgoing_payment(
        self, backend: Any, quote: MeltQuote, fee_limit: Amount
    ) -> PaymentResponse:
        """Execute an outgoing payment."""

    @abstractmethod
    async def get_outgoing_payment_status(
        self, backend: Any, quote: MeltQuote
    ) -> PaymentStatus:
        """Return the current outgoing payment status."""

    @abstractmethod
    def quote_expiry(self, payment_request: str) -> Optional[int]:
        """Return the payment request's absolute expiry, if it has one."""

    def validate_internal_settlement(
        self, mint_quote: MintQuote, melt_quote: MeltQuote
    ) -> None:
        if mint_quote.request != melt_quote.request:
            raise ValueError("payment requests do not match")
        if mint_quote.amount != melt_quote.amount:
            raise ValueError("payment amounts do not match")

    async def status(self, backend: Any) -> StatusResponse:
        return await backend.status()

    async def incoming_payment_stream(self, backend: Any) -> AsyncGenerator[str, None]:
        async for checking_id in backend.paid_invoices_stream():
            yield checking_id

    def funding_source_id(self, backend: Any, unit: Unit) -> str:
        return f"{backend.__class__.__module__}.{backend.__class__.__qualname__}:{unit.name}:{id(backend)}"
