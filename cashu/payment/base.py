from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, AsyncGenerator, Optional

from pydantic import BaseModel, ConfigDict, Field

from ..core.base import Amount, MeltQuote, MintQuote, Unit
from ..core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from ..core.settings import settings
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
    mint_options: Optional[dict[str, Any]] = None
    melt_options: Optional[dict[str, Any]] = None
    mint_enabled: bool = True
    melt_enabled: bool = True
    mint_min_amount: Optional[int] = Field(default=None, ge=0)
    mint_max_amount: Optional[int] = Field(default=None, ge=0)
    melt_min_amount: Optional[int] = Field(default=None, ge=0)
    melt_max_amount: Optional[int] = Field(default=None, ge=0)


class PaymentMethodPlugin(ABC):
    """Protocol boundary between Cashu quote orchestration and a payment rail.

    Method-specific parsing, canonicalization, fee conventions and proofs belong
    here.  The ledger only handles Cashu accounting and proof state transitions.
    """

    method: str
    mint_quote_request_model: type[BaseModel] = PostMintQuoteRequest
    melt_quote_request_model: type[BaseModel] = PostMeltQuoteRequest
    allows_partial_mint: bool = False
    allows_repeated_payments: bool = False
    allows_amountless_mint: bool = False
    requires_quote_id: bool = False
    supports_balance: bool = True

    def supports_partial_mint(self, backend: Any) -> bool:
        return self.allows_partial_mint

    def supports_repeated_payments(self, backend: Any) -> bool:
        return self.allows_repeated_payments

    def supports_amountless_mint(self, backend: Any) -> bool:
        return self.allows_amountless_mint

    def supports_internal_settlement(self, backend: Any) -> bool:
        return False

    def supports_reusable_requests(self, backend: Any) -> bool:
        """Whether independent outgoing payments may use the same request."""
        return self.method != "bolt11" and self.supports_repeated_payments(backend)

    def amountless_payment_amount(self, request: PostMeltQuoteRequest) -> Optional[int]:
        if request.options and request.options.amountless:
            raise ValueError("backend does not support amountless melt options")
        return None

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

    def operation_settings(
        self, backend: Any, unit: Unit, *, melt: bool = False
    ) -> PaymentMethodSettings:
        policy = self.settings_for(backend, unit).model_copy(deep=True)
        direction = "melt" if melt else "mint"
        for bound in ("min_amount", "max_amount"):
            value = getattr(policy, f"{direction}_{bound}")
            if value is not None:
                setattr(policy, bound, value)
        policy.options = (
            policy.melt_options if melt else policy.mint_options or policy.options
        )
        if self.method == "bolt11":
            disabled = (
                settings.mint_bolt11_disable_melt
                if melt
                else settings.mint_bolt11_disable_mint
            )
            setattr(
                policy,
                f"{direction}_enabled",
                not disabled and getattr(policy, f"{direction}_enabled"),
            )
            cap = (
                settings.mint_max_melt_bolt11_sat
                if melt
                else settings.mint_max_mint_bolt11_sat
            )
            if cap and unit in {Unit.sat, Unit.msat}:
                cap *= 1000 if unit == Unit.msat else 1
                policy.max_amount = (
                    min(cap, policy.max_amount) if policy.max_amount is not None else cap
                )
                policy.min_amount = policy.min_amount or 0
        return policy

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
        self,
        backend: Any,
        request: PostMintQuoteRequest,
        quote_id: Optional[str] = None,
    ) -> InvoiceResponse:
        """Create payment instructions for a mint quote."""

    @abstractmethod
    async def get_incoming_payment_status(
        self, backend: Any, quote: MintQuote
    ) -> PaymentStatus:
        """Return the current incoming payment status."""

    @abstractmethod
    async def quote_outgoing_payment(
        self,
        backend: Any,
        request: PostMeltQuoteRequest,
        quote_id: Optional[str] = None,
    ) -> PaymentQuoteResponse:
        """Price an outgoing payment for a melt quote."""

    def get_payment_checking_id(self, backend: Any, quote: MeltQuote) -> str:
        """Identify an outgoing attempt before sending, without doing I/O."""
        return quote.checking_id

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

    def validate_payment_request(self, backend: Any, request: str) -> Optional[int]:
        """Validate locally and return the payment request's absolute expiry."""
        return self.quote_expiry(request)

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

    async def start(self, backend: Any) -> None:
        """Initialize a payment backend before mint services start."""

    async def stop(self, backend: Any) -> None:
        """Release resources owned by a payment backend."""

    async def incoming_payment_stream(self, backend: Any) -> AsyncGenerator[str, None]:
        async for checking_id in backend.paid_invoices_stream():
            yield checking_id

    def funding_source_id(self, backend: Any, unit: Unit) -> str:
        """Identify reserves shared by methods so the watchdog counts them once.

        Override when different backend instances report the same wallet balance.
        Each source's status must report its complete balance in this unit.
        """
        return f"{backend.__class__.__module__}.{backend.__class__.__qualname__}:{unit.name}:{id(backend)}"
