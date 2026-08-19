from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import AsyncGenerator, Coroutine, Optional

from pydantic import BaseModel

from ..core.base import (
    Amount,
    MeltQuote,
    Unit,
)
from ..core.models import PostMeltQuoteRequest


class StatusResponse(BaseModel):
    balance: Amount
    error_message: Optional[str] = None


class InvoiceQuoteResponse(BaseModel):
    checking_id: str
    amount: int


class PaymentQuoteResponse(BaseModel):
    checking_id: str
    amount: Amount
    fee: Amount


class InvoiceResponse(BaseModel):
    ok: bool  # True: invoice created, False: failed
    checking_id: Optional[str] = None
    payment_request: Optional[str] = None
    error_message: Optional[str] = None


class PaymentResult(Enum):
    SETTLED = auto()  # Payment settled, e.g. invoice paid, payment confirmed, etc.
    FAILED = auto()  # Payment failed, e.g. invoice expired, payment rejected, etc.
    PENDING = auto()  # Payment is still pending, e.g. invoice not yet paid, payment not yet confirmed, etc.
    ERROR = auto()  # Error during payment, e.g. network error, backend error, etc.

    def __str__(self):
        return self.name


class PaymentResponse(BaseModel):
    result: PaymentResult
    checking_id: Optional[str] = None
    fee: Optional[Amount] = None
    preimage: Optional[str] = None
    error_message: Optional[str] = None

    @property
    def pending(self) -> bool:
        return self.result == PaymentResult.PENDING

    @property
    def settled(self) -> bool:
        return self.result == PaymentResult.SETTLED

    @property
    def failed(self) -> bool:
        return self.result == PaymentResult.FAILED

    @property
    def error(self) -> bool:
        return self.result == PaymentResult.ERROR


class PaymentStatusResult(Enum):
    SETTLED = auto()  # Payment settled, e.g. invoice paid, payment confirmed, etc.
    FAILED = auto()  # Payment failed, e.g. invoice expired, payment rejected, etc.
    PENDING = auto()  # Payment is still pending, e.g. invoice not yet paid, payment not yet confirmed, etc.
    NOT_FOUND = (
        auto()
    )  # Payment status not found, e.g. invoice not found, payment not found, etc.
    ERROR = (
        auto()
    )  # Error during payment status check, e.g. network error, backend error, etc.

    def __str__(self):
        return self.name


class PaymentStatus(BaseModel):
    result: PaymentStatusResult
    fee: Optional[Amount] = None
    preimage: Optional[str] = None
    error_message: Optional[str] = None

    @property
    def pending(self) -> bool:
        return self.result == PaymentStatusResult.PENDING

    @property
    def settled(self) -> bool:
        return self.result == PaymentStatusResult.SETTLED

    @property
    def failed(self) -> bool:
        return self.result == PaymentStatusResult.FAILED

    @property
    def not_found(self) -> bool:
        return self.result == PaymentStatusResult.NOT_FOUND

    @property
    def error(self) -> bool:
        return self.result == PaymentStatusResult.ERROR

    def __str__(self) -> str:
        if self.result == PaymentStatusResult.SETTLED:
            return (
                "settled"
                + (f" (preimage: {self.preimage})" if self.preimage else "")
                + (f" (fee: {self.fee})" if self.fee else "")
            )
        elif self.result == PaymentStatusResult.FAILED:
            return "failed"
        elif self.result == PaymentStatusResult.PENDING:
            return "still pending"
        elif self.result == PaymentStatusResult.ERROR:
            return "error" + (
                f" (Error: {self.error_message})" if self.error_message else ""
            )
        else:  # self.result == PaymentStatusResult.UNKNOWN:
            return "unknown" + (
                f" (Error: {self.error_message})" if self.error_message else ""
            )


class LightningBackend(ABC):
    supports_mpp: bool = False
    supports_incoming_payment_stream: bool = False
    supported_units: set[Unit]
    supports_description: bool = False
    unit: Unit

    def assert_unit_supported(self, unit: Unit):
        if unit not in self.supported_units:
            raise Unsupported(f"Unit {unit} is not supported")

    @abstractmethod
    def __init__(self, unit: Unit, **kwargs):
        pass

    @abstractmethod
    def status(self) -> Coroutine[None, None, StatusResponse]:
        pass

    @abstractmethod
    def create_invoice(
        self,
        amount: Amount,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
    ) -> Coroutine[None, None, InvoiceResponse]:
        pass

    @abstractmethod
    def pay_invoice(
        self, quote: MeltQuote, fee_limit_msat: int
    ) -> Coroutine[None, None, PaymentResponse]:
        pass

    @abstractmethod
    def get_invoice_status(
        self, checking_id: str
    ) -> Coroutine[None, None, PaymentStatus]:
        pass

    @abstractmethod
    def get_payment_status(
        self, checking_id: str
    ) -> Coroutine[None, None, PaymentStatus]:
        pass

    @abstractmethod
    async def get_payment_quote(
        self,
        melt_quote: PostMeltQuoteRequest,
    ) -> PaymentQuoteResponse:
        pass

    # @abstractmethod
    # async def get_invoice_quote(
    #     self,
    #     bolt11: str,
    # ) -> InvoiceQuoteResponse:
    #     pass

    @abstractmethod
    def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        pass


class Unsupported(Exception):
    pass
