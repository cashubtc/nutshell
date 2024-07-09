from abc import ABC, abstractmethod
from typing import AsyncGenerator, Coroutine, Optional, Union

from pydantic import BaseModel

from ..core.base import (
    Amount,
    MeltQuote,
    Unit,
)
from ..core.models import PostMeltQuoteRequest


class StatusResponse(BaseModel):
    error_message: Optional[str] = None
    balance: Union[int, float]


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


class PaymentResponse(BaseModel):
    ok: Optional[bool] = None  # True: paid, False: failed, None: pending or unknown
    checking_id: Optional[str] = None
    fee: Optional[Amount] = None
    preimage: Optional[str] = None
    error_message: Optional[str] = None


class PaymentStatus(BaseModel):
    paid: Optional[bool] = None
    fee: Optional[Amount] = None
    preimage: Optional[str] = None

    @property
    def pending(self) -> bool:
        return self.paid is not True

    @property
    def failed(self) -> bool:
        return self.paid is False

    def __str__(self) -> str:
        if self.paid is True:
            return "settled"
        elif self.paid is False:
            return "failed"
        elif self.paid is None:
            return "still pending"
        else:
            return "unknown (should never happen)"


class LightningBackend(ABC):
    supports_mpp: bool = False
    supports_incoming_payment_stream: bool = False
    supported_units: set[Unit]
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
