from abc import ABC, abstractmethod
from typing import AsyncGenerator, Coroutine, Optional, Union
from enum import Enum

from pydantic import BaseModel

from ..core.base import (
    Amount,
    MeltQuote,
    Unit,
)
from ..core.models import PostMeltQuoteRequest


class StatusResponse(BaseModel):
    error_message: Optional[str]
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

class PaymentResult(Enum):
    FAILED = 0
    SETTLED = 1
    PENDING = 2

    UNKNOWN = 3

    def __str__(self):
        return self.name

    # We assume `None` is `FAILED`
    @classmethod
    def from_paid_flag(cls, paid: Optional[bool]):
        if paid is None or paid == False:
            return cls.FAILED
        elif paid == True:
            return cls.SETTLED

class PaymentResponse(BaseModel):
    result: PaymentResult
    ok: Optional[bool] = None  # True: paid, False: failed, None: pending or unknown
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
    def unknown(self) -> bool:
        return self.result == PaymentResult.UNKNOWN

class PaymentStatus(BaseModel):
    result: PaymentResult
    paid: Optional[bool] = None
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
    def unknown(self) -> bool:
        return self.result == PaymentResult.UNKNOWN

    def __str__(self) -> str:
        if self.result == PaymentResult.SETTLED:
            return "settled"
        elif self.result == PaymentResult.FAILED:
            return "failed"
        elif self.result == PaymentResult.PENDING:
            return "still pending"
        else: # self.result == PaymentResult.UNKNOWN:
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
