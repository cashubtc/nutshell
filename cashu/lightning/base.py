from abc import ABC, abstractmethod
from typing import Coroutine, Optional, Union

from pydantic import BaseModel


class StatusResponse(BaseModel):
    error_message: Optional[str]
    balance: Union[int, float]


class InvoiceQuoteResponse(BaseModel):
    checking_id: str
    amount: int


class PaymentQuoteResponse(BaseModel):
    checking_id: str
    amount: int
    fee: int


class InvoiceResponse(BaseModel):
    ok: bool  # True: invoice created, False: failed
    checking_id: Optional[str] = None
    payment_request: Optional[str] = None
    error_message: Optional[str] = None


class PaymentResponse(BaseModel):
    ok: Optional[bool] = None  # True: paid, False: failed, None: pending or unknown
    checking_id: Optional[str] = None
    fee_msat: Optional[int] = None
    preimage: Optional[str] = None
    error_message: Optional[str] = None


class PaymentStatus(BaseModel):
    paid: Optional[bool] = None
    fee_msat: Optional[int] = None
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

    @abstractmethod
    def status(self) -> Coroutine[None, None, StatusResponse]:
        pass

    @abstractmethod
    def create_invoice(
        self,
        amount: int,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
    ) -> Coroutine[None, None, InvoiceResponse]:
        pass

    @abstractmethod
    def pay_invoice(
        self, bolt11: str, fee_limit_msat: int
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
        bolt11: str,
    ) -> PaymentQuoteResponse:
        pass

    # @abstractmethod
    # async def get_invoice_quote(
    #     self,
    #     bolt11: str,
    # ) -> InvoiceQuoteResponse:
    #     pass

    # @abstractmethod
    # def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
    #     pass


class Unsupported(Exception):
    pass
