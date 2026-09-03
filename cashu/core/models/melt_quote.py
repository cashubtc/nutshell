from typing import List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

from cashu.core.base import BlindedSignature, MeltQuote
from cashu.core.constants import MAX_PAYMENT_REQUEST_LEN, MAX_UNIT_LEN


class PostMeltRequestOptionMpp(BaseModel):
    amount: int = Field(gt=0)  # input amount


class PostMeltRequestOptions(BaseModel):
    mpp: Optional[PostMeltRequestOptionMpp]


class PostMeltQuoteRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    unit: str = Field(..., max_length=MAX_UNIT_LEN)  # input unit
    request: str = Field(
        ..., max_length=MAX_PAYMENT_REQUEST_LEN
    )  # output payment request
    amount: Optional[int] = Field(default=None, gt=0)
    options: Optional[PostMeltRequestOptions] = None

    @property
    def is_mpp(self) -> bool:
        if self.options and self.options.mpp:
            return True
        else:
            return False

    @property
    def mpp_amount(self) -> int:
        if self.is_mpp and self.options and self.options.mpp:
            return self.options.mpp.amount
        else:
            raise Exception("quote request is not mpp.")


class PostMeltQuoteResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    quote: str  # quote id
    amount: int  # input amount
    unit: str  # input unit
    method: str  # payment method
    request: str  # output payment request
    fee_reserve: Optional[int] = None  # input fee reserve
    state: str  # state of the quote
    expiry: Optional[int] = None  # expiry of the quote
    payment_preimage: Optional[str] = None  # payment preimage
    change: Union[List[BlindedSignature], None] = None  # NUT-08 change

    @classmethod
    def from_melt_quote(cls, melt_quote: MeltQuote) -> "PostMeltQuoteResponse":
        # Keep internal settlement identifiers and timestamps off the wire while
        # allowing a payment method to add its own protocol fields.
        response = {
            "quote": melt_quote.quote,
            "amount": melt_quote.amount,
            "unit": melt_quote.unit,
            "method": melt_quote.method,
            "request": melt_quote.request,
            "fee_reserve": melt_quote.fee_reserve,
            "state": melt_quote.state.value,
            "expiry": melt_quote.expiry,
            "payment_preimage": melt_quote.payment_preimage,
            "change": melt_quote.change,
        }
        response = {**melt_quote.method_data, **response}
        return cls.model_validate(response)
