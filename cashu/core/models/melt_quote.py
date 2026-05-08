from typing import List, Optional, Union

from pydantic import BaseModel, Field

from cashu.core.base import BlindedSignature, MeltQuote
from cashu.core.constants import MAX_PAYMENT_REQUEST_LEN, MAX_UNIT_LEN


class PostMeltRequestOptionMpp(BaseModel):
    amount: int = Field(gt=0)  # input amount


class PostMeltRequestOptions(BaseModel):
    mpp: Optional[PostMeltRequestOptionMpp]


class PostMeltQuoteRequest(BaseModel):
    unit: str = Field(..., max_length=MAX_UNIT_LEN)  # input unit
    request: str = Field(
        ..., max_length=MAX_PAYMENT_REQUEST_LEN
    )  # output payment request
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
    quote: str  # quote id
    amount: int  # input amount
    unit: Optional[
        str
    ]  # input unit (optional for BACKWARDS COMPAT mint response < 0.17.0)
    request: Optional[
        str
    ]  # output payment request (optional for BACKWARDS COMPAT mint response < 0.17.0)
    fee_reserve: int  # input fee reserve
    paid: Optional[bool] = (
        None  # whether the request has been paid # DEPRECATED as per NUT PR #136
    )
    state: Optional[str]  # state of the quote
    expiry: Optional[int]  # expiry of the quote
    payment_preimage: Optional[str] = None  # payment preimage
    change: Union[List[BlindedSignature], None] = None  # NUT-08 change

    @classmethod
    def from_melt_quote(self, melt_quote: MeltQuote) -> "PostMeltQuoteResponse":
        to_dict = melt_quote.model_dump()
        # turn state into string
        to_dict["state"] = melt_quote.state.value
        # add deprecated "paid" field
        to_dict["paid"] = melt_quote.paid
        return PostMeltQuoteResponse.model_validate(to_dict)
