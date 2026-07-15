from typing import Annotated, List, Optional

from pydantic import BaseModel, Field

from cashu.core.base import MintQuote
from cashu.core.constants import (
    MAX_INVOICE_DESC_LEN,
    MAX_PUBKEY_LEN,
    MAX_QUOTE_ID_LEN,
    MAX_UNIT_LEN,
)
from cashu.core.settings import settings


class PostMintQuoteRequest(BaseModel):
    unit: str = Field(..., max_length=MAX_UNIT_LEN)  # output unit
    amount: int = Field(..., gt=0)  # output amount
    description: Optional[str] = Field(
        default=None, max_length=MAX_INVOICE_DESC_LEN
    )  # invoice description
    pubkey: Optional[str] = Field(
        default=None, max_length=MAX_PUBKEY_LEN
    )  # NUT-20 quote lock pubkey


class PostMintQuoteCheckRequest(BaseModel):
    quotes: List[Annotated[str, Field(max_length=MAX_QUOTE_ID_LEN)]] = Field(
        ..., max_length=settings.mint_max_request_length
    )


class PostMintQuoteResponse(BaseModel):
    quote: str  # quote id
    request: str  # input payment request
    amount: int  # output amount
    unit: str  # output unit
    method: str  # payment method
    amount_paid: Optional[int] = None
    amount_issued: Optional[int] = None
    updated_at: Optional[int] = None
    state: str  # state of the quote
    expiry: Optional[int] = None  # expiry of the quote
    pubkey: Optional[str] = None  # NUT-20 quote lock pubkey

    @classmethod
    def from_mint_quote(cls, mint_quote: MintQuote) -> "PostMintQuoteResponse":
        to_dict = mint_quote.model_dump()
        # turn state into string
        to_dict["state"] = mint_quote.state.value
        to_dict["amount_paid"] = mint_quote.amount_paid
        to_dict["amount_issued"] = mint_quote.amount_issued
        to_dict["updated_at"] = mint_quote.updated_at
        return cls.model_validate(to_dict)
