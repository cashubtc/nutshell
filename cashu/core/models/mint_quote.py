from typing import Annotated, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cashu.core.base import MintQuote
from cashu.core.constants import (
    MAX_INVOICE_DESC_LEN,
    MAX_PUBKEY_LEN,
    MAX_QUOTE_ID_LEN,
    MAX_UNIT_LEN,
)
from cashu.core.settings import settings


class PostMintQuoteRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    unit: str = Field(..., max_length=MAX_UNIT_LEN)  # output unit
    amount: Optional[int] = Field(default=None, gt=0)  # method-specific output amount
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
    model_config = ConfigDict(extra="allow")

    quote: str  # quote id
    request: str  # input payment request
    amount: Optional[int] = None  # method-specific output amount
    unit: str  # output unit
    method: str  # payment method
    amount_paid: Optional[int] = None
    amount_issued: Optional[int] = None
    updated_at: Optional[int] = None
    state: str  # state of the quote
    expiry: Optional[int] = None  # expiry of the quote
    pubkey: Optional[str] = None  # NUT-20 quote lock pubkey

    @model_validator(mode="after")
    def validate_method_fields(self) -> "PostMintQuoteResponse":
        if self.method == "bolt11" and self.amount is None:
            raise ValueError("bolt11 mint quote responses require an amount")
        return self

    @classmethod
    def from_mint_quote(cls, mint_quote: MintQuote) -> "PostMintQuoteResponse":
        # Build the public wire object explicitly. MintQuote also contains internal
        # fields (for example checking_id) which must never become response extras.
        response = {
            "quote": mint_quote.quote,
            "request": mint_quote.request,
            "amount": mint_quote.amount or None,
            "unit": mint_quote.unit,
            "method": mint_quote.method,
            "amount_paid": mint_quote.amount_paid,
            "amount_issued": mint_quote.amount_issued,
            "updated_at": mint_quote.updated_at,
            "state": mint_quote.state.value,
            "expiry": mint_quote.expiry,
            "pubkey": mint_quote.pubkey,
        }
        # Processor-defined fields must never replace the normative NUT-04
        # envelope. Unknown, non-reserved fields remain available for custom
        # payment methods.
        response = {**mint_quote.method_data, **response}
        return cls.model_validate(response)
