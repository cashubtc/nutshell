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
    amount: Optional[
        int
    ]  # output amount (optional for BACKWARDS COMPAT mint response < 0.17.0)
    unit: Optional[
        str
    ]  # output unit (optional for BACKWARDS COMPAT mint response <  0.17.0)
    amount_paid: Optional[int] = None
    amount_issued: Optional[int] = None
    updated_at: Optional[int] = None
    state: Optional[str] = None  # state of the quote (optional for backwards compat)
    expiry: Optional[int] = None  # expiry of the quote
    pubkey: Optional[str] = None  # NUT-20 quote lock pubkey

    @classmethod
    def from_mint_quote(cls, mint_quote: MintQuote) -> "PostMintQuoteResponse":
        if hasattr(mint_quote, "model_dump"):
            to_dict = mint_quote.model_dump()
        else:
            to_dict = {
                "quote": mint_quote.quote,
                "request": mint_quote.request,
                "amount": mint_quote.amount,
                "unit": mint_quote.unit,
                "state": getattr(mint_quote, "state", None),
                "expiry": getattr(mint_quote, "expiry", None),
                "pubkey": getattr(mint_quote, "pubkey", None),
            }

        if hasattr(to_dict.get("state"), "value"):
            to_dict["state"] = to_dict["state"].value
        elif hasattr(mint_quote, "state") and hasattr(mint_quote.state, "value"):
            to_dict["state"] = mint_quote.state.value

        amount_paid = getattr(mint_quote, "amount_paid", None)
        if amount_paid is None:
            state_val = to_dict.get("state")
            if state_val in ["PAID", "ISSUED"]:
                amount_paid = mint_quote.amount
            else:
                amount_paid = 0
        to_dict["amount_paid"] = amount_paid

        amount_issued = getattr(mint_quote, "amount_issued", None)
        if amount_issued is None:
            state_val = to_dict.get("state")
            if state_val == "ISSUED":
                amount_issued = mint_quote.amount
            else:
                amount_issued = 0
        to_dict["amount_issued"] = amount_issued

        updated_at = getattr(mint_quote, "updated_at", None)
        if updated_at is None:
            updated_at = getattr(mint_quote, "created_time", 0) or getattr(mint_quote, "expiry", 0) or 0
        to_dict["updated_at"] = updated_at

        return cls.model_validate(to_dict)
