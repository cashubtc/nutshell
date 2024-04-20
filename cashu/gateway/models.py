from typing import List, Optional, Union

from pydantic import BaseModel, Field

from ..core.base import (
    Proof,
)
from ..core.settings import settings


class GatewayMeltQuoteRequest(BaseModel):
    unit: str = Field(..., max_length=settings.mint_max_request_length)  # input unit
    request: str = Field(
        ..., max_length=settings.mint_max_request_length
    )  # output payment request
    mint: str = Field(..., max_length=settings.mint_max_request_length)  # mint url


class GatewayMeltQuoteResponse(BaseModel):
    quote: str  # quote id
    pubkey: str  # P2PK pubkey of the gateway
    amount: int  # input amount
    expiry: Optional[int]  # expiry of the quote


class GatewayMeltRequest(BaseModel):
    quote: str = Field(..., max_length=settings.mint_max_request_length)  # quote id
    inputs: List[Proof] = Field(..., max_items=settings.mint_max_request_length)


class GatewayMeltResponse(BaseModel):
    paid: Union[bool, None]
    payment_preimage: Union[str, None]