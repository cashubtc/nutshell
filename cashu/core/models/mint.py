from typing import Annotated, List, Optional

from pydantic import BaseModel, Field

from cashu.core.base import BlindedMessage, BlindedSignature
from cashu.core.constants import MAX_QUOTE_ID_LEN, MAX_SIG_LEN
from cashu.core.settings import settings


class PostMintRequest(BaseModel):
    quote: str = Field(..., max_length=MAX_QUOTE_ID_LEN)  # quote id
    outputs: List[BlindedMessage] = Field(
        ..., max_length=settings.mint_max_request_length
    )
    signature: Optional[str] = Field(
        default=None, max_length=MAX_SIG_LEN
    )  # NUT-20 quote signature


class PostMintResponse(BaseModel):
    signatures: List[BlindedSignature] = []


class PostMintBatchRequest(BaseModel):
    quotes: List[Annotated[str, Field(max_length=MAX_QUOTE_ID_LEN)]] = Field(..., max_length=settings.mint_max_request_length)
    quote_amounts: Optional[List[int]] = Field(default=None, max_length=settings.mint_max_request_length)
    outputs: List[BlindedMessage] = Field(
        ..., max_length=settings.mint_max_request_length
    )
    signatures: Optional[List[Optional[str]]] = Field(
        default=None, max_length=settings.mint_max_request_length
    )


class PostMintBatchResponse(BaseModel):
    signatures: List[BlindedSignature] = []
