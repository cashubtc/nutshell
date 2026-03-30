from typing import List, Optional

from pydantic import BaseModel, Field

from cashu.core.base import BlindedMessage, BlindedMessage_Deprecated, BlindedSignature
from cashu.core.settings import settings


class PostMintRequest(BaseModel):
    quote: str = Field(..., max_length=settings.mint_max_request_length)  # quote id
    outputs: List[BlindedMessage] = Field(
        ..., max_length=settings.mint_max_request_length
    )
    signature: Optional[str] = Field(
        default=None, max_length=settings.mint_max_request_length
    )  # NUT-20 quote signature


class PostMintResponse(BaseModel):
    signatures: List[BlindedSignature] = []


class GetMintResponse_deprecated(BaseModel):
    pr: str
    hash: str


class PostMintRequest_deprecated(BaseModel):
    outputs: List[BlindedMessage_Deprecated] = Field(
        ..., max_length=settings.mint_max_request_length
    )


class PostMintResponse_deprecated(BaseModel):
    promises: List[BlindedSignature] = []
