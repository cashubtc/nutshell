from typing import List, Optional

from pydantic import BaseModel, Field

from cashu.core.base import BlindedMessage, BlindedMessage_Deprecated, BlindedSignature
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


class GetMintResponse_deprecated(BaseModel):
    pr: str
    hash: str


class PostMintRequest_deprecated(BaseModel):
    outputs: List[BlindedMessage_Deprecated] = Field(
        ..., max_length=settings.mint_max_request_length
    )


class PostMintResponse_deprecated(BaseModel):
    promises: List[BlindedSignature] = []
