from typing import List, Optional

from pydantic import BaseModel, Field

from cashu.core.base import (
    BlindedMessage,
    BlindedMessage_Deprecated,
    BlindedSignature,
    Proof,
)
from cashu.core.settings import settings


class PostSwapRequest(BaseModel):
    inputs: List[Proof] = Field(..., max_length=settings.mint_max_request_length)
    outputs: List[BlindedMessage] = Field(
        ..., max_length=settings.mint_max_request_length
    )


class PostSwapResponse(BaseModel):
    signatures: List[BlindedSignature]


# deprecated since 0.13.0
class PostSwapRequest_Deprecated(BaseModel):
    proofs: List[Proof] = Field(..., max_length=settings.mint_max_request_length)
    amount: Optional[int] = None
    outputs: List[BlindedMessage_Deprecated] = Field(
        ..., max_length=settings.mint_max_request_length
    )


class PostSwapResponse_Deprecated(BaseModel):
    promises: List[BlindedSignature] = []


class PostSwapResponse_Very_Deprecated(BaseModel):
    fst: List[BlindedSignature] = []
    snd: List[BlindedSignature] = []
    deprecated: str = "The amount field is deprecated since 0.13.0"
