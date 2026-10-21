from typing import List

from pydantic import BaseModel, Field

from cashu.core.base import (
    BlindedMessage,
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
