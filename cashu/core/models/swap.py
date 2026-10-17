from typing import List, Optional

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
    unpoisonable: bool = False


class PostSwapResponse(BaseModel):
    signatures: List[BlindedSignature]
    unpoisonable_r: Optional[str] = Field(
        default=None, exclude_if=lambda value: value is None
    )
