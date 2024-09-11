from typing import List

from pydantic import BaseModel, Field

from ...core.base import BlindedMessage, BlindedSignature
from ...core.settings import settings


class PostAuthBlindMintRequest(BaseModel):
    auth: str = Field(
        ...,
        max_length=settings.mint_max_request_length,
        description="Authentication token containing user identifying information.",
    )
    outputs: List[BlindedMessage] = Field(
        ...,
        max_items=settings.mint_max_request_length,
        description="Blinded messages for creating blind auth tokens.",
    )


class PostAuthBlindMintResponse(BaseModel):
    signatures: List[BlindedSignature] = []
