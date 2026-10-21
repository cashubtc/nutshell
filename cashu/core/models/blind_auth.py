from typing import List

from pydantic import BaseModel, Field

from cashu.core.base import BlindedMessage, BlindedSignature
from cashu.core.settings import settings


class PostAuthBlindMintRequest(BaseModel):
    outputs: List[BlindedMessage] = Field(
        ...,
        max_length=settings.mint_max_request_length,
        description="Blinded messages for creating blind auth tokens.",
    )


class PostAuthBlindMintResponse(BaseModel):
    signatures: List[BlindedSignature] = []
