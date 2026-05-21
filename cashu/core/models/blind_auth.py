from typing import List

from pydantic import BaseModel, Field

from cashu.core.base import BlindedMessage, BlindedSignature


class PostAuthBlindMintRequest(BaseModel):
    outputs: List[BlindedMessage] = Field(
        ...,
        description="Blinded messages for creating blind auth tokens.",
    )


class PostAuthBlindMintResponse(BaseModel):
    signatures: List[BlindedSignature] = []
