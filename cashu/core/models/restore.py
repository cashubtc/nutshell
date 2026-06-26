from typing import List

from pydantic import BaseModel, Field

from cashu.core.base import BlindedMessage, BlindedMessage_Deprecated, BlindedSignature
from cashu.core.settings import settings


class PostRestoreRequest(BaseModel):
    outputs: List[BlindedMessage] = Field(
        ..., max_length=settings.mint_max_request_length
    )


class PostRestoreRequest_Deprecated(BaseModel):
    outputs: List[BlindedMessage_Deprecated] = Field(
        ..., max_length=settings.mint_max_request_length
    )


class PostRestoreResponse(BaseModel):
    outputs: List[BlindedMessage] = []
    signatures: List[BlindedSignature] = []
