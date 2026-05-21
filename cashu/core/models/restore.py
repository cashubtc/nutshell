from typing import List

from pydantic import BaseModel

from cashu.core.base import BlindedMessage, BlindedMessage_Deprecated, BlindedSignature


class PostRestoreRequest(BaseModel):
    outputs: List[BlindedMessage]


class PostRestoreRequest_Deprecated(BaseModel):
    outputs: List[BlindedMessage_Deprecated]


class PostRestoreResponse(BaseModel):
    outputs: List[BlindedMessage] = []
    signatures: List[BlindedSignature] = []
