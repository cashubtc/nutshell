from typing import List, Optional

from pydantic import BaseModel, Field

from cashu.core.base import BlindedMessage, BlindedMessage_Deprecated, BlindedSignature
from cashu.core.constants import MAX_QUOTE_ID_LEN, MAX_SIG_LEN


class PostMintRequest(BaseModel):
    quote: str = Field(..., max_length=MAX_QUOTE_ID_LEN)  # quote id
    outputs: List[BlindedMessage]
    signature: Optional[str] = Field(
        default=None, max_length=MAX_SIG_LEN
    )  # NUT-20 quote signature


class PostMintResponse(BaseModel):
    signatures: List[BlindedSignature] = []


class GetMintResponse_deprecated(BaseModel):
    pr: str
    hash: str


class PostMintRequest_deprecated(BaseModel):
    outputs: List[BlindedMessage_Deprecated]


class PostMintResponse_deprecated(BaseModel):
    promises: List[BlindedSignature] = []
