from typing import List, Optional

from pydantic import BaseModel

from cashu.core.base import (
    BlindedMessage,
    BlindedMessage_Deprecated,
    BlindedSignature,
    Proof,
)


class PostSwapRequest(BaseModel):
    inputs: List[Proof]
    outputs: List[BlindedMessage]


class PostSwapResponse(BaseModel):
    signatures: List[BlindedSignature]


# deprecated since 0.13.0
class PostSwapRequest_Deprecated(BaseModel):
    proofs: List[Proof]
    amount: Optional[int] = None
    outputs: List[BlindedMessage_Deprecated]


class PostSwapResponse_Deprecated(BaseModel):
    promises: List[BlindedSignature] = []


class PostSwapResponse_Very_Deprecated(BaseModel):
    fst: List[BlindedSignature] = []
    snd: List[BlindedSignature] = []
    deprecated: str = "The amount field is deprecated since 0.13.0"
