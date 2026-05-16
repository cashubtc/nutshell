from typing import List, Optional, Union

from pydantic import BaseModel, Field

from cashu.core.base import (
    BlindedMessage,
    BlindedMessage_Deprecated,
    BlindedSignature,
    Proof,
)
from cashu.core.constants import MAX_PAYMENT_REQUEST_LEN, MAX_QUOTE_ID_LEN
from cashu.core.settings import settings


class PostMeltRequest(BaseModel):
    quote: str = Field(..., max_length=MAX_QUOTE_ID_LEN)  # quote id
    inputs: List[Proof] = Field(..., max_length=settings.mint_max_request_length)
    outputs: Union[List[BlindedMessage], None] = Field(
        None, max_length=settings.mint_max_request_length
    )
    prefer_async: Optional[bool] = None


class PostMeltResponse_deprecated(BaseModel):
    paid: Union[bool, None]
    preimage: Union[str, None]
    change: Union[List[BlindedSignature], None] = None


class PostMeltRequest_deprecated(BaseModel):
    proofs: List[Proof] = Field(..., max_length=settings.mint_max_request_length)
    pr: str = Field(..., max_length=MAX_PAYMENT_REQUEST_LEN)
    outputs: Union[List[BlindedMessage_Deprecated], None] = Field(
        None, max_length=settings.mint_max_request_length
    )
