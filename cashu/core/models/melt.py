from typing import List, Optional, Union

from pydantic import BaseModel, Field

from cashu.core.base import (
    BlindedMessage,
    Proof,
)
from cashu.core.constants import MAX_QUOTE_ID_LEN
from cashu.core.settings import settings


class PostMeltRequest(BaseModel):
    quote: str = Field(..., max_length=MAX_QUOTE_ID_LEN)  # quote id
    inputs: List[Proof] = Field(..., max_length=settings.mint_max_request_length)
    outputs: Union[List[BlindedMessage], None] = Field(
        None, max_length=settings.mint_max_request_length
    )
    prefer_async: Optional[bool] = None
