from typing import Annotated, List

from pydantic import BaseModel, Field

from cashu.core.base import ProofState
from cashu.core.constants import MAX_PUBKEY_LEN
from cashu.core.settings import settings


class PostCheckStateRequest(BaseModel):
    Ys: List[Annotated[str, Field(max_length=MAX_PUBKEY_LEN)]] = Field(
        ..., max_length=settings.mint_max_request_length
    )


class PostCheckStateResponse(BaseModel):
    states: List[ProofState] = []
