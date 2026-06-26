from typing import Annotated, List, Union

from pydantic import BaseModel, Field

from cashu.core.base import Proof, ProofState
from cashu.core.constants import MAX_PAYMENT_REQUEST_LEN, MAX_PUBKEY_LEN
from cashu.core.settings import settings


class PostCheckStateRequest(BaseModel):
    Ys: List[Annotated[str, Field(max_length=MAX_PUBKEY_LEN)]] = Field(
        ..., max_length=settings.mint_max_request_length
    )


class PostCheckStateResponse(BaseModel):
    states: List[ProofState] = []


class CheckSpendableRequest_deprecated(BaseModel):
    proofs: List[Proof] = Field(..., max_length=settings.mint_max_request_length)


class CheckSpendableResponse_deprecated(BaseModel):
    spendable: List[bool]
    pending: List[bool]


class CheckFeesRequest_deprecated(BaseModel):
    pr: str = Field(..., max_length=MAX_PAYMENT_REQUEST_LEN)


class CheckFeesResponse_deprecated(BaseModel):
    fee: Union[int, None]
