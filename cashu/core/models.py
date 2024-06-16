from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field

from .base import (
    BlindedMessage,
    BlindedMessage_Deprecated,
    BlindedSignature,
    Proof,
    ProofState,
)
from .settings import settings

# ------- API -------

# ------- API: INFO -------


class MintMeltMethodSetting(BaseModel):
    method: str
    unit: str
    min_amount: Optional[int] = None
    max_amount: Optional[int] = None


class GetInfoResponse(BaseModel):
    name: Optional[str] = None
    pubkey: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    description_long: Optional[str] = None
    contact: Optional[List[List[str]]] = None
    motd: Optional[str] = None
    nuts: Optional[Dict[int, Any]] = None

    def supports(self, nut: int) -> Optional[bool]:
        return nut in self.nuts if self.nuts else None


class Nut15MppSupport(BaseModel):
    method: str
    unit: str
    mpp: bool


class GetInfoResponse_deprecated(BaseModel):
    name: Optional[str] = None
    pubkey: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    description_long: Optional[str] = None
    contact: Optional[List[List[str]]] = None
    nuts: Optional[List[str]] = None
    motd: Optional[str] = None
    parameter: Optional[dict] = None


# ------- API: KEYS -------


class KeysResponseKeyset(BaseModel):
    id: str
    unit: str
    keys: Dict[int, str]


class KeysResponse(BaseModel):
    keysets: List[KeysResponseKeyset]


class KeysetsResponseKeyset(BaseModel):
    id: str
    unit: str
    active: bool
    input_fee_ppk: Optional[int] = None


class KeysetsResponse(BaseModel):
    keysets: list[KeysetsResponseKeyset]


class KeysResponse_deprecated(BaseModel):
    __root__: Dict[str, str]


class KeysetsResponse_deprecated(BaseModel):
    keysets: list[str]


# ------- API: MINT QUOTE -------


class PostMintQuoteRequest(BaseModel):
    unit: str = Field(..., max_length=settings.mint_max_request_length)  # output unit
    amount: int = Field(..., gt=0)  # output amount


class PostMintQuoteResponse(BaseModel):
    quote: str  # quote id
    request: str  # input payment request
    paid: bool  # whether the request has been paid
    expiry: Optional[int]  # expiry of the quote


# ------- API: MINT -------


class PostMintRequest(BaseModel):
    quote: str = Field(..., max_length=settings.mint_max_request_length)  # quote id
    outputs: List[BlindedMessage] = Field(
        ..., max_items=settings.mint_max_request_length
    )


class PostMintResponse(BaseModel):
    signatures: List[BlindedSignature] = []


class GetMintResponse_deprecated(BaseModel):
    pr: str
    hash: str


class PostMintRequest_deprecated(BaseModel):
    outputs: List[BlindedMessage_Deprecated] = Field(
        ..., max_items=settings.mint_max_request_length
    )


class PostMintResponse_deprecated(BaseModel):
    promises: List[BlindedSignature] = []


# ------- API: MELT QUOTE -------


class PostMeltRequestOptionMpp(BaseModel):
    amount: int = Field(gt=0)  # input amount


class PostMeltRequestOptions(BaseModel):
    mpp: Optional[PostMeltRequestOptionMpp]


class PostMeltQuoteRequest(BaseModel):
    unit: str = Field(..., max_length=settings.mint_max_request_length)  # input unit
    request: str = Field(
        ..., max_length=settings.mint_max_request_length
    )  # output payment request
    options: Optional[PostMeltRequestOptions] = None

    @property
    def is_mpp(self) -> bool:
        if self.options and self.options.mpp:
            return True
        else:
            return False

    @property
    def mpp_amount(self) -> int:
        if self.is_mpp and self.options and self.options.mpp:
            return self.options.mpp.amount
        else:
            raise Exception("quote request is not mpp.")


class PostMeltQuoteResponse(BaseModel):
    quote: str  # quote id
    amount: int  # input amount
    fee_reserve: int  # input fee reserve
    paid: bool  # whether the request has been paid
    expiry: Optional[int]  # expiry of the quote


# ------- API: MELT -------


class PostMeltRequest(BaseModel):
    quote: str = Field(..., max_length=settings.mint_max_request_length)  # quote id
    inputs: List[Proof] = Field(..., max_items=settings.mint_max_request_length)
    outputs: Union[List[BlindedMessage], None] = Field(
        None, max_items=settings.mint_max_request_length
    )


class PostMeltResponse(BaseModel):
    paid: Union[bool, None]
    payment_preimage: Union[str, None]
    change: Union[List[BlindedSignature], None] = None


class PostMeltRequest_deprecated(BaseModel):
    proofs: List[Proof] = Field(..., max_items=settings.mint_max_request_length)
    pr: str = Field(..., max_length=settings.mint_max_request_length)
    outputs: Union[List[BlindedMessage_Deprecated], None] = Field(
        None, max_items=settings.mint_max_request_length
    )


class PostMeltResponse_deprecated(BaseModel):
    paid: Union[bool, None]
    preimage: Union[str, None]
    change: Union[List[BlindedSignature], None] = None


# ------- API: SPLIT -------


class PostSplitRequest(BaseModel):
    inputs: List[Proof] = Field(..., max_items=settings.mint_max_request_length)
    outputs: List[BlindedMessage] = Field(
        ..., max_items=settings.mint_max_request_length
    )


class PostSplitResponse(BaseModel):
    signatures: List[BlindedSignature]


# deprecated since 0.13.0
class PostSplitRequest_Deprecated(BaseModel):
    proofs: List[Proof] = Field(..., max_items=settings.mint_max_request_length)
    amount: Optional[int] = None
    outputs: List[BlindedMessage_Deprecated] = Field(
        ..., max_items=settings.mint_max_request_length
    )


class PostSplitResponse_Deprecated(BaseModel):
    promises: List[BlindedSignature] = []


class PostSplitResponse_Very_Deprecated(BaseModel):
    fst: List[BlindedSignature] = []
    snd: List[BlindedSignature] = []
    deprecated: str = "The amount field is deprecated since 0.13.0"


# ------- API: CHECK -------


class PostCheckStateRequest(BaseModel):
    Ys: List[str] = Field(..., max_items=settings.mint_max_request_length)


class PostCheckStateResponse(BaseModel):
    states: List[ProofState] = []


class CheckSpendableRequest_deprecated(BaseModel):
    proofs: List[Proof] = Field(..., max_items=settings.mint_max_request_length)


class CheckSpendableResponse_deprecated(BaseModel):
    spendable: List[bool]
    pending: List[bool]


class CheckFeesRequest_deprecated(BaseModel):
    pr: str = Field(..., max_length=settings.mint_max_request_length)


class CheckFeesResponse_deprecated(BaseModel):
    fee: Union[int, None]


# ------- API: RESTORE -------


class PostRestoreRequest(BaseModel):
    outputs: List[BlindedMessage] = Field(
        ..., max_items=settings.mint_max_request_length
    )


class PostRestoreRequest_Deprecated(BaseModel):
    outputs: List[BlindedMessage_Deprecated] = Field(
        ..., max_items=settings.mint_max_request_length
    )


class PostRestoreResponse(BaseModel):
    outputs: List[BlindedMessage] = []
    signatures: List[BlindedSignature] = []
    promises: Optional[List[BlindedSignature]] = []  # deprecated since 0.15.1

    # duplicate value of "signatures" for backwards compatibility with old clients < 0.15.1
    def __init__(self, **data):
        super().__init__(**data)
        self.promises = self.signatures
