from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, root_validator

from .base import (
    BlindedMessage,
    BlindedMessage_Deprecated,
    BlindedSignature,
    MeltQuote,
    MintQuote,
    Proof,
    ProofState,
)
from .settings import settings

# ------- API -------

# ------- API: INFO -------


class MintMethodSetting(BaseModel):
    method: str
    unit: str
    min_amount: Optional[int] = None
    max_amount: Optional[int] = None
    description: Optional[bool] = None


class MeltMethodSetting(BaseModel):
    method: str
    unit: str
    min_amount: Optional[int] = None
    max_amount: Optional[int] = None


class MintInfoContact(BaseModel):
    method: str
    info: str


class GetInfoResponse(BaseModel):
    name: Optional[str] = None
    pubkey: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    description_long: Optional[str] = None
    contact: Optional[List[MintInfoContact]] = None
    motd: Optional[str] = None
    icon_url: Optional[str] = None
    urls: Optional[List[str]] = None
    time: Optional[int] = None
    nuts: Optional[Dict[int, Any]] = None

    def supports(self, nut: int) -> Optional[bool]:
        return nut in self.nuts if self.nuts else None

    # BEGIN DEPRECATED: NUT-06 contact field change
    # NUT-06 PR: https://github.com/cashubtc/nuts/pull/117
    @root_validator(pre=True)
    def preprocess_deprecated_contact_field(cls, values):
        if "contact" in values and values["contact"]:
            if isinstance(values["contact"][0], list):
                values["contact"] = [
                    MintInfoContact(method=method, info=info)
                    for method, info in values["contact"]
                    if method and info
                ]
        return values

    # END DEPRECATED: NUT-06 contact field change


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
    description: Optional[str] = Field(
        default=None, max_length=settings.mint_max_request_length
    )  # invoice description


class PostMintQuoteResponse(BaseModel):
    quote: str  # quote id
    request: str  # input payment request
    paid: Optional[bool]  # DEPRECATED as per NUT-04 PR #141
    state: Optional[str]  # state of the quote
    expiry: Optional[int]  # expiry of the quote

    @classmethod
    def from_mint_quote(self, mint_quote: MintQuote) -> "PostMintQuoteResponse":
        to_dict = mint_quote.dict()
        # turn state into string
        to_dict["state"] = mint_quote.state.value
        return PostMintQuoteResponse.parse_obj(to_dict)


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
    paid: Optional[bool] = (
        None  # whether the request has been paid # DEPRECATED as per NUT PR #136
    )
    state: Optional[str]  # state of the quote
    expiry: Optional[int]  # expiry of the quote
    payment_preimage: Optional[str] = None  # payment preimage
    change: Union[List[BlindedSignature], None] = None  # NUT-08 change

    @classmethod
    def from_melt_quote(self, melt_quote: MeltQuote) -> "PostMeltQuoteResponse":
        to_dict = melt_quote.dict()
        # turn state into string
        to_dict["state"] = melt_quote.state.value
        # add deprecated "paid" field
        to_dict["paid"] = melt_quote.paid
        return PostMeltQuoteResponse.parse_obj(to_dict)


# ------- API: MELT -------


class PostMeltRequest(BaseModel):
    quote: str = Field(..., max_length=settings.mint_max_request_length)  # quote id
    inputs: List[Proof] = Field(..., max_items=settings.mint_max_request_length)
    outputs: Union[List[BlindedMessage], None] = Field(
        None, max_items=settings.mint_max_request_length
    )


class PostMeltResponse_deprecated(BaseModel):
    paid: Union[bool, None]
    preimage: Union[str, None]
    change: Union[List[BlindedSignature], None] = None


class PostMeltRequest_deprecated(BaseModel):
    proofs: List[Proof] = Field(..., max_items=settings.mint_max_request_length)
    pr: str = Field(..., max_length=settings.mint_max_request_length)
    outputs: Union[List[BlindedMessage_Deprecated], None] = Field(
        None, max_items=settings.mint_max_request_length
    )


# ------- API: SPLIT -------


class PostSwapRequest(BaseModel):
    inputs: List[Proof] = Field(..., max_items=settings.mint_max_request_length)
    outputs: List[BlindedMessage] = Field(
        ..., max_items=settings.mint_max_request_length
    )


class PostSwapResponse(BaseModel):
    signatures: List[BlindedSignature]


# deprecated since 0.13.0
class PostSwapRequest_Deprecated(BaseModel):
    proofs: List[Proof] = Field(..., max_items=settings.mint_max_request_length)
    amount: Optional[int] = None
    outputs: List[BlindedMessage_Deprecated] = Field(
        ..., max_items=settings.mint_max_request_length
    )


class PostSwapResponse_Deprecated(BaseModel):
    promises: List[BlindedSignature] = []


class PostSwapResponse_Very_Deprecated(BaseModel):
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
