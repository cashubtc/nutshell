from enum import Enum
from typing import Annotated, List, Union

from pydantic import BaseModel, Field, field_validator

from ..constants import MAX_QUOTE_ID_LEN
from ..settings import settings


class JSONRPCRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: int
    method: str
    params: dict


class JSONRPCResponse(BaseModel):
    jsonrpc: str = "2.0"
    result: dict
    id: int


class JSONRPCNotification(BaseModel):
    jsonrpc: str = "2.0"
    method: str
    params: dict


class JSONRPCErrorCode(Enum):
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    SERVER_ERROR = -32000
    APPLICATION_ERROR = -32099
    SYSTEM_ERROR = -32098
    TRANSPORT_ERROR = -32097


class JSONRPCError(BaseModel):
    code: JSONRPCErrorCode
    message: str


class JSONRPCErrorResponse(BaseModel):
    jsonrpc: str = "2.0"
    error: JSONRPCError
    id: int


# Cashu Websocket protocol


class JSONRPCMethods(Enum):
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"


class JSONRPCSubscriptionKinds(Enum):
    MINT_QUOTE = "mint_quote"
    MELT_QUOTE = "melt_quote"
    PROOF_STATE = "proof_state"

    # TODO: Remove these deprecated bolt11-specific aliases once old websocket
    # clients have been migrated to the method-independent NUT-17 kinds.
    BOLT11_MINT_QUOTE = "bolt11_mint_quote"
    BOLT11_MELT_QUOTE = "bolt11_melt_quote"

    @classmethod
    def normalize(
        cls, kind: Union["JSONRPCSubscriptionKinds", str]
    ) -> "JSONRPCSubscriptionKinds":
        parsed_kind = kind if isinstance(kind, cls) else cls(kind)

        if parsed_kind == cls.BOLT11_MINT_QUOTE:
            return cls.MINT_QUOTE
        if parsed_kind == cls.BOLT11_MELT_QUOTE:
            return cls.MELT_QUOTE

        return parsed_kind


class JSONRPCStatus(Enum):
    OK = "OK"


class JSONRPCSubscribeParams(BaseModel):
    kind: JSONRPCSubscriptionKinds
    filters: List[Annotated[str, Field(max_length=MAX_QUOTE_ID_LEN)]] = Field(
        ..., max_length=settings.mint_max_request_length
    )
    subId: str

    @field_validator("kind", mode="before")
    @classmethod
    def normalize_kind(cls, kind):
        return JSONRPCSubscriptionKinds.normalize(kind)


class JSONRPCUnsubscribeParams(BaseModel):
    subId: str


class JSONRPCNotficationParams(BaseModel):
    subId: str
    payload: dict


class JSONRRPCSubscribeResponse(BaseModel):
    status: JSONRPCStatus
    subId: str
