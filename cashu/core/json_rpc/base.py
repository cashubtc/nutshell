from enum import Enum
from typing import List

from pydantic import BaseModel, Field

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
    BOLT11_MINT_QUOTE = "bolt11_mint_quote"
    BOLT11_MELT_QUOTE = "bolt11_melt_quote"
    PROOF_STATE = "proof_state"


class JSONRPCStatus(Enum):
    OK = "OK"


class JSONRPCSubscribeParams(BaseModel):
    kind: JSONRPCSubscriptionKinds
    filters: List[str] = Field(..., max_length=settings.mint_max_request_length)
    subId: str


class JSONRPCUnsubscribeParams(BaseModel):
    subId: str


class JSONRPCNotficationParams(BaseModel):
    subId: str
    payload: dict


class JSONRRPCSubscribeResponse(BaseModel):
    status: JSONRPCStatus
    subId: str
