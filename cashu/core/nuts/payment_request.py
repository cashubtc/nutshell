from typing import List, Optional

from pydantic import BaseModel


class Transport(BaseModel):
    t: str  # type
    a: str  # target
    g: Optional[List[List[str]]] = None  # tags


class NUT10Option(BaseModel):
    k: str  # kind
    d: str  # data
    t: Optional[List[List[str]]] = None  # tags


class PaymentRequest(BaseModel):
    i: Optional[str] = None  # payment id
    a: Optional[int] = None  # amount
    u: Optional[str] = None  # unit
    s: Optional[bool] = None  # single use
    m: Optional[List[str]] = None  # mints
    d: Optional[str] = None  # description
    t: Optional[List[Transport]] = None  # transports
    nut10: Optional[NUT10Option] = None
