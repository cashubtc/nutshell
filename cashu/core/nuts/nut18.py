import base64
from typing import List, Optional

import cbor2
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

    def serialize(self) -> str:
        # Exclude none fields to keep payload small matching spec intent (optional fields)
        obj = self.model_dump(exclude_none=True)
        data = cbor2.dumps(obj)
        encoded = base64.urlsafe_b64encode(data).decode().rstrip("=")
        return "creqA" + encoded

    def serialize_bech32m(self) -> str:
        """Serialize to NUT-26 Bech32m + TLV format."""
        from .nut26 import serialize as _serialize_bech32m
        return _serialize_bech32m(self)

    @classmethod
    def deserialize(cls, creq: str) -> "PaymentRequest":
        if creq.lower().startswith("creqb1"):
            from .nut26 import deserialize as _deserialize_bech32m
            return _deserialize_bech32m(creq)

        if not creq.startswith("creqA"):
            raise ValueError("Invalid prefix, expected 'creqA'")

        data_str = creq[5:]
        # Restore padding if needed
        padded = data_str + "=" * (-len(data_str) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        obj = cbor2.loads(decoded)
        return cls(**obj)
