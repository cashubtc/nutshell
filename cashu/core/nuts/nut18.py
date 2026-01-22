import base64
import json
from typing import List, Optional

import cbor2
from pydantic import BaseModel

from ...core.base import Proof
from ...core.nuts.nut20 import BlindedMessage


class Transport(BaseModel):
    t: str  # type
    a: str  # target
    g: Optional[List[List[str]]] = None  # tags


class NUT10Option(BaseModel):
    k: str  # kind
    d: str  # data
    t: Optional[List[List[str]]] = None  # tags


class PaymentRequest(BaseModel):
    i: Optional[str] = None  # id
    a: Optional[int] = None  # amount
    u: Optional[str] = None  # unit
    s: Optional[bool] = None  # single use
    m: Optional[List[str]] = None  # mints
    d: Optional[str] = None  # description
    t: Optional[List[Transport]] = None  # transports
    nut10: Optional[NUT10Option] = None  # NUT-10 locking condition

    def to_dict(self):
        # exclude None fields to keep it compact
        return self.dict(exclude_none=True)

    def serialize(self) -> str:
        prefix = "creqA"
        data = self.to_dict()
        # cbor encode
        cbor_data = cbor2.dumps(data)
        # base64 urlsafe encode
        b64_data = base64.urlsafe_b64encode(cbor_data).decode()
        return prefix + b64_data

    @classmethod
    def deserialize(cls, encoded: str) -> "PaymentRequest":
        prefix = "creqA"
        if not encoded.startswith(prefix):
            raise ValueError(f"Invalid payment request prefix. Expected {prefix}")

        b64_data = encoded[len(prefix) :]
        # Add padding if necessary
        b64_data += "=" * (4 - len(b64_data) % 4)

        cbor_data = base64.urlsafe_b64decode(b64_data)
        data = cbor2.loads(cbor_data)
        return cls(**data)


class PaymentRequestPayload(BaseModel):
    id: Optional[str] = None
    memo: Optional[str] = None
    mint: str
    unit: str
    proofs: List[Proof]

    def to_json(self) -> str:
        # Use Proof.to_dict() for serialization
        return json.dumps(
            {
                "id": self.id,
                "memo": self.memo,
                "mint": self.mint,
                "unit": self.unit,
                "proofs": [p.to_dict(include_dleq=True) for p in self.proofs],
            }
        )
