from sqlite3 import Row
from typing import List

from pydantic import BaseModel


class Proof(BaseModel):
    amount: int
    C: str
    secret: str
    reserved: bool = False  # whether this proof is reserved for sending
    send_id: str = ""  # unique ID of send attempt
    time_created: str = ""
    time_reserved: str = ""

    @classmethod
    def from_row(cls, row: Row):
        return cls(
            amount=row[0],
            C=row[1],
            secret=row[2],
            reserved=row[3] or False,
            send_id=row[4] or "",
            time_created=row[5] or "",
            time_reserved=row[6] or "",
        )

    @classmethod
    def from_dict(cls, d: dict):
        return cls(
            amount=d["amount"],
            C=d["C"],
            secret=d["secret"],
            reserved=d["reserved"] or False,
            send_id=d["send_id"] or "",
            time_created=d["time_created"] or "",
            time_reserved=d["time_reserved"] or "",
        )

    def __getitem__(self, key):
        return self.__getattribute__(key)

    def __setitem__(self, key, val):
        self.__setattr__(key, val)


class Proofs(BaseModel):
    """TODO: Use this model"""

    proofs: List[Proof]


class Invoice(BaseModel):
    amount: int
    pr: str
    hash: str
    issued: bool = False

    @classmethod
    def from_row(cls, row: Row):
        return cls(
            amount=int(row[0]),
            pr=str(row[1]),
            hash=str(row[2]),
            issued=bool(row[3]),
        )


class BlindedMessage(BaseModel):
    amount: int
    B_: str


class BlindedSignature(BaseModel):
    amount: int
    C_: str

    @classmethod
    def from_dict(cls, d: dict):
        return cls(
            amount=d["amount"],
            C_=d["C_"],
        )


class MintPayloads(BaseModel):
    blinded_messages: List[BlindedMessage] = []


class SplitPayload(BaseModel):
    proofs: List[Proof]
    amount: int
    output_data: MintPayloads


class CheckPayload(BaseModel):
    proofs: List[Proof]


class MeltPayload(BaseModel):
    proofs: List[Proof]
    amount: int
    invoice: str
