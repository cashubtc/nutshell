from sqlite3 import Row
from typing import List

from pydantic import BaseModel


class BasePoint(BaseModel):
    """Named BasePoint because it conflicts with ecc.curve.Point"""

    x: int
    y: int


class Proof(BaseModel):
    amount: int
    C: BasePoint
    secret: str
    reserved: bool = False  # whether this proof is reserved for sending

    @classmethod
    def from_row(cls, row: Row):
        return cls(
            amount=row[0],
            C=dict(
                x=int(row[1]),
                y=int(row[2]),
            ),
            secret=row[3],
            reserved=row[4] or False,
        )

    @classmethod
    def from_dict(cls, d: dict):
        return cls(
            amount=d["amount"],
            C=dict(
                x=int(d["C"]["x"]),
                y=int(d["C"]["y"]),
            ),
            secret=d["secret"],
            reserved=d["reserved"] or False,
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
    B_: BasePoint


class BlindedSignature(BaseModel):
    amount: int
    C_: BasePoint

    @classmethod
    def from_dict(cls, d: dict):
        return cls(
            amount=d["amount"],
            C_=dict(
                x=int(d["C_"]["x"]),
                y=int(d["C_"]["y"]),
            ),
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
