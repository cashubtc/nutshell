from sqlite3 import Row
from typing import List

from pydantic import BaseModel


class Proof(BaseModel):
    amount: int
    C: str
    secret: str
    reserved: bool = False  # whether this proof is reserved for sending

    @classmethod
    def from_row(cls, row: Row):
        return cls(
            amount=row[0],
            C=row[1],
            secret=row[2],
            reserved=row[3] or False,
        )

    @classmethod
    def from_dict(cls, d: dict):
        return cls(
            amount=d["amount"],
            C=d["C"],
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
