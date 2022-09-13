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

    @classmethod
    def from_row(cls, row: Row):
        return dict(
            amount=row[0],
            C=dict(
                x=int(row[1]),
                y=int(row[2]),
            ),
            secret=row[3],
        )


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


class MintPayload(BaseModel):
    amount: int
    B_: BasePoint


class MintPayloads(BaseModel):
    payloads: List[MintPayload] = []


class SplitPayload(BaseModel):
    proofs: List[Proof]
    amount: int
    output_data: MintPayloads
