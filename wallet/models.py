from pydantic import BaseModel
from sqlite3 import Row


class Proof(dict):
    amount: int
    C_x: int
    C_y: int
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
