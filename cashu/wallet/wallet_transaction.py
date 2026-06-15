from dataclasses import dataclass
from enum import Enum
from typing import Optional


class WalletTransactionState(Enum):
    mint = "mint"
    melt = "melt"
    send = "send"
    receive = "receive"

    def __str__(self):
        return self.name


@dataclass
class WalletTransaction:
    id: int
    tx_type: str
    amount: int
    unit: str
    mint: str
    state: str
    created_time: int
    quote_id: Optional[str] = None
    fee: Optional[int] = None
    preimage: Optional[str] = None

    @classmethod
    def from_row(cls, row) -> "WalletTransaction":
        return cls(
            id=row["id"],
            tx_type=row["type"],
            amount=row["amount"],
            unit=row["unit"],
            mint=row["mint"],
            state=row["state"],
            created_time=row["created_time"],
            quote_id=row["quote_id"],
            fee=row["fee"],
            preimage=row["preimage"],
        )
