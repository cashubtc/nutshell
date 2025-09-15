from dataclasses import dataclass
from typing import Optional


class WalletError(Exception):
    msg: str

    def __init__(self, msg):
        super().__init__(msg)
        self.msg = msg


class BalanceTooLowError(WalletError):
    msg = "Balance too low"

    def __init__(self, msg: Optional[str] = None):
        super().__init__(msg or self.msg)


@dataclass(frozen=True)
class InputFeeExceedsLimitError(WalletError):
    actual_fee_ppk: int
    max_fee_ppk: int

    def __post_init__(self):
        msg = f"Input fee {self.actual_fee_ppk} ppk exceeds limit of {self.max_fee_ppk} ppk"
        super().__init__(msg)
