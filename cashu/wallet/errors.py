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


class InputFeeExceedsLimitError(WalletError):
    def __init__(self, actual_fee_ppk: int, max_fee_ppk: int):
        self.actual_fee_ppk = actual_fee_ppk
        self.max_fee_ppk = max_fee_ppk
        msg = f"Input fee {actual_fee_ppk} ppk exceeds limit of {max_fee_ppk} ppk"
        super().__init__(msg)
