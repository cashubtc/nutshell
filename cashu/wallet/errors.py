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
