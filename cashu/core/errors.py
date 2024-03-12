from typing import Optional


class CashuError(Exception):
    code: int
    detail: str

    def __init__(self, detail, code=0):
        super().__init__(detail)
        self.code = code
        self.detail = detail


class NotAllowedError(CashuError):
    detail = "not allowed"
    code = 10000

    def __init__(self, detail: Optional[str] = None, code: Optional[int] = None):
        super().__init__(detail or self.detail, code=code or self.code)


class TransactionError(CashuError):
    detail = "transaction error"
    code = 11000

    def __init__(self, detail: Optional[str] = None, code: Optional[int] = None):
        super().__init__(detail or self.detail, code=code or self.code)


class TokenAlreadySpentError(TransactionError):
    detail = "Token already spent."
    code = 11001

    def __init__(self):
        super().__init__(self.detail, code=self.code)


class SecretTooLongError(TransactionError):
    detail = "secret too long"
    code = 11003

    def __init__(self):
        super().__init__(self.detail, code=self.code)


class NoSecretInProofsError(TransactionError):
    detail = "no secret in proofs"
    code = 11004

    def __init__(self):
        super().__init__(self.detail, code=self.code)


class KeysetError(CashuError):
    detail = "keyset error"
    code = 12000

    def __init__(self, detail: Optional[str] = None, code: Optional[int] = None):
        super().__init__(detail or self.detail, code=code or self.code)


class KeysetNotFoundError(KeysetError):
    detail = "keyset not found"
    code = 12001

    def __init__(self):
        super().__init__(self.detail, code=self.code)


class LightningError(CashuError):
    detail = "Lightning error"
    code = 20000

    def __init__(self, detail: Optional[str] = None, code: Optional[int] = None):
        super().__init__(detail or self.detail, code=code or self.code)


class QuoteNotPaidError(CashuError):
    detail = "quote not paid"
    code = 20001

    def __init__(self):
        super().__init__(self.detail, code=2001)
