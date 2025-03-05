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


class OutputsAlreadySignedError(CashuError):
    detail = "outputs have already been signed before."
    code = 10002

    def __init__(self, detail: Optional[str] = None, code: Optional[int] = None):
        super().__init__(detail or self.detail, code=code or self.code)


class InvalidProofsError(CashuError):
    detail = "proofs could not be verified"
    code = 10003

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


class TransactionNotBalancedError(TransactionError):
    code = 11002

    def __init__(self, detail):
        super().__init__(detail, code=self.code)


class SecretTooLongError(TransactionError):
    code = 11003

    def __init__(self, detail="secret too long"):
        super().__init__(detail, code=self.code)


class NoSecretInProofsError(TransactionError):
    detail = "no secret in proofs"
    code = 11004

    def __init__(self):
        super().__init__(self.detail, code=self.code)


class TransactionUnitError(TransactionError):
    code = 11005

    def __init__(self, detail):
        super().__init__(detail, code=self.code)


class TransactionAmountExceedsLimitError(TransactionError):
    code = 11006

    def __init__(self, detail):
        super().__init__(detail, code=self.code)


class TransactionDuplicateInputsError(TransactionError):
    detail = "Duplicate inputs provided"
    code = 11007

    def __init__(self, detail: Optional[str] = None):
        super().__init__(detail, code=self.code)


class TransactionDuplicateOutputsError(TransactionError):
    detail = "Duplicate outputs provided"
    code = 11008

    def __init__(self, detail: Optional[str] = None):
        super().__init__(detail, code=self.code)


class TransactionMultipleUnitsError(TransactionError):
    detail = "Inputs/Outputs of multiple units"
    code = 11009

    def __init__(self, detail: Optional[str] = None):
        super().__init__(detail, code=self.code)


class TransactionUnitMismatchError(TransactionError):
    detail = "Inputs and outputs not of same unit"
    code = 11010

    def __init__(self, detail: Optional[str] = None):
        super().__init__(detail, code=self.code)


class KeysetError(CashuError):
    detail = "keyset error"
    code = 12000

    def __init__(self, detail: Optional[str] = None, code: Optional[int] = None):
        super().__init__(detail or self.detail, code=code or self.code)


class KeysetNotFoundError(KeysetError):
    detail = "keyset not found"
    code = 12001

    def __init__(self, keyset_id: Optional[str] = None):
        if keyset_id:
            self.detail = f"{self.detail}: {keyset_id}"
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
        super().__init__(self.detail, code=self.code)


class LightningPaymentFailedError(CashuError):
    detail = "Lightning payment failed"
    code = 20004

    def __init__(self, detail: Optional[str] = None):
        super().__init__(detail or self.detail, code=self.code)


class QuoteSignatureInvalidError(CashuError):
    detail = "Signature for mint request invalid"
    code = 20008

    def __init__(self):
        super().__init__(self.detail, code=self.code)


class QuoteRequiresPubkeyError(CashuError):
    detail = "Pubkey required for mint quote"
    code = 20009

    def __init__(self):
        super().__init__(self.detail, code=self.code)


class ClearAuthRequiredError(CashuError):
    detail = "Endpoint requires clear auth"
    code = 80001

    def __init__(self):
        super().__init__(self.detail, code=self.code)


class ClearAuthFailedError(CashuError):
    detail = "Clear authentication failed"
    code = 80002

    def __init__(self):
        super().__init__(self.detail, code=self.code)


class BlindAuthRequiredError(CashuError):
    detail = "Endpoint requires blind auth"
    code = 81001

    def __init__(self):
        super().__init__(self.detail, code=self.code)


class BlindAuthFailedError(CashuError):
    detail = "Blind authentication failed"
    code = 81002

    def __init__(self):
        super().__init__(self.detail, code=self.code)


class BlindAuthAmountExceededError(CashuError):
    detail = "Maximum blind auth amount exceeded"
    code = 81003

    def __init__(self, detail: Optional[str] = None):
        super().__init__(detail or self.detail, code=self.code)


class BlindAuthRateLimitExceededError(CashuError):
    detail = "Blind auth token mint rate limit exceeded"
    code = 81004

    def __init__(self):
        super().__init__(self.detail, code=self.code)
