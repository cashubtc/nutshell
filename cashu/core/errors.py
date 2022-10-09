from pydantic import BaseModel


class CashuError(BaseModel):
    code = "000"
    error = "CashuError"


# class CashuError(Exception, BaseModel):
#     code = "000"
#     error = "CashuError"


# class MintException(CashuError):
#     code = 100
#     error = "Mint"


# class LightningException(MintException):
#     code = 200
#     error = "Lightning"


# class InvoiceNotPaidException(LightningException):
#     code = 201
#     error = "invoice not paid."
