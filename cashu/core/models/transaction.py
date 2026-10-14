from typing import List, Optional

from pydantic import BaseModel, Field

from cashu.core.base import BlindedMessage, BlindedSignature, Proof
from cashu.core.constants import MAX_PUBKEY_LEN, MAX_QUOTE_ID_LEN, MAX_WITNESS_LEN
from cashu.core.crypto.transcript import derived_quote_id
from cashu.core.settings import settings

from .melt_quote import PostMeltQuoteResponse
from .mint_quote import PostMintQuoteResponse


class TransactionQuoteInput(BaseModel):
    quote: str = Field(..., max_length=MAX_QUOTE_ID_LEN)
    amount: int = Field(..., gt=0)  # amount this transaction issues against the quote
    witness: str = Field(..., max_length=MAX_WITNESS_LEN)


class TransactionMeltOutput(BaseModel):
    quote: str = Field(..., max_length=MAX_QUOTE_ID_LEN)
    fee_reserve: int = Field(..., ge=0)  # the reserve this transaction commits
    fee_index: Optional[int] = None  # NUT-30 quotes with fee_options


class TransactionChangeOutput(BaseModel):
    # Omitted for an id bound to the transaction's inputs (NUT-XX).
    id_preimage: Optional[str] = Field(None, pattern=r"^[0-9a-fA-F]{64}$")
    pubkey: str = Field(..., max_length=MAX_PUBKEY_LEN)  # change quote lock key
    amount: Optional[int] = Field(None, gt=0)  # omitted on the remainder quote

    @property
    def quote_id(self) -> Optional[str]:
        """The change quote's derived id (NUT-04), None if bound to the inputs."""
        if self.id_preimage is None:
            return None
        return derived_quote_id(bytes.fromhex(self.id_preimage))


class PostTransactionRequest(BaseModel):
    proof_inputs: List[Proof] = Field([], max_length=settings.mint_max_request_length)
    mint_quote_inputs: List[TransactionQuoteInput] = Field(
        [], max_length=settings.mint_max_request_length
    )
    blinded_outputs: List[BlindedMessage] = Field(
        [], max_length=settings.mint_max_request_length
    )
    # Multi-melt is reserved (NUT-XX).
    melt_quote_outputs: List[TransactionMeltOutput] = Field([], max_length=1)
    change_quote_outputs: List[TransactionChangeOutput] = Field(
        [], max_length=settings.mint_max_request_length
    )
    prefer_async: Optional[bool] = None


class PostTransactionResponse(BaseModel):
    state: str  # PENDING, PAID or FAILED
    signatures: List[BlindedSignature] = []
    melt_quotes: List[PostMeltQuoteResponse] = []
    change_quotes: List[Optional[PostMintQuoteResponse]] = []
