"""Transaction transcript (taproot secrets spec 2.2.1).

The one message every input signs: msg = domain tag || TLV stream; each
input carries one BIP-340 signature over SHA256(msg). Containers: 0x01
proof input, 0x02 mint quote input, 0x03 blinded message output, 0x04 melt
quote output. Container types ascend (inputs before outputs by
construction); elements keep request order within their type; field
streams inside are ascending unique (2.6). Byte-identical with cashu-ts
src/crypto/transcript.ts, pinned by the shared vectors.
"""

import hashlib
from dataclasses import dataclass
from typing import List, Optional

from .taproot import minimal_be, tlv_record

TRANSCRIPT_DOMAIN_TAG = "Cashu_Transaction_v1"

_CONTAINER_PROOF_INPUT = 0x01
_CONTAINER_MINT_QUOTE_INPUT = 0x02
_CONTAINER_BLINDED_OUTPUT = 0x03
_CONTAINER_MELT_QUOTE_OUTPUT = 0x04


@dataclass
class TranscriptProofInput:
    amount: int
    keyset_id: bytes
    secret: bytes  # 33-byte compressed point P
    C: bytes


@dataclass
class TranscriptQuote:
    amount: int
    quote_id: str


@dataclass
class TranscriptBlindedOutput:
    amount: int
    keyset_id: bytes
    B_: bytes


@dataclass
class TransactionShape:
    proof_inputs: Optional[List[TranscriptProofInput]] = None
    mint_quote_inputs: Optional[List[TranscriptQuote]] = None
    blinded_outputs: Optional[List[TranscriptBlindedOutput]] = None
    melt_quote_outputs: Optional[List[TranscriptQuote]] = None


def _amount_record(amount: int) -> bytes:
    if amount < 0:
        raise ValueError("Transcript amount must be non-negative")
    return tlv_record(0x01, minimal_be(amount))


def _proof_input_container(p: TranscriptProofInput) -> bytes:
    if len(p.secret) != 33:
        raise ValueError("Transcript proof secret must be 33 bytes")
    return tlv_record(
        _CONTAINER_PROOF_INPUT,
        _amount_record(p.amount)
        + tlv_record(0x02, p.keyset_id)
        + tlv_record(0x03, p.secret)
        + tlv_record(0x04, p.C),
    )


def _quote_container(container_type: int, q: TranscriptQuote) -> bytes:
    if not q.quote_id:
        raise ValueError("Transcript quote id must be non-empty")
    return tlv_record(
        container_type,
        _amount_record(q.amount) + tlv_record(0x02, q.quote_id.encode("utf-8")),
    )


def _blinded_output_container(o: TranscriptBlindedOutput) -> bytes:
    return tlv_record(
        _CONTAINER_BLINDED_OUTPUT,
        _amount_record(o.amount)
        + tlv_record(0x02, o.keyset_id)
        + tlv_record(0x03, o.B_),
    )


def build_transaction_transcript(tx: TransactionShape) -> bytes:
    """Serialize a transaction to its TLV transcript (without the domain tag)."""
    proofs = tx.proof_inputs or []
    mint_quotes = tx.mint_quote_inputs or []
    blinded = tx.blinded_outputs or []
    melt_quotes = tx.melt_quote_outputs or []
    if not proofs and not mint_quotes:
        raise ValueError("Transaction requires at least one input")
    if not blinded and not melt_quotes:
        raise ValueError("Transaction requires at least one output")
    return (
        b"".join(_proof_input_container(p) for p in proofs)
        + b"".join(_quote_container(_CONTAINER_MINT_QUOTE_INPUT, q) for q in mint_quotes)
        + b"".join(_blinded_output_container(o) for o in blinded)
        + b"".join(_quote_container(_CONTAINER_MELT_QUOTE_OUTPUT, q) for q in melt_quotes)
    )


def transaction_digest(tx: TransactionShape) -> bytes:
    """The 32-byte digest every input signs: SHA256(domain tag || transcript)."""
    return hashlib.sha256(
        TRANSCRIPT_DOMAIN_TAG.encode("utf-8") + build_transaction_transcript(tx)
    ).digest()
