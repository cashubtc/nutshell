"""Transaction transcript (NUT-10).

One shared digest, one derived message per input:
transaction_digest = SHA256(domain tag || TLV stream); each input carries
one BIP-340 signature over its input digest,
tagged_hash("Cashu_TransactionInput", transaction_digest || SHA256(its own
container record)). Containers: 0x01 proof input, 0x02 mint quote input,
0x03 blinded message output, 0x04 melt quote output. Container types
ascend (inputs before outputs by construction); elements keep request
order within their type; field streams inside are ascending unique.
Byte-identical with cashu-ts src/crypto/transcript.ts, pinned by the
shared vectors.
"""

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .nutroot import minimal_be, tagged_hash, tlv_record

TRANSCRIPT_DOMAIN_TAG = "Cashu_Transaction_v1"
TRANSCRIPT_INPUT_TAG = "Cashu_TransactionInput"
SPEND_COMMITMENT_TAG = "Cashu_SpendCommitment"

_CONTAINER_PROOF_INPUT = 0x01
_CONTAINER_MINT_QUOTE_INPUT = 0x02
_CONTAINER_BLINDED_OUTPUT = 0x03
_CONTAINER_MELT_QUOTE_OUTPUT = 0x04


@dataclass
class TranscriptProofInput:
    amount: int
    keyset_id: bytes
    secret: bytes  # v3: the 33-byte compressed point P; v0-v2: the secret's raw bytes
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
    # Mixed transactions are normative (NUT-10), so a v0-v2 input appears here
    # with its secret's raw bytes next to a v3 input's 33-byte point.
    if not p.secret:
        raise ValueError("Transcript proof secret must be non-empty")
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
    # NUT-10: the same proof or quote twice would sign one input digest for two inputs.
    if len({p.secret for p in proofs}) != len(proofs):
        raise ValueError("Transaction repeats a proof input")
    if len({q.quote_id for q in mint_quotes}) != len(mint_quotes):
        raise ValueError("Transaction repeats a mint quote input")
    return (
        b"".join(_proof_input_container(p) for p in proofs)
        + b"".join(_quote_container(_CONTAINER_MINT_QUOTE_INPUT, q) for q in mint_quotes)
        + b"".join(_blinded_output_container(o) for o in blinded)
        + b"".join(_quote_container(_CONTAINER_MELT_QUOTE_OUTPUT, q) for q in melt_quotes)
    )


def transaction_digest(tx: TransactionShape) -> bytes:
    """The shared 32-byte digest: SHA256(domain tag || transcript)."""
    return hashlib.sha256(
        TRANSCRIPT_DOMAIN_TAG.encode("utf-8") + build_transaction_transcript(tx)
    ).digest()


def input_digest(transaction_digest_: bytes, container: bytes) -> bytes:
    """The message one input signs: tagged_hash(input tag, transaction_digest || SHA256(container))."""
    if len(transaction_digest_) != 32:
        raise ValueError("Transaction digest must be 32 bytes")
    return tagged_hash(
        TRANSCRIPT_INPUT_TAG, transaction_digest_, hashlib.sha256(container).digest()
    )


@dataclass
class InputContext:
    """One input's signing context: its container record and the digest it signs."""

    container: bytes
    digest: bytes


def transaction_inputs(
    tx: TransactionShape,
) -> Tuple[bytes, Dict[bytes, InputContext], Dict[str, InputContext]]:
    """(transaction_digest, proof contexts by secret bytes, quote contexts by quote id).

    The transcript builder has already refused duplicates, so the keys are unique.
    """
    digest = transaction_digest(tx)
    proofs = {
        p.secret: InputContext(container=c, digest=input_digest(digest, c))
        for p in (tx.proof_inputs or [])
        for c in [_proof_input_container(p)]
    }
    quotes = {
        q.quote_id: InputContext(container=c, digest=input_digest(digest, c))
        for q in (tx.mint_quote_inputs or [])
        for c in [_quote_container(_CONTAINER_MINT_QUOTE_INPUT, q)]
    }
    return digest, proofs, quotes


def spend_commitment(Y: bytes, input_digest_: bytes, witness: str) -> bytes:
    """The NUT-07 spend commitment: tagged_hash(tag, Y || input_digest || SHA256(witness)).

    `witness` is the exact string value as sent; `Y` contributes its raw compressed bytes.
    """
    return tagged_hash(
        SPEND_COMMITMENT_TAG,
        Y,
        input_digest_,
        hashlib.sha256(witness.encode("utf-8")).digest(),
    )
