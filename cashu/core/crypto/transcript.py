"""Transaction transcript (NUT-10): one shared digest, one derived message per input.

Byte-identical with cashu-ts src/crypto/transcript.ts, pinned by the shared vectors.
"""

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .nutroot import minimal_be, tagged_hash, tlv_record

TRANSCRIPT_INPUT_TAG = "Cashu_TransactionInput"
SPEND_COMMITMENT_TAG = "Cashu_SpendCommitment"

# The high nibble is the section: 0x1n inputs, 0x2n outputs, 0xFn never in a transaction.
_CONTAINER_PROOF_INPUT = 0x11
_CONTAINER_MINT_QUOTE_INPUT = 0x12
_CONTAINER_BLINDED_OUTPUT = 0x21
_CONTAINER_MELT_QUOTE_OUTPUT = 0x22
_CONTAINER_CHANGE_QUOTE_OUTPUT = 0x23


@dataclass
class TranscriptProofInput:
    amount: int
    keyset_id: bytes
    Y: bytes  # the keyset's hash_to_curve of the secret; the secret itself never appears
    C: bytes


@dataclass
class TranscriptQuote:
    amount: int
    quote_id: str
    pubkey: Optional[bytes] = None  # 33-byte lock key; required on a mint quote input


@dataclass
class TranscriptBlindedOutput:
    amount: int
    keyset_id: bytes
    B_: bytes


@dataclass
class TranscriptChangeOutput:
    pubkey: bytes  # 33-byte compressed lock key (NUT-XX)
    amount: Optional[int] = None  # None on the remainder quote


@dataclass
class TransactionShape:
    proof_inputs: Optional[List[TranscriptProofInput]] = None
    mint_quote_inputs: Optional[List[TranscriptQuote]] = None
    blinded_outputs: Optional[List[TranscriptBlindedOutput]] = None
    melt_quote_outputs: Optional[List[TranscriptQuote]] = None
    change_quote_outputs: Optional[List[TranscriptChangeOutput]] = None


def _amount_record(amount: int) -> bytes:
    if amount < 0:
        raise ValueError("Transcript amount must be non-negative")
    return tlv_record(0x01, minimal_be(amount))


def _change_output_container(c: TranscriptChangeOutput) -> bytes:
    if len(c.pubkey) != 33:
        raise ValueError("Transcript change lock key must be 33 bytes")
    return tlv_record(
        _CONTAINER_CHANGE_QUOTE_OUTPUT,
        (_amount_record(c.amount) if c.amount is not None else b"")
        + tlv_record(0x02, c.pubkey),
    )


def _proof_input_container(p: TranscriptProofInput) -> bytes:
    # Field 03 is Y on the keyset's curve (NUT-10): 48 bytes under a v3 keyset,
    # 33 under a v0-v2 one, which mixed transactions carry beside v3 inputs.
    if len(p.Y) not in (33, 48):
        raise ValueError("Transcript proof Y must be a compressed curve point")
    return tlv_record(
        _CONTAINER_PROOF_INPUT,
        _amount_record(p.amount)
        + tlv_record(0x02, p.keyset_id)
        + tlv_record(0x03, p.Y)
        + tlv_record(0x04, p.C),
    )


def _quote_fields(q: TranscriptQuote) -> bytes:
    """Fields 01 amount and 02 quote id, shared by the mint quote input and melt quote output."""
    if not q.quote_id:
        raise ValueError("Transcript quote id must be non-empty")
    return _amount_record(q.amount) + tlv_record(0x02, q.quote_id.encode("utf-8"))


def _mint_quote_input_container(q: TranscriptQuote) -> bytes:
    # The container commits the lock key, so an offline co-signer can tell which key the input needs.
    if q.pubkey is None or len(q.pubkey) != 33:
        raise ValueError("Transcript mint quote input needs its 33-byte lock key")
    return tlv_record(
        _CONTAINER_MINT_QUOTE_INPUT, _quote_fields(q) + tlv_record(0x03, q.pubkey)
    )


def _melt_quote_output_container(q: TranscriptQuote) -> bytes:
    return tlv_record(_CONTAINER_MELT_QUOTE_OUTPUT, _quote_fields(q))


def _blinded_output_container(o: TranscriptBlindedOutput) -> bytes:
    return tlv_record(
        _CONTAINER_BLINDED_OUTPUT,
        _amount_record(o.amount)
        + tlv_record(0x02, o.keyset_id)
        + tlv_record(0x03, o.B_),
    )


def build_transaction_transcript(tx: TransactionShape) -> bytes:
    """Serialize a transaction to its TLV transcript."""
    proofs = tx.proof_inputs or []
    mint_quotes = tx.mint_quote_inputs or []
    blinded = tx.blinded_outputs or []
    melt_quotes = tx.melt_quote_outputs or []
    change = tx.change_quote_outputs or []
    if not proofs and not mint_quotes:
        raise ValueError("Transaction requires at least one input")
    if not blinded and not melt_quotes and not change:
        raise ValueError("Transaction requires at least one output")
    # NUT-10: the same proof or quote twice would sign one input digest for two inputs.
    if len({p.Y for p in proofs}) != len(proofs):
        raise ValueError("Transaction repeats a proof input")
    if len({q.quote_id for q in mint_quotes}) != len(mint_quotes):
        raise ValueError("Transaction repeats a mint quote input")
    return (
        b"".join(_proof_input_container(p) for p in proofs)
        + b"".join(_mint_quote_input_container(q) for q in mint_quotes)
        + output_section(tx)
    )


def output_section(tx: TransactionShape) -> bytes:
    """The transcript's output section (its 0x2n containers), which a template leaf hashes."""
    return (
        b"".join(_blinded_output_container(o) for o in (tx.blinded_outputs or []))
        + b"".join(
            _melt_quote_output_container(q) for q in (tx.melt_quote_outputs or [])
        )
        + b"".join(_change_output_container(c) for c in (tx.change_quote_outputs or []))
    )


def transaction_digest(tx: TransactionShape) -> bytes:
    """The shared 32-byte digest: SHA256(transcript)."""
    return hashlib.sha256(build_transaction_transcript(tx)).digest()


def input_digest(transaction_digest_: bytes, container: bytes) -> bytes:
    """The message one input signs: tagged_hash(input tag, transaction_digest || SHA256(container))."""
    if len(transaction_digest_) != 32:
        raise ValueError("Transaction digest must be 32 bytes")
    return tagged_hash(
        TRANSCRIPT_INPUT_TAG, transaction_digest_, hashlib.sha256(container).digest()
    )


@dataclass
class InputContext:
    """One input's signing context: its container record, the digest it signs,
    and the transaction's output section (what a template leaf commits to)."""

    container: bytes
    digest: bytes
    outputs: bytes = b""


def transaction_inputs(
    tx: TransactionShape,
) -> Tuple[bytes, Dict[bytes, InputContext], Dict[str, InputContext]]:
    """(transaction_digest, proof contexts by Y bytes, quote contexts by quote id).

    The transcript builder has already refused duplicates, so the keys are unique.
    """
    digest = transaction_digest(tx)
    outputs = output_section(tx)
    proofs = {
        p.Y: InputContext(container=c, digest=input_digest(digest, c), outputs=outputs)
        for p in (tx.proof_inputs or [])
        for c in [_proof_input_container(p)]
    }
    quotes = {
        q.quote_id: InputContext(
            container=c, digest=input_digest(digest, c), outputs=outputs
        )
        for q in (tx.mint_quote_inputs or [])
        for c in [_mint_quote_input_container(q)]
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
