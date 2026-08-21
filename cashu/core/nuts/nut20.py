import json
from hashlib import sha256
from typing import List

from coincurve import PublicKeyXOnly
from loguru import logger

from ..base import BlindedMessage
from ..crypto.secp import PrivateKey, PublicKey
from ..crypto.taproot import keyset_id_transcript_bytes, verify_script_path_spend
from ..crypto.transcript import (
    TransactionShape,
    TranscriptBlindedOutput,
    TranscriptQuote,
    transaction_digest,
)


def generate_keypair() -> tuple[str, str]:
    privkey = PrivateKey()
    assert privkey.public_key
    pubkey = privkey.public_key
    return privkey.to_hex(), pubkey.format().hex()


def int_to_minimal_bytes(val: int) -> bytes:
    if val == 0:
        return b""
    return val.to_bytes((val.bit_length() + 7) // 8, "big")


def construct_message(quote_id: str, outputs: List[BlindedMessage]) -> bytes:
    dst = b"Cashu_MintQuoteSig_v1"
    quote_bytes = quote_id.encode("utf-8")
    msg = dst + len(quote_bytes).to_bytes(4, "big") + quote_bytes
    for o in outputs:
        amount_bytes = int_to_minimal_bytes(o.amount)
        b_bytes = bytes.fromhex(o.B_)
        msg += len(amount_bytes).to_bytes(4, "big") + amount_bytes
        msg += len(b_bytes).to_bytes(4, "big") + b_bytes
    return sha256(msg).digest()


def sign_mint_quote(
    quote_id: str,
    outputs: List[BlindedMessage],
    private_key: str,
) -> str:
    privkey = PrivateKey(bytes.fromhex(private_key))
    msgbytes = construct_message(quote_id, outputs)
    sig = privkey.sign_schnorr(msgbytes)
    return sig.hex()


def construct_message_legacy(quote_id: str, outputs: List[BlindedMessage]) -> bytes:
    serialized_outputs = b"".join([o.B_.encode("utf-8") for o in outputs])
    msgbytes = sha256(quote_id.encode("utf-8") + serialized_outputs).digest()
    return msgbytes


def verify_mint_quote(
    quote_id: str,
    outputs: List[BlindedMessage],
    public_key: str,
    signature: str,
) -> bool:
    pubkey = PublicKeyXOnly(bytes.fromhex(public_key)[1:])
    sig = bytes.fromhex(signature)

    # Try verifying with the new spec method first
    msgbytes = construct_message(quote_id, outputs)
    try:
        if pubkey.verify(sig, msgbytes):
            return True
    except Exception:
        pass

    # Fallback to the legacy method for backward compatibility
    # Deprecated since version 0.20.2
    logger.warning(
        "Using legacy NUT-20 signature verification. This fallback is deprecated since version 0.20.2."
    )
    msgbytes_legacy = construct_message_legacy(quote_id, outputs)
    try:
        return pubkey.verify(sig, msgbytes_legacy)
    except Exception:
        return False


def construct_transaction_message(
    quote_id: str, amount: int, outputs: List[BlindedMessage]
) -> bytes:
    """V3 (taproot secrets): the quote is a transaction input signing the
    transaction digest (spec 2.2.2 / 5); NUT-20's separate message retires."""
    return construct_batch_transaction_message([(quote_id, amount)], outputs)


def construct_batch_transaction_message(
    quotes: List[tuple], outputs: List[BlindedMessage]
) -> bytes:
    """The one transaction digest for a (batch) mint: every quote input
    (quote_id, amount) in request order plus all blinded outputs. Every
    quote's witness signs this same message (spec 2.2.2)."""
    return transaction_digest(
        TransactionShape(
            mint_quote_inputs=[
                TranscriptQuote(amount=amount, quote_id=quote_id)
                for (quote_id, amount) in quotes
            ],
            blinded_outputs=[
                TranscriptBlindedOutput(
                    amount=o.amount,
                    keyset_id=keyset_id_transcript_bytes(o.id),
                    B_=bytes.fromhex(o.B_),
                )
                for o in outputs
            ],
        )
    )


def sign_mint_quote_v3(
    quote_id: str, amount: int, outputs: List[BlindedMessage], private_key: str
) -> str:
    privkey = PrivateKey(bytes.fromhex(private_key))
    return privkey.sign_schnorr(
        construct_transaction_message(quote_id, amount, outputs)
    ).hex()


def verify_mint_quote_v3(
    quote_id: str,
    amount: int,
    outputs: List[BlindedMessage],
    public_key: str,
    signature: str,
    batch_quotes: "List[tuple] | None" = None,
) -> bool:
    """Verify a v3 locked-quote witness: key path (hex sig or {"signatures"})
    or script path ({"leaf", "control", ...}) against the quote lock point.
    For batch mints, pass every quote as `batch_quotes`; the digest covers
    them all and `quote_id`/`amount` are ignored."""
    digest = construct_batch_transaction_message(
        batch_quotes if batch_quotes is not None else [(quote_id, amount)], outputs
    )
    witness = None
    if signature.strip().startswith("{"):
        try:
            witness = json.loads(signature)
        except ValueError:
            return False
    if isinstance(witness, dict) and "leaf" in witness:
        try:
            verify_script_path_spend(
                PublicKey(bytes.fromhex(public_key)), digest, witness
            )
            return True
        except Exception:
            return False
    sig_hex = (
        witness.get("signatures", [None])[0] if isinstance(witness, dict) else signature
    )
    if not isinstance(sig_hex, str):
        return False
    try:
        pubkey = PublicKeyXOnly(bytes.fromhex(public_key)[1:])
        return pubkey.verify(bytes.fromhex(sig_hex), digest)
    except Exception:
        return False


def sign_mint_quote_batch_v3(
    quotes: List[tuple], outputs: List[BlindedMessage], private_key: str
) -> str:
    """Sign the batch transaction digest (all quote inputs + outputs)."""
    privkey = PrivateKey(bytes.fromhex(private_key))
    return privkey.sign_schnorr(
        construct_batch_transaction_message(quotes, outputs)
    ).hex()
