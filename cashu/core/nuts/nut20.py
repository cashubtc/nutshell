from hashlib import sha256
from typing import List

from coincurve import PublicKeyXOnly
from loguru import logger

from ..base import BlindedMessage
from ..crypto.nutroot import (
    NutrootWitness,
    keyset_id_transcript_bytes,
    verify_script_path_spend,
)
from ..crypto.secp import PrivateKey, PublicKey
from ..crypto.transcript import (
    TransactionShape,
    TranscriptBlindedOutput,
    TranscriptQuote,
    transaction_inputs,
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
    """V3 (nutroot secrets): the quote is a transaction input signing its own
    input digest (NUT-10); NUT-20's separate message retires."""
    return construct_batch_transaction_message([(quote_id, amount)], outputs, quote_id)


def construct_batch_transaction_message(
    quotes: List[tuple], outputs: List[BlindedMessage], for_quote_id: str
) -> bytes:
    """The input digest quote `for_quote_id` signs in a (batch) mint: the
    shared transcript covers every quote input (quote_id, amount) in request
    order plus all blinded outputs, and each quote's witness signs its own
    input digest over it (NUT-10)."""
    _, _, quote_contexts = transaction_inputs(
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
    if for_quote_id not in quote_contexts:
        raise ValueError("quote is not an input of this transaction")
    return quote_contexts[for_quote_id].digest


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
    For batch mints, pass every quote as `batch_quotes`; the shared transcript
    covers them all and `quote_id` selects this quote's input digest."""
    digest = construct_batch_transaction_message(
        batch_quotes if batch_quotes is not None else [(quote_id, amount)],
        outputs,
        quote_id,
    )
    witness: NutrootWitness | None = None
    if signature.strip().startswith("{"):
        try:
            witness = NutrootWitness.model_validate_json(signature)
        except ValueError:
            return False
    if witness is not None and witness.is_script_path:
        try:
            verify_script_path_spend(
                PublicKey(bytes.fromhex(public_key)), digest, witness
            )
            return True
        except Exception:
            return False
    sig_hex = witness.signatures[0] if witness is not None else signature
    try:
        pubkey = PublicKeyXOnly(bytes.fromhex(public_key)[1:])
        return pubkey.verify(bytes.fromhex(sig_hex), digest)
    except Exception:
        return False


def sign_mint_quote_batch_v3(
    quotes: List[tuple],
    outputs: List[BlindedMessage],
    private_key: str,
    for_quote_id: str,
) -> str:
    """Sign one quote's input digest over the batch transcript (all quote
    inputs + outputs)."""
    privkey = PrivateKey(bytes.fromhex(private_key))
    return privkey.sign_schnorr(
        construct_batch_transaction_message(quotes, outputs, for_quote_id)
    ).hex()
