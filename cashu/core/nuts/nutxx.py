"""NUT-XX: mint quote lookup by public key."""

from hashlib import sha256

from coincurve import PublicKeyXOnly

from ..crypto.secp import PublicKey

MINT_QUOTE_LOOKUP_DOMAIN = b"Cashu_MintQuoteLookup_v1"

# Bound the signature-verification work an unauthenticated request can trigger.
MAX_LOOKUP_PUBKEYS = 50
SCHNORR_SIGNATURE_HEX_LENGTH = 128


def construct_message(mint_pubkey: str, pubkey: str) -> bytes:
    """Return the UTF-8 preimage whose SHA-256 digest is signed."""
    return MINT_QUOTE_LOOKUP_DOMAIN + mint_pubkey.encode() + pubkey.encode()


def verify_signature(mint_pubkey: str, pubkey: PublicKey, signature: bytes) -> bool:
    """Verify a NUT-XX quote-lookup signature for ``pubkey``."""
    message = construct_message(mint_pubkey, pubkey.format().hex())
    xonly_pubkey = PublicKeyXOnly(pubkey.format()[1:])
    return xonly_pubkey.verify(signature, sha256(message).digest())
