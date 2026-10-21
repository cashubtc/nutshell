"""NUT-22 blind authentication on v3 (version 02) auth keysets.

A version 02 BAT's secret is a nutroot point secret and its AuthProof
carries a required key-path witness over the request transcript digest
(method, target, body hash). One grammar, one signing rule: the digest
construction is NUT-10's.
"""

import json
from typing import Optional
from urllib.parse import unquote_to_bytes

from coincurve import PublicKeyXOnly

from ..base import AuthProof
from ..crypto.nutroot import NutrootWitness, is_nutroot_point_secret
from ..crypto.secp import PrivateKey
from ..crypto.transcript import request_digest

# Local derivation record marking a BAT proof's fresh private key,
# "BATKEY:<hex>". Wallet auth-db only; never sent to the mint.
BATKEY_PREFIX = "BATKEY:"


def relative_request_target(raw_target: bytes, mount_path: str = "") -> str:
    """Remove a mint's mount prefix while retaining the exact endpoint bytes."""
    path, separator, query = raw_target.partition(b"?")
    root = mount_path.rstrip("/").encode("utf-8")
    decoded = unquote_to_bytes(path)
    if root and (decoded == root or decoded.startswith(root + b"/")):
        encoded_index = 0
        decoded_index = 0
        while decoded_index < len(root):
            escape = path[encoded_index : encoded_index + 3]
            if (
                len(escape) == 3
                and escape[0] == 0x25
                and all(byte in b"0123456789abcdefABCDEF" for byte in escape[1:])
            ):
                encoded_index += 3
            else:
                encoded_index += 1
            decoded_index += 1
        path = path[encoded_index:] or b"/"
    return (path + separator + query).decode("ascii")


def bat_private_key(derivation_path: Optional[str]) -> Optional[PrivateKey]:
    """The stored private key behind a version 02 BAT proof, if any."""
    if not derivation_path or not derivation_path.startswith(BATKEY_PREFIX):
        return None
    try:
        return PrivateKey(bytes.fromhex(derivation_path[len(BATKEY_PREFIX) :]))
    except Exception:
        return None


def sign_request(private_key: PrivateKey, method: str, target: str, body: bytes) -> str:
    """The serialized witness for a version 02 BAT authorizing this request."""
    signature = private_key.sign_schnorr(request_digest(method, target, body))
    return json.dumps({"signatures": [signature.hex()]})


def verify_bat_request_witness(
    auth_proof: AuthProof, method: str, target: str, body: bytes
) -> bool:
    """Verify a version 02 BAT's witness against the request it authorizes.

    The secret must be a point, the witness a key-path shape with exactly
    one signature, and the signature valid over the request digest.
    """
    if not is_nutroot_point_secret(auth_proof.secret, auth_proof.id):
        return False
    if not auth_proof.witness:
        return False
    try:
        witness = NutrootWitness.model_validate_json(auth_proof.witness)
        if witness.is_script_path:
            return False
        pubkey = PublicKeyXOnly(bytes.fromhex(auth_proof.secret)[1:])
        return pubkey.verify(
            bytes.fromhex(witness.signatures[0]), request_digest(method, target, body)
        )
    except Exception:
        return False
