import hashlib
from enum import Enum
from typing import Union

from .crypto.secp import PrivateKey, PublicKey
from .secret import Secret, SecretKind


class SigFlags(Enum):
    # require signatures only on the inputs (default signature flag)
    SIG_INPUTS = "SIG_INPUTS"
    # require signatures on inputs and outputs
    SIG_ALL = "SIG_ALL"


class P2PKSecret(Secret):
    @classmethod
    def from_secret(cls, secret: Secret):
        assert SecretKind(secret.kind) == SecretKind.P2PK, "Secret is not a P2PK secret"
        # NOTE: exclude tags in .dict() because it doesn't deserialize it properly
        # need to add it back in manually with tags=secret.tags
        return cls(**secret.dict(exclude={"tags"}), tags=secret.tags)

    @property
    def locktime(self) -> Union[None, int]:
        locktime = self.tags.get_tag("locktime")
        return int(locktime) if locktime else None

    @property
    def sigflag(self) -> Union[None, SigFlags]:
        sigflag = self.tags.get_tag("sigflag")
        return SigFlags(sigflag) if sigflag else None

    @property
    def n_sigs(self) -> Union[None, int]:
        n_sigs = self.tags.get_tag("n_sigs")
        return int(n_sigs) if n_sigs else None


def schnorr_sign(message: bytes, private_key: PrivateKey) -> bytes:
    signature = private_key.schnorr_sign(
        hashlib.sha256(message).digest(), None, raw=True
    )
    return signature


def verify_schnorr_signature(
    message: bytes, pubkey: PublicKey, signature: bytes
) -> bool:
    return pubkey.schnorr_verify(
        hashlib.sha256(message).digest(), signature, None, raw=True
    )
