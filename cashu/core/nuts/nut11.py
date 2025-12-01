import hashlib
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional, Union

from loguru import logger

from ..base import BlindedMessage, Proof
from ..crypto.secp import PrivateKey, PublicKey
from ..secret import Secret, SecretKind, Tags


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
    def sigflag(self) -> SigFlags:
        sigflag = self.tags.get_tag("sigflag")
        return SigFlags(sigflag) if sigflag else SigFlags.SIG_INPUTS

    @property
    def n_sigs(self) -> int:
        n_sigs = self.tags.get_tag_int("n_sigs")
        return int(n_sigs) if n_sigs else 1

    @property
    def n_sigs_refund(self) -> Union[None, int]:
        n_sigs_refund = self.tags.get_tag_int("n_sigs_refund")
        return n_sigs_refund


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


def create_p2pk_lock(
    self,
    data: str,
    locktime_seconds: Optional[int] = None,
    tags: Optional[Tags] = None,
    sig_all: bool = False,
    n_sigs: int = 1,
) -> P2PKSecret:
    """Generate a P2PK secret with the given pubkeys, locktime, tags, and signature flag.

    Args:
        data (str): Public key to lock to.
        locktime_seconds (Optional[int], optional): Locktime in seconds. Defaults to None.
        tags (Optional[Tags], optional): Tags to add to the secret. Defaults to None.
        sig_all (bool, optional): Whether to use SIG_ALL spending condition. Defaults to False.
        n_sigs (int, optional): Number of signatures required. Defaults to 1.

    Returns:
        P2PKSecret: P2PK secret with the given pubkeys, locktime, tags, and signature flag.
    """
    logger.debug(f"Provided tags: {tags}")
    if not tags:
        tags = Tags()
        logger.debug(f"Before tags: {tags}")
    if locktime_seconds:
        tags["locktime"] = str(
            int((datetime.now() + timedelta(seconds=locktime_seconds)).timestamp())
        )
    tags["sigflag"] = SigFlags.SIG_ALL.value if sig_all else SigFlags.SIG_INPUTS.value
    if n_sigs > 1:
        tags["n_sigs"] = str(n_sigs)
    logger.debug(f"After tags: {tags}")
    return P2PKSecret(
        kind=SecretKind.P2PK.value,
        data=data,
        tags=tags,
    )


def sigall_message_to_sign(proofs: List[Proof], outputs: List[BlindedMessage]) -> str:
    """
    Creates the message to sign for sigall spending conditions.
    The message is a concatenation of all proof secrets and signatures + all output attributes (amount, id, B_).
    """

    # Concatenate all proof secrets
    message = "".join([p.secret + p.C for p in proofs])

    # Concatenate all output attributes
    message += "".join([str(o.amount) + o.id + o.B_ for o in outputs])

    return message
