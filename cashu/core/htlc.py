from enum import Enum
from typing import Union

from .secret import Secret, SecretKind


class SigFlags(Enum):
    # require signatures only on the inputs (default signature flag)
    SIG_INPUTS = "SIG_INPUTS"
    # require signatures on inputs and outputs
    SIG_ALL = "SIG_ALL"


class HTLCSecret(Secret):
    @classmethod
    def from_secret(cls, secret: Secret):
        assert SecretKind(secret.kind) == SecretKind.HTLC, "Secret is not a HTLC secret"
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
        return SigFlags(sigflag) if sigflag else SigFlags.SIG_INPUTS

    @property
    def n_sigs(self) -> Union[None, int]:
        n_sigs = self.tags.get_tag_int("n_sigs")
        return int(n_sigs) if n_sigs else 1

    @property
    def n_sigs_refund(self) -> Union[None, int]:
        n_sigs_refund = self.tags.get_tag_int("n_sigs_refund")
        return n_sigs_refund
