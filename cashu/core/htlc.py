from .errors import InvalidProofsError
from .p2pk import P2PKSecret, SigFlags
from .secret import Secret, SecretKind


# HTLCSecret inherits properties from P2PKSecret
class HTLCSecret(P2PKSecret, Secret):
    @classmethod
    def from_secret(cls, secret: Secret):
        if SecretKind(secret.kind) != SecretKind.HTLC:
            raise InvalidProofsError("Secret is not an HTLC secret")

        if secret.tags.get_tag("sigflag") and secret.tags.get_tag("sigflag") not in [
            SigFlags.SIG_INPUTS.value,
            SigFlags.SIG_ALL.value,
        ]:
            raise InvalidProofsError("Secret does not have a valid sigflag tag")
        # NOTE: exclude tags in .dict() because it doesn't deserialize it properly
        # need to add it back in manually with tags=secret.tags
        return cls(**secret.model_dump(exclude={"tags"}), tags=secret.tags)
