from .p2pk import P2PKSecret
from .secret import Secret, SecretKind


# HTLCSecret inherits properties from P2PKSecret
class HTLCSecret(P2PKSecret, Secret):
    @classmethod
    def from_secret(cls, secret: Secret):
        assert SecretKind(secret.kind) == SecretKind.HTLC, "Secret is not a HTLC secret"
        # NOTE: exclude tags in .dict() because it doesn't deserialize it properly
        # need to add it back in manually with tags=secret.tags
        return cls(**secret.dict(exclude={"tags"}), tags=secret.tags)
