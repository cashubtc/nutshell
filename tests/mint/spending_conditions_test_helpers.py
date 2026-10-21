from cashu.core.base import HTLCWitness, P2PKWitness, Proof
from cashu.core.crypto.secp import PrivateKey
from cashu.core.p2pk import schnorr_sign
from cashu.core.secret import Secret, SecretKind, Tags


def pubkey_and_sig(message: str):
    priv = PrivateKey()
    pub = priv.public_key.format().hex()
    sig = schnorr_sign(message.encode("utf-8"), priv).hex()
    return pub, sig


def secret_str(
    *,
    kind: SecretKind,
    data: str,
    sigflag=None,
    extra_tags: list[list[str]] | None = None,
) -> str:
    tags = []
    if sigflag:
        tags.append(["sigflag", sigflag.value])
    if extra_tags:
        tags.extend(extra_tags)
    return Secret(
        kind=kind.value,
        data=data,
        tags=Tags(tags=tags),
        nonce="0" * 32,
    ).serialize()


def proof(
    secret: str,
    signatures: list[str] | None = None,
    htlc_preimage: str | None = None,
):
    witness = None
    if signatures is not None:
        witness = P2PKWitness(signatures=signatures).model_dump_json()
    if htlc_preimage is not None:
        witness = HTLCWitness(preimage=htlc_preimage).model_dump_json()
    return Proof(id="ks", amount=1, C="00", secret=secret, witness=witness)
