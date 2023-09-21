import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Union

from loguru import logger
from pydantic import BaseModel

from .crypto.secp import PrivateKey, PublicKey


class SecretKind:
    P2SH = "P2SH"
    P2PK = "P2PK"


class SigFlags:
    SIG_INPUTS = (  # require signatures only on the inputs (default signature flag)
        "SIG_INPUTS"
    )
    SIG_ALL = "SIG_ALL"  # require signatures on inputs and outputs


class Tags(BaseModel):
    """
    Tags are used to encode additional information in the Secret of a Proof.
    """

    __root__: List[List[str]] = []

    def __init__(self, tags: Optional[List[List[str]]] = None, **kwargs):
        super().__init__(**kwargs)
        self.__root__ = tags or []

    def __setitem__(self, key: str, value: str) -> None:
        self.__root__.append([key, value])

    def __getitem__(self, key: str) -> Union[str, None]:
        return self.get_tag(key)

    def get_tag(self, tag_name: str) -> Union[str, None]:
        for tag in self.__root__:
            if tag[0] == tag_name:
                return tag[1]
        return None

    def get_tag_all(self, tag_name: str) -> List[str]:
        all_tags = []
        for tag in self.__root__:
            if tag[0] == tag_name:
                for t in tag[1:]:
                    all_tags.append(t)
        return all_tags


class Secret(BaseModel):
    """Describes spending condition encoded in the secret field of a Proof."""

    kind: str
    data: str
    tags: Tags
    nonce: Union[None, str] = None

    def serialize(self) -> str:
        data_dict: Dict[str, Any] = {
            "data": self.data,
            "nonce": self.nonce or PrivateKey().serialize()[:32],
        }
        if self.tags.__root__:
            logger.debug(f"Serializing tags: {self.tags.__root__}")
            data_dict["tags"] = self.tags.__root__
        return json.dumps(
            [self.kind, data_dict],
        )

    @classmethod
    def deserialize(cls, from_proof: str):
        kind, kwargs = json.loads(from_proof)
        data = kwargs.pop("data")
        nonce = kwargs.pop("nonce")
        tags_list: List = kwargs.pop("tags", None)
        tags = Tags(tags=tags_list)
        logger.debug(f"Deserialized Secret: {kind}, {data}, {nonce}, {tags}")
        return cls(kind=kind, data=data, nonce=nonce, tags=tags)


class P2PKSecret(Secret):
    @classmethod
    def from_secret(cls, secret: Secret):
        assert secret.kind == SecretKind.P2PK, "Secret is not a P2PK secret"
        # NOTE: exclude tags in .dict() because it doesn't deserialize it properly
        # need to add it back in manually with tags=secret.tags
        return cls(**secret.dict(exclude={"tags"}), tags=secret.tags)

    def get_p2pk_pubkey_from_secret(self) -> List[str]:
        """Gets the P2PK pubkey from a Secret depending on the locktime

        Args:
            secret (Secret): P2PK Secret in ecash token

        Returns:
            str: pubkey to use for P2PK, empty string if anyone can spend (locktime passed)
        """
        # the pubkey in the data field is the pubkey to use for P2PK
        pubkeys: List[str] = [self.data]

        # get all additional pubkeys from tags for multisig
        pubkeys += self.tags.get_tag_all("pubkeys")

        # check if locktime is passed and if so, only return refund pubkeys
        now = time.time()
        if self.locktime and self.locktime < now:
            logger.trace(f"p2pk locktime ran out ({self.locktime}<{now}).")
            # check tags if a refund pubkey is present.
            # If yes, we demand the signature to be from the refund pubkey
            return self.tags.get_tag_all("refund")

        return pubkeys

    @property
    def locktime(self) -> Union[None, int]:
        locktime = self.tags.get_tag("locktime")
        return int(locktime) if locktime else None

    @property
    def sigflag(self) -> Union[None, str]:
        return self.tags.get_tag("sigflag")

    @property
    def n_sigs(self) -> Union[None, int]:
        n_sigs = self.tags.get_tag("n_sigs")
        return int(n_sigs) if n_sigs else None


class P2SHScript(BaseModel):
    """
    Unlocks P2SH spending condition of a Proof
    """

    script: str
    signature: str
    address: Union[str, None] = None


def sign_p2pk_sign(message: bytes, private_key: PrivateKey):
    # ecdsa version
    # signature = private_key.ecdsa_serialize(private_key.ecdsa_sign(message))
    signature = private_key.schnorr_sign(
        hashlib.sha256(message).digest(), None, raw=True
    )
    return signature.hex()


def verify_p2pk_signature(message: bytes, pubkey: PublicKey, signature: bytes):
    # ecdsa version
    # return pubkey.ecdsa_verify(message, pubkey.ecdsa_deserialize(signature))
    return pubkey.schnorr_verify(
        hashlib.sha256(message).digest(), signature, None, raw=True
    )


if __name__ == "__main__":
    # generate keys
    private_key_bytes = b"12300000000000000000000000000123"
    private_key = PrivateKey(private_key_bytes, raw=True)
    print(private_key.serialize())
    public_key = private_key.pubkey
    assert public_key
    print(public_key.serialize().hex())

    # sign message (=pubkey)
    message = public_key.serialize()
    signature = private_key.ecdsa_serialize(private_key.ecdsa_sign(message))
    print(signature.hex())

    # verify
    pubkey_verify = PublicKey(message, raw=True)
    print(public_key.ecdsa_verify(message, pubkey_verify.ecdsa_deserialize(signature)))
