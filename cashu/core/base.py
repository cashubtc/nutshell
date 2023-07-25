import base64
import json
import time
from sqlite3 import Row
from typing import Any, Dict, List, Optional, Union

from loguru import logger
from pydantic import BaseModel

from .crypto.keys import derive_keys, derive_keyset_id, derive_pubkeys
from .crypto.secp import PrivateKey, PublicKey
from .legacy import derive_keys_backwards_compatible_insecure_pre_0_12
from .p2pk import sign_p2pk_sign

# ------- PROOFS -------


class SecretKind:
    P2SH = "P2SH"
    P2PK = "P2PK"


class SigFlags:
    SIG_INPUTS = (
        "SIG_INPUTS"  # require signatures only on the inputs (default signature flag)
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
                all_tags.append(tag[1])
        return all_tags


class Secret(BaseModel):
    """Describes spending condition encoded in the secret field of a Proof."""

    kind: str
    data: str
    nonce: Union[None, str] = None
    tags: Union[None, Tags] = None

    def serialize(self) -> str:
        data_dict: Dict[str, Any] = {
            "data": self.data,
            "nonce": self.nonce or PrivateKey().serialize()[:32],
        }
        if self.tags and self.tags.__root__:
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
        tags_list = kwargs.pop("tags", None)
        if tags_list:
            tags = Tags(tags=tags_list)
        else:
            tags = None
        logger.debug(f"Deserialized Secret: {kind}, {data}, {nonce}, {tags}")
        return cls(kind=kind, data=data, nonce=nonce, tags=tags)

    @property
    def locktime(self) -> Union[None, int]:
        if self.tags:
            locktime = self.tags.get_tag("locktime")
            if locktime:
                return int(locktime)
        return None

    @property
    def sigflag(self) -> Union[None, str]:
        if self.tags:
            sigflag = self.tags.get_tag("sigflag")
            if sigflag:
                return sigflag
        return None

    @property
    def n_sigs(self) -> Union[None, int]:
        if self.tags:
            n_sigs = self.tags.get_tag("n_sigs")
            if n_sigs:
                return int(n_sigs)
        return None

    def get_p2pk_pubkey_from_secret(self) -> List[str]:
        """Gets the P2PK pubkey from a Secret depending on the locktime

        Args:
            secret (Secret): P2PK Secret in ecash token

        Returns:
            str: pubkey to use for P2PK, empty string if anyone can spend (locktime passed)
        """
        pubkeys: List[str] = [self.data]  # for now we only support one pubkey
        # get all additional pubkeys from tags for multisig
        if self.tags and self.tags.get_tag("pubkey"):
            pubkeys += self.tags.get_tag_all("pubkey")

        now = time.time()
        if self.locktime and self.locktime < now:
            logger.trace(f"p2pk locktime ran out ({self.locktime}<{now}).")
            # check tags if a refund pubkey is present.
            # If yes, we demand the signature to be from the refund pubkey
            if self.tags:
                refund_pubkey = self.tags.get_tag("refund")
                if refund_pubkey:
                    pubkeys = [refund_pubkey]
                    return pubkeys
            return []
        return pubkeys


class P2SHScript(BaseModel):
    """
    Unlocks P2SH spending condition of a Proof
    """

    script: str
    signature: str
    address: Union[str, None] = None


class DLEQ(BaseModel):
    """
    Discrete Log Equality (DLEQ) Proof
    """

    e: str
    s: str
    B_: str
    C_: str


class Proof(BaseModel):
    """
    Value token
    """

    id: Union[
        None, str
    ] = ""  # NOTE: None for backwards compatibility for old clients that do not include the keyset id < 0.3
    amount: int = 0
    secret: str = ""  # secret or message to be blinded and signed
    C: str = ""  # signature on secret, unblinded by wallet
    dleq: Union[DLEQ, None] = None  # DLEQ proof
    p2pksigs: Union[List[str], None] = []  # P2PK signature
    p2shscript: Union[P2SHScript, None] = None  # P2SH spending condition
    reserved: Union[
        None, bool
    ] = False  # whether this proof is reserved for sending, used for coin management in the wallet
    send_id: Union[
        None, str
    ] = ""  # unique ID of send attempt, used for grouping pending tokens in the wallet
    time_created: Union[None, str] = ""
    time_reserved: Union[None, str] = ""
    derivation_path: Union[None, str] = ""  # derivation path of the proof

    def to_dict(self, include_dleq=False):
        # dictionary without the fields that don't need to be send to Carol
        if not include_dleq:
            return dict(id=self.id, amount=self.amount, secret=self.secret, C=self.C)

        assert self.dleq, "DLEQ proof is missing"
        return dict(
            id=self.id,
            amount=self.amount,
            secret=self.secret,
            C=self.C,
            dleq=self.dleq.dict(),
        )

    def to_dict_no_dleq(self):
        # dictionary without the fields that don't need to be send to Carol
        return dict(id=self.id, amount=self.amount, secret=self.secret, C=self.C)

    def to_dict_no_secret(self):
        # dictionary but without the secret itself
        return dict(id=self.id, amount=self.amount, C=self.C)

    def __getitem__(self, key):
        return self.__getattribute__(key)

    def __setitem__(self, key, val):
        self.__setattr__(key, val)


class Proofs(BaseModel):
    # NOTE: not used in Pydantic validation
    __root__: List[Proof]


class BlindedMessage(BaseModel):
    """
    Blinded message or blinded secret or "output" which is to be signed by the mint
    """

    amount: int
    B_: str  # Hex-encoded blinded message
    p2pksigs: Union[List[str], None] = None  # signature for p2pk with SIG_ALL


class BlindedSignature(BaseModel):
    """
    Blinded signature or "promise" which is the signature on a `BlindedMessage`
    """

    id: str
    amount: int
    C_: str  # Hex-encoded signature
    dleq: Optional[DLEQ] = None  # DLEQ proof


class BlindedMessages(BaseModel):
    # NOTE: not used in Pydantic validation
    __root__: List[BlindedMessage] = []


# ------- LIGHTNING INVOICE -------


class Invoice(BaseModel):
    amount: int
    pr: str
    hash: str
    payment_hash: Union[None, str] = None
    preimage: Union[str, None] = None
    issued: Union[None, bool] = False
    paid: Union[None, bool] = False
    time_created: Union[None, str, int, float] = ""
    time_paid: Union[None, str, int, float] = ""


# ------- API -------

# ------- API: INFO -------


class GetInfoResponse(BaseModel):
    name: Optional[str] = None
    pubkey: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    description_long: Optional[str] = None
    contact: Optional[List[List[str]]] = None
    nuts: Optional[List[str]] = None
    motd: Optional[str] = None
    parameter: Optional[dict] = None


# ------- API: KEYS -------


class KeysResponse(BaseModel):
    __root__: Dict[str, str]


class KeysetsResponse(BaseModel):
    keysets: list[str]


# ------- API: MINT -------


class PostMintRequest(BaseModel):
    outputs: List[BlindedMessage]


class PostMintResponse(BaseModel):
    promises: List[BlindedSignature] = []


class GetMintResponse(BaseModel):
    pr: str
    hash: str


# ------- API: MELT -------


class PostMeltRequest(BaseModel):
    proofs: List[Proof]
    pr: str
    outputs: Union[List[BlindedMessage], None]


class GetMeltResponse(BaseModel):
    paid: Union[bool, None]
    preimage: Union[str, None]
    change: Union[List[BlindedSignature], None] = None


# ------- API: SPLIT -------


class PostSplitRequest(BaseModel):
    proofs: List[Proof]
    amount: Optional[int] = None  # deprecated since 0.13.0
    outputs: List[BlindedMessage]
    # signature: Optional[str] = None

    # def sign(self, private_key: PrivateKey):
    #     """
    #     Create a signed split request. The signature is over the `proofs` and `outputs` fields.
    #     """
    #     # message = json.dumps(self.proofs).encode("utf-8") + json.dumps(
    #     #     self.outputs
    #     # ).encode("utf-8")
    #     message = json.dumps(self.dict(include={"proofs": ..., "outputs": ...})).encode(
    #         "utf-8"
    #     )
    #     self.signature = sign_p2pk_sign(message, private_key)


class PostSplitResponse(BaseModel):
    promises: List[BlindedSignature]


# deprecated since 0.13.0
class PostSplitResponse_Deprecated(BaseModel):
    fst: List[BlindedSignature] = []
    snd: List[BlindedSignature] = []
    deprecated: str = "The amount field is deprecated since 0.13.0"


# ------- API: CHECK -------


class CheckSpendableRequest(BaseModel):
    proofs: List[Proof]


class CheckSpendableResponse(BaseModel):
    spendable: List[bool]
    pending: Optional[
        List[bool]
    ] = None  # TODO: Uncomment when all mints are updated to 0.12.3 and support /check
    # with pending tokens (kept for backwards compatibility of new wallets with old mints)


class CheckFeesRequest(BaseModel):
    pr: str


class CheckFeesResponse(BaseModel):
    fee: Union[int, None]


# ------- API: RESTORE -------


class PostRestoreResponse(BaseModel):
    outputs: List[BlindedMessage] = []
    promises: List[BlindedSignature] = []


# ------- KEYSETS -------


class KeyBase(BaseModel):
    """
    Public key from a keyset id for a given amount.
    """

    id: str
    amount: int
    pubkey: str


class WalletKeyset:
    """
    Contains the keyset from the wallets's perspective.
    """

    id: str
    public_keys: Dict[int, PublicKey]
    mint_url: Union[str, None] = None
    valid_from: Union[str, None] = None
    valid_to: Union[str, None] = None
    first_seen: Union[str, None] = None
    active: Union[bool, None] = True

    def __init__(
        self,
        public_keys: Dict[int, PublicKey],
        id=None,
        mint_url=None,
        valid_from=None,
        valid_to=None,
        first_seen=None,
        active=None,
    ):
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.first_seen = first_seen
        self.active = active
        self.mint_url = mint_url

        self.public_keys = public_keys
        # overwrite id by deriving it from the public keys
        self.id = derive_keyset_id(self.public_keys)

    def serialize(self):
        return json.dumps(
            {amount: key.serialize().hex() for amount, key in self.public_keys.items()}
        )

    @classmethod
    def from_row(cls, row: Row):
        def deserialize(serialized: str):
            return {
                amount: PublicKey(bytes.fromhex(hex_key), raw=True)
                for amount, hex_key in dict(json.loads(serialized)).items()
            }

        return cls(
            id=row["id"],
            public_keys=deserialize(str(row["public_keys"]))
            if dict(row).get("public_keys")
            else {},
            mint_url=row["mint_url"],
            valid_from=row["valid_from"],
            valid_to=row["valid_to"],
            first_seen=row["first_seen"],
            active=row["active"],
        )


class MintKeyset:
    """
    Contains the keyset from the mint's perspective.
    """

    id: str
    derivation_path: str
    private_keys: Dict[int, PrivateKey]
    public_keys: Union[Dict[int, PublicKey], None] = None
    valid_from: Union[str, None] = None
    valid_to: Union[str, None] = None
    first_seen: Union[str, None] = None
    active: Union[bool, None] = True
    version: Union[str, None] = None

    def __init__(
        self,
        id=None,
        valid_from=None,
        valid_to=None,
        first_seen=None,
        active=None,
        seed: str = "",
        derivation_path: str = "",
        version: str = "1",
    ):
        self.derivation_path = derivation_path
        self.id = id
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.first_seen = first_seen
        self.active = active
        self.version = version
        # generate keys from seed
        if seed:
            self.generate_keys(seed)

    def generate_keys(self, seed):
        """Generates keys of a keyset from a seed."""
        backwards_compatibility_pre_0_12 = False
        if (
            self.version
            and len(self.version.split(".")) > 1
            and int(self.version.split(".")[0]) == 0
            and int(self.version.split(".")[1]) <= 11
        ):
            backwards_compatibility_pre_0_12 = True
            # WARNING: Broken key derivation for backwards compatibility with < 0.12
            self.private_keys = derive_keys_backwards_compatible_insecure_pre_0_12(
                seed, self.derivation_path
            )
        else:
            self.private_keys = derive_keys(seed, self.derivation_path)
        self.public_keys = derive_pubkeys(self.private_keys)  # type: ignore
        self.id = derive_keyset_id(self.public_keys)  # type: ignore
        if backwards_compatibility_pre_0_12:
            logger.warning(
                f"WARNING: Using weak key derivation for keyset {self.id} (backwards compatibility < 0.12)"
            )


class MintKeysets:
    """
    Collection of keyset IDs and the corresponding keyset of the mint.
    """

    keysets: Dict[str, MintKeyset]

    def __init__(self, keysets: List[MintKeyset]):
        self.keysets = {k.id: k for k in keysets}  # type: ignore

    def get_ids(self):
        return [k for k, _ in self.keysets.items()]


# ------- TOKEN -------


class TokenV1(BaseModel):
    """
    A (legacy) Cashu token that includes proofs. This can only be received if the receiver knows the mint associated with the
    keyset ids of the proofs.
    """

    # NOTE: not used in Pydantic validation
    __root__: List[Proof]


class TokenV2Mint(BaseModel):
    """
    Object that describes how to reach the mints associated with the proofs in a TokenV2 object.
    """

    url: str  # mint URL
    ids: List[str]  # List of keyset id's that are from this mint


class TokenV2(BaseModel):
    """
    A Cashu token that includes proofs and their respective mints. Can include proofs from multiple different mints and keysets.
    """

    proofs: List[Proof]
    mints: Optional[List[TokenV2Mint]] = None

    def to_dict(self):
        if self.mints:
            return dict(
                proofs=[p.to_dict() for p in self.proofs],
                mints=[m.dict() for m in self.mints],
            )
        else:
            return dict(proofs=[p.to_dict() for p in self.proofs])


class TokenV3Token(BaseModel):
    mint: Optional[str] = None
    proofs: List[Proof]

    def to_dict(self, include_dleq=False):
        return_dict = dict(proofs=[p.to_dict(include_dleq) for p in self.proofs])
        if self.mint:
            return_dict.update(dict(mint=self.mint))  # type: ignore
        return return_dict


class TokenV3(BaseModel):
    """
    A Cashu token that includes proofs and their respective mints. Can include proofs from multiple different mints and keysets.
    """

    token: List[TokenV3Token] = []
    memo: Optional[str] = None

    def to_dict(self, include_dleq=False):
        return_dict = dict(token=[t.to_dict(include_dleq) for t in self.token])
        if self.memo:
            return_dict.update(dict(memo=self.memo))  # type: ignore
        return return_dict

    def get_proofs(self):
        return [proof for token in self.token for proof in token.proofs]

    def get_amount(self):
        return sum([p.amount for p in self.get_proofs()])

    def get_keysets(self):
        return list(set([p.id for p in self.get_proofs()]))

    @classmethod
    def deserialize(cls, tokenv3_serialized: str) -> "TokenV3":
        """
        Takes a TokenV3 and serializes it as "cashuA<json_urlsafe_base64>.
        """
        prefix = "cashuA"
        assert tokenv3_serialized.startswith(prefix), Exception(
            f"Token prefix not valid. Expected {prefix}."
        )
        token_base64 = tokenv3_serialized[len(prefix) :]
        token = json.loads(base64.urlsafe_b64decode(token_base64))
        return cls.parse_obj(token)

    def serialize(self, include_dleq=False) -> str:
        """
        Takes a TokenV3 and serializes it as "cashuA<json_urlsafe_base64>.
        """
        prefix = "cashuA"
        tokenv3_serialized = prefix
        # encode the token as a base64 string
        tokenv3_serialized += base64.urlsafe_b64encode(
            json.dumps(self.to_dict(include_dleq)).encode()
        ).decode()
        return tokenv3_serialized
