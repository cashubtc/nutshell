from sqlite3 import Row
from typing import Any, Dict, List, Union

from pydantic import BaseModel

from cashu.core.crypto import derive_keys, derive_keyset_id, derive_pubkeys
from cashu.core.secp import PrivateKey, PublicKey


class P2SHScript(BaseModel):
    script: str
    signature: str
    address: Union[str, None] = None

    @classmethod
    def from_row(cls, row: Row):
        return cls(
            address=row[0],
            script=row[1],
            signature=row[2],
            used=row[3],
        )


class Proof(BaseModel):
    id: str = ""
    amount: int = 0
    secret: str = ""
    C: str = ""
    script: Union[P2SHScript, None] = None
    reserved: bool = False  # whether this proof is reserved for sending
    send_id: str = ""  # unique ID of send attempt
    time_created: str = ""
    time_reserved: str = ""

    @classmethod
    def from_row(cls, row: Row):
        return cls(
            amount=row[0],
            C=row[1],
            secret=row[2],
            reserved=row[3] or False,
            send_id=row[4] or "",
            time_created=row[5] or "",
            time_reserved=row[6] or "",
            id=row[7] or "",
        )

    @classmethod
    def from_dict(cls, d: dict):
        assert "amount" in d, "no amount in proof"
        return cls(
            amount=d.get("amount"),
            C=d.get("C"),
            secret=d.get("secret") or "",
            reserved=d.get("reserved") or False,
            send_id=d.get("send_id") or "",
            time_created=d.get("time_created") or "",
            time_reserved=d.get("time_reserved") or "",
        )

    def to_dict(self):
        return dict(id=self.id, amount=self.amount, secret=self.secret, C=self.C)

    def to_dict_no_secret(self):
        return dict(id=self.id, amount=self.amount, C=self.C)

    def __getitem__(self, key):
        return self.__getattribute__(key)

    def __setitem__(self, key, val):
        self.__setattr__(key, val)


class Proofs(BaseModel):
    """TODO: Use this model"""

    proofs: List[Proof]


class Invoice(BaseModel):
    amount: int
    pr: str
    hash: str
    issued: bool = False

    @classmethod
    def from_row(cls, row: Row):
        return cls(
            amount=int(row[0]),
            pr=str(row[1]),
            hash=str(row[2]),
            issued=bool(row[3]),
        )


class BlindedMessage(BaseModel):
    amount: int
    B_: str


class BlindedSignature(BaseModel):
    id: Union[str, None] = None
    amount: int
    C_: str

    @classmethod
    def from_dict(cls, d: dict):
        return cls(
            id=d.get("id"),
            amount=d["amount"],
            C_=d["C_"],
        )


class MintRequest(BaseModel):
    blinded_messages: List[BlindedMessage] = []


class GetMintResponse(BaseModel):
    pr: str
    hash: str


class GetMeltResponse(BaseModel):
    paid: Union[bool, None]
    preimage: Union[str, None]


class SplitRequest(BaseModel):
    proofs: List[Proof]
    amount: int
    output_data: Union[
        MintRequest, None
    ] = None  # backwards compatibility with clients < v0.2.2
    outputs: Union[MintRequest, None] = None

    def __init__(self, **data):
        super().__init__(**data)
        self.backwards_compatibility_v021()

    def backwards_compatibility_v021(self):
        # before v0.2.2: output_data, after: outputs
        if self.output_data:
            self.outputs = self.output_data
            self.output_data = None


class PostSplitResponse(BaseModel):
    fst: List[BlindedSignature]
    snd: List[BlindedSignature]


class CheckRequest(BaseModel):
    proofs: List[Proof]


class CheckFeesRequest(BaseModel):
    pr: str


class CheckFeesResponse(BaseModel):
    fee: Union[int, None]


class MeltRequest(BaseModel):
    proofs: List[Proof]
    invoice: str


class KeyBase(BaseModel):
    id: str
    amount: int
    pubkey: str

    @classmethod
    def from_row(cls, row: Row):
        if row is None:
            return cls
        return cls(
            id=row[0],
            amount=int(row[1]),
            pubkey=row[2],
        )


class WalletKeyset:
    id: str
    public_keys: Dict[int, PublicKey]
    mint_url: Union[str, None] = None
    valid_from: Union[str, None] = None
    valid_to: Union[str, None] = None
    first_seen: Union[str, None] = None
    active: bool = True

    def __init__(
        self,
        pubkeys: Dict[int, PublicKey] = None,
        mint_url=None,
        id=None,
        valid_from=None,
        valid_to=None,
        first_seen=None,
        active=None,
    ):
        self.id = id
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.first_seen = first_seen
        self.active = active
        self.mint_url = mint_url
        if pubkeys:
            self.public_keys = pubkeys
            self.id = derive_keyset_id(self.public_keys)

    @classmethod
    def from_row(cls, row: Row):
        if row is None:
            return cls
        return cls(
            id=row[0],
            mint_url=row[1],
            valid_from=row[2],
            valid_to=row[3],
            first_seen=row[4],
            active=row[5],
        )


class MintKeyset:
    id: str
    derivation_path: str
    private_keys: Dict[int, PrivateKey]
    public_keys: Dict[int, PublicKey] = {}
    valid_from: Union[str, None] = None
    valid_to: Union[str, None] = None
    first_seen: Union[str, None] = None
    active: bool = True
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
        version: str = "",
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
        self.private_keys = derive_keys(seed, self.derivation_path)
        self.public_keys = derive_pubkeys(self.private_keys)
        self.id = derive_keyset_id(self.public_keys)

    @classmethod
    def from_row(cls, row: Row):
        if row is None:
            return cls
        return cls(
            id=row[0],
            derivation_path=row[1],
            valid_from=row[2],
            valid_to=row[3],
            first_seen=row[4],
            active=row[5],
            version=row[6],
        )

    def get_keybase(self):
        return {
            k: KeyBase(id=self.id, amount=k, pubkey=v.serialize().hex())
            for k, v in self.public_keys.items()
        }


class MintKeysets:
    keysets: Dict[str, MintKeyset]

    def __init__(self, keysets: List[MintKeyset]):
        self.keysets: Dict[str, MintKeyset] = {k.id: k for k in keysets}

    def get_ids(self):
        return [k for k, _ in self.keysets.items()]
