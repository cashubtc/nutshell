import base64
import json
import math
from dataclasses import dataclass
from enum import Enum
from sqlite3 import Row
from typing import Dict, List, Optional, Union

from loguru import logger
from pydantic import BaseModel

from .crypto.aes import AESCipher
from .crypto.b_dhke import hash_to_curve
from .crypto.keys import (
    derive_keys,
    derive_keys_sha256,
    derive_keyset_id,
    derive_keyset_id_deprecated,
    derive_pubkeys,
)
from .crypto.secp import PrivateKey, PublicKey
from .legacy import derive_keys_backwards_compatible_insecure_pre_0_12
from .settings import settings


class DLEQ(BaseModel):
    """
    Discrete Log Equality (DLEQ) Proof
    """

    e: str
    s: str


class DLEQWallet(BaseModel):
    """
    Discrete Log Equality (DLEQ) Proof
    """

    e: str
    s: str
    r: str  # blinding_factor, unknown to mint but sent from wallet to wallet for DLEQ proof


# ------- PROOFS -------


class HTLCWitness(BaseModel):
    preimage: Optional[str] = None
    signature: Optional[str] = None

    @classmethod
    def from_witness(cls, witness: str):
        return cls(**json.loads(witness))


class P2SHWitness(BaseModel):
    """
    Unlocks P2SH spending condition of a Proof
    """

    script: str
    signature: str
    address: Union[str, None] = None

    @classmethod
    def from_witness(cls, witness: str):
        return cls(**json.loads(witness))


class P2PKWitness(BaseModel):
    """
    Unlocks P2PK spending condition of a Proof
    """

    signatures: List[str]

    @classmethod
    def from_witness(cls, witness: str):
        return cls(**json.loads(witness))


class Proof(BaseModel):
    """
    Value token
    """

    id: str = ""
    amount: int = 0
    secret: str = ""  # secret or message to be blinded and signed
    Y: str = ""  # hash_to_curve(secret)
    C: str = ""  # signature on secret, unblinded by wallet
    dleq: Optional[DLEQWallet] = None  # DLEQ proof
    witness: Union[None, str] = ""  # witness for spending condition

    # whether this proof is reserved for sending, used for coin management in the wallet
    reserved: Union[None, bool] = False
    # unique ID of send attempt, used for grouping pending tokens in the wallet
    send_id: Union[None, str] = ""
    time_created: Union[None, str] = ""
    time_reserved: Union[None, str] = ""
    derivation_path: Union[None, str] = ""  # derivation path of the proof
    mint_id: Union[
        None, str
    ] = None  # holds the id of the mint operation that created this proof
    melt_id: Union[
        None, str
    ] = None  # holds the id of the melt operation that destroyed this proof

    def __init__(self, **data):
        super().__init__(**data)
        self.Y = hash_to_curve(self.secret.encode("utf-8")).serialize().hex()

    @classmethod
    def from_dict(cls, proof_dict: dict):
        if proof_dict.get("dleq") and isinstance(proof_dict["dleq"], str):
            proof_dict["dleq"] = DLEQWallet(**json.loads(proof_dict["dleq"]))
        else:
            # overwrite the empty string with None
            proof_dict["dleq"] = None
        c = cls(**proof_dict)
        return c

    def to_dict(self, include_dleq=False):
        # necessary fields
        return_dict = dict(id=self.id, amount=self.amount, secret=self.secret, C=self.C)

        # optional fields
        if include_dleq:
            assert self.dleq, "DLEQ proof is missing"
            return_dict["dleq"] = self.dleq.dict()  # type: ignore

        if self.witness:
            return_dict["witness"] = self.witness

        return return_dict

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

    @property
    def p2pksigs(self) -> List[str]:
        assert self.witness, "Witness is missing for p2pk signature"
        return P2PKWitness.from_witness(self.witness).signatures

    @property
    def htlcpreimage(self) -> Union[str, None]:
        assert self.witness, "Witness is missing for htlc preimage"
        return HTLCWitness.from_witness(self.witness).preimage


class Proofs(BaseModel):
    # NOTE: not used in Pydantic validation
    __root__: List[Proof]


class BlindedMessage(BaseModel):
    """
    Blinded message or blinded secret or "output" which is to be signed by the mint
    """

    amount: int
    id: Optional[
        str
    ]  # DEPRECATION: Only Optional for backwards compatibility with old clients < 0.15 for deprecated API route.
    B_: str  # Hex-encoded blinded message
    witness: Union[str, None] = None  # witnesses (used for P2PK with SIG_ALL)

    @property
    def p2pksigs(self) -> List[str]:
        assert self.witness, "Witness missing in output"
        return P2PKWitness.from_witness(self.witness).signatures


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
    bolt11: str
    id: str
    out: Union[None, bool] = None
    payment_hash: Union[None, str] = None
    preimage: Union[str, None] = None
    issued: Union[None, bool] = False
    paid: Union[None, bool] = False
    time_created: Union[None, str, int, float] = ""
    time_paid: Union[None, str, int, float] = ""


class MeltQuote(BaseModel):
    quote: str
    method: str
    request: str
    checking_id: str
    unit: str
    amount: int
    fee_reserve: int
    paid: bool
    created_time: Union[int, None] = None
    paid_time: Union[int, None] = None
    fee_paid: int = 0
    proof: str = ""
    expiry: Optional[int] = None

    @classmethod
    def from_row(cls, row: Row):
        try:
            created_time = int(row["created_time"]) if row["created_time"] else None
            paid_time = int(row["paid_time"]) if row["paid_time"] else None
        except Exception:
            created_time = (
                int(row["created_time"].timestamp()) if row["created_time"] else None
            )
            paid_time = int(row["paid_time"].timestamp()) if row["paid_time"] else None

        return cls(
            quote=row["quote"],
            method=row["method"],
            request=row["request"],
            checking_id=row["checking_id"],
            unit=row["unit"],
            amount=row["amount"],
            fee_reserve=row["fee_reserve"],
            paid=row["paid"],
            created_time=created_time,
            paid_time=paid_time,
            fee_paid=row["fee_paid"],
            proof=row["proof"],
        )


class MintQuote(BaseModel):
    quote: str
    method: str
    request: str
    checking_id: str
    unit: str
    amount: int
    paid: bool
    issued: bool
    created_time: Union[int, None] = None
    paid_time: Union[int, None] = None
    expiry: Optional[int] = None

    @classmethod
    def from_row(cls, row: Row):
        try:
            #  SQLITE: row is timestamp (string)
            created_time = int(row["created_time"]) if row["created_time"] else None
            paid_time = int(row["paid_time"]) if row["paid_time"] else None
        except Exception:
            # POSTGRES: row is datetime.datetime
            created_time = (
                int(row["created_time"].timestamp()) if row["created_time"] else None
            )
            paid_time = int(row["paid_time"].timestamp()) if row["paid_time"] else None
        return cls(
            quote=row["quote"],
            method=row["method"],
            request=row["request"],
            checking_id=row["checking_id"],
            unit=row["unit"],
            amount=row["amount"],
            paid=row["paid"],
            issued=row["issued"],
            created_time=created_time,
            paid_time=paid_time,
        )


# ------- KEYSETS -------


class KeyBase(BaseModel):
    """
    Public key from a keyset id for a given amount.
    """

    id: str
    amount: int
    pubkey: str


class Unit(Enum):
    sat = 0
    msat = 1
    usd = 2

    def str(self, amount: int) -> str:
        if self == Unit.sat:
            return f"{amount} sat"
        elif self == Unit.msat:
            return f"{amount} msat"
        elif self == Unit.usd:
            return f"${amount/100:.2f} USD"
        else:
            raise Exception("Invalid unit")

    def __str__(self):
        return self.name


@dataclass
class Amount:
    unit: Unit
    amount: int

    def to(self, to_unit: Unit, round: Optional[str] = None):
        if self.unit == to_unit:
            return self

        if self.unit == Unit.sat:
            if to_unit == Unit.msat:
                return Amount(to_unit, self.amount * 1000)
            else:
                raise Exception(f"Cannot convert {self.unit.name} to {to_unit.name}")
        elif self.unit == Unit.msat:
            if to_unit == Unit.sat:
                if round == "up":
                    return Amount(to_unit, math.ceil(self.amount / 1000))
                elif round == "down":
                    return Amount(to_unit, math.floor(self.amount / 1000))
                else:
                    return Amount(to_unit, self.amount // 1000)
            else:
                raise Exception(f"Cannot convert {self.unit.name} to {to_unit.name}")
        else:
            return self

    def str(self) -> str:
        return self.unit.str(self.amount)

    def __repr__(self):
        return self.unit.str(self.amount)


class Method(Enum):
    bolt11 = 0


class WalletKeyset:
    """
    Contains the keyset from the wallets's perspective.
    """

    id: str
    unit: Unit
    public_keys: Dict[int, PublicKey]
    mint_url: Union[str, None] = None
    valid_from: Union[str, None] = None
    valid_to: Union[str, None] = None
    first_seen: Union[str, None] = None
    active: Union[bool, None] = True

    def __init__(
        self,
        public_keys: Dict[int, PublicKey],
        unit: str,
        id: Optional[str] = None,
        mint_url=None,
        valid_from=None,
        valid_to=None,
        first_seen=None,
        active=True,
        use_deprecated_id=False,  # BACKWARDS COMPATIBILITY < 0.15.0
    ):
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.first_seen = first_seen
        self.active = active
        self.mint_url = mint_url

        self.public_keys = public_keys
        # overwrite id by deriving it from the public keys
        if not id:
            self.id = derive_keyset_id(self.public_keys)
        else:
            self.id = id

        # BEGIN BACKWARDS COMPATIBILITY < 0.15.0
        if use_deprecated_id:
            logger.warning(
                "Using deprecated keyset id derivation for backwards compatibility <"
                " 0.15.0"
            )
            self.id = derive_keyset_id_deprecated(self.public_keys)
        # END BACKWARDS COMPATIBILITY < 0.15.0

        self.unit = Unit[unit]

        logger.trace(f"Derived keyset id {self.id} from public keys.")
        if id and id != self.id and use_deprecated_id:
            logger.warning(
                f"WARNING: Keyset id {self.id} does not match the given id {id}."
                " Overwriting."
            )
            self.id = id

    def serialize(self):
        return json.dumps(
            {amount: key.serialize().hex() for amount, key in self.public_keys.items()}
        )

    @classmethod
    def from_row(cls, row: Row):
        def deserialize(serialized: str) -> Dict[int, PublicKey]:
            return {
                int(amount): PublicKey(bytes.fromhex(hex_key), raw=True)
                for amount, hex_key in dict(json.loads(serialized)).items()
            }

        return cls(
            id=row["id"],
            unit=row["unit"],
            public_keys=(
                deserialize(str(row["public_keys"]))
                if dict(row).get("public_keys")
                else {}
            ),
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
    private_keys: Dict[int, PrivateKey]
    active: bool
    unit: Unit
    derivation_path: str
    seed: Optional[str] = None
    encrypted_seed: Optional[str] = None
    seed_encryption_method: Optional[str] = None
    public_keys: Optional[Dict[int, PublicKey]] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    first_seen: Optional[str] = None
    version: Optional[str] = None

    duplicate_keyset_id: Optional[str] = None  # BACKWARDS COMPATIBILITY < 0.15.0

    def __init__(
        self,
        *,
        derivation_path: str,
        seed: Optional[str] = None,
        encrypted_seed: Optional[str] = None,
        seed_encryption_method: Optional[str] = None,
        valid_from: Optional[str] = None,
        valid_to: Optional[str] = None,
        first_seen: Optional[str] = None,
        active: Optional[bool] = None,
        unit: Optional[str] = None,
        version: Optional[str] = None,
        id: str = "",
    ):
        self.derivation_path = derivation_path

        if encrypted_seed and not settings.mint_seed_decryption_key:
            raise Exception("MINT_SEED_DECRYPTION_KEY not set, but seed is encrypted.")
        if settings.mint_seed_decryption_key and encrypted_seed:
            self.seed = AESCipher(settings.mint_seed_decryption_key).decrypt(
                encrypted_seed
            )
        else:
            self.seed = seed

        assert self.seed, "seed not set"

        self.id = id
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.first_seen = first_seen
        self.active = bool(active) if active is not None else False
        self.version = version or settings.version

        self.version_tuple = tuple(
            [int(i) for i in self.version.split(".")] if self.version else []
        )

        # infer unit from derivation path
        if not unit:
            logger.trace(
                f"Unit for keyset {self.derivation_path} not set – attempting to parse"
                " from derivation path"
            )
            try:
                self.unit = Unit(
                    int(self.derivation_path.split("/")[2].replace("'", ""))
                )
                logger.trace(f"Inferred unit: {self.unit.name}")
            except Exception:
                logger.trace(
                    "Could not infer unit from derivation path"
                    f" {self.derivation_path} – assuming 'sat'"
                )
                self.unit = Unit.sat
        else:
            self.unit = Unit[unit]

        # generate keys from seed
        assert self.seed, "seed not set"
        assert self.derivation_path, "derivation path not set"

        self.generate_keys()

        logger.trace(f"Loaded keyset id: {self.id} ({self.unit.name})")

    @property
    def public_keys_hex(self) -> Dict[int, str]:
        assert self.public_keys, "public keys not set"
        return {
            int(amount): key.serialize().hex()
            for amount, key in self.public_keys.items()
        }

    def generate_keys(self):
        """Generates keys of a keyset from a seed."""
        assert self.seed, "seed not set"
        assert self.derivation_path, "derivation path not set"

        if self.version_tuple < (0, 12):
            # WARNING: Broken key derivation for backwards compatibility with < 0.12
            self.private_keys = derive_keys_backwards_compatible_insecure_pre_0_12(
                self.seed, self.derivation_path
            )
            self.public_keys = derive_pubkeys(self.private_keys)  # type: ignore
            logger.trace(
                f"WARNING: Using weak key derivation for keyset {self.id} (backwards"
                " compatibility < 0.12)"
            )
            self.id = derive_keyset_id_deprecated(self.public_keys)  # type: ignore
        elif self.version_tuple < (0, 15):
            self.private_keys = derive_keys_sha256(self.seed, self.derivation_path)
            logger.trace(
                f"WARNING: Using non-bip32 derivation for keyset {self.id} (backwards"
                " compatibility < 0.15)"
            )
            self.public_keys = derive_pubkeys(self.private_keys)  # type: ignore
            self.id = derive_keyset_id_deprecated(self.public_keys)  # type: ignore
        else:
            self.private_keys = derive_keys(self.seed, self.derivation_path)
            self.public_keys = derive_pubkeys(self.private_keys)  # type: ignore
            self.id = derive_keyset_id(self.public_keys)  # type: ignore


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

    def get_mints(self):
        return list(set([t.mint for t in self.token if t.mint]))

    @classmethod
    def deserialize(cls, tokenv3_serialized: str) -> "TokenV3":
        """
        Ingesta a serialized "cashuA<json_urlsafe_base64>" token and returns a TokenV3.
        """
        prefix = "cashuA"
        assert tokenv3_serialized.startswith(prefix), Exception(
            f"Token prefix not valid. Expected {prefix}."
        )
        token_base64 = tokenv3_serialized[len(prefix) :]
        # if base64 string is not a multiple of 4, pad it with "="
        token_base64 += "=" * (4 - len(token_base64) % 4)

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
