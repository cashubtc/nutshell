import base64
import json
import math
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from sqlite3 import Row
from typing import Any, Dict, List, Optional, Union

import cbor2
from loguru import logger
from pydantic import BaseModel, root_validator

from cashu.core.json_rpc.base import JSONRPCSubscriptionKinds

from ..mint.events.event_model import LedgerEvent
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


class ProofSpentState(Enum):
    unspent = "UNSPENT"
    spent = "SPENT"
    pending = "PENDING"

    def __str__(self):
        return self.name


class ProofState(LedgerEvent):
    Y: str
    state: ProofSpentState
    witness: Optional[str] = None

    @root_validator()
    def check_witness(cls, values):
        state, witness = values.get("state"), values.get("witness")
        if witness is not None and state != ProofSpentState.spent:
            raise ValueError('Witness can only be set if the spent state is "SPENT"')
        return values

    @property
    def identifier(self) -> str:
        """Implementation of the abstract method from LedgerEventManager"""
        return self.Y

    @property
    def kind(self) -> JSONRPCSubscriptionKinds:
        return JSONRPCSubscriptionKinds.PROOF_STATE

    @property
    def unspent(self) -> bool:
        return self.state == ProofSpentState.unspent

    @property
    def spent(self) -> bool:
        return self.state == ProofSpentState.spent

    @property
    def pending(self) -> bool:
        return self.state == ProofSpentState.pending


class HTLCWitness(BaseModel):
    preimage: Optional[str] = None
    signatures: Optional[List[str]] = None

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
    witness: Union[None, str] = None  # witness for spending condition

    # whether this proof is reserved for sending, used for coin management in the wallet
    reserved: Union[None, bool] = False
    # unique ID of send attempt, used for grouping pending tokens in the wallet
    send_id: Union[None, str] = ""
    time_created: Union[None, str] = ""
    time_reserved: Union[None, str] = ""
    derivation_path: Union[None, str] = ""  # derivation path of the proof
    mint_id: Union[None, str] = (
        None  # holds the id of the mint operation that created this proof
    )
    melt_id: Union[None, str] = (
        None  # holds the id of the melt operation that destroyed this proof
    )

    def __init__(self, **data):
        super().__init__(**data)
        self.Y = hash_to_curve(self.secret.encode("utf-8")).serialize().hex()

    @classmethod
    def from_dict(cls, proof_dict: dict):
        if proof_dict.get("dleq") and isinstance(proof_dict["dleq"], dict):
            proof_dict["dleq"] = DLEQWallet(**proof_dict["dleq"])
        elif proof_dict.get("dleq") and isinstance(proof_dict["dleq"], str):
            # Proofs read from the database have the DLEQ proof as a string
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
    def htlcpreimage(self) -> str | None:
        assert self.witness, "Witness is missing for htlc preimage"
        return HTLCWitness.from_witness(self.witness).preimage

    @property
    def htlcsigs(self) -> List[str] | None:
        assert self.witness, "Witness is missing for htlc signatures"
        return HTLCWitness.from_witness(self.witness).signatures


class Proofs(BaseModel):
    # NOTE: not used in Pydantic validation
    __root__: List[Proof]


class BlindedMessage(BaseModel):
    """
    Blinded message or blinded secret or "output" which is to be signed by the mint
    """

    amount: int
    id: str  # Keyset id
    B_: str  # Hex-encoded blinded message
    witness: Union[str, None] = None  # witnesses (used for P2PK with SIG_ALL)

    @property
    def p2pksigs(self) -> List[str]:
        assert self.witness, "Witness missing in output"
        return P2PKWitness.from_witness(self.witness).signatures


class BlindedMessage_Deprecated(BaseModel):
    """
    Deprecated: BlindedMessage for v0 protocol (deprecated api routes) have no id field.

    Blinded message or blinded secret or "output" which is to be signed by the mint
    """

    amount: int
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

    @classmethod
    def from_row(cls, row: Row):
        return cls(
            id=row["id"],
            amount=row["amount"],
            C_=row["c_"],
            dleq=DLEQ(e=row["dleq_e"], s=row["dleq_s"]),
        )


# ------- Quotes -------


class MeltQuoteState(Enum):
    unpaid = "UNPAID"
    pending = "PENDING"
    paid = "PAID"

    def __str__(self):
        return self.name


class MeltQuote(LedgerEvent):
    quote: str
    method: str
    request: str
    checking_id: str
    unit: str
    amount: int
    fee_reserve: int
    state: MeltQuoteState
    created_time: Union[int, None] = None
    paid_time: Union[int, None] = None
    fee_paid: int = 0
    payment_preimage: Optional[str] = None
    expiry: Optional[int] = None
    change: Optional[List[BlindedSignature]] = None
    mint: Optional[str] = None

    @classmethod
    def from_row(cls, row: Row):
        try:
            created_time = int(row["created_time"]) if row["created_time"] else None
            paid_time = int(row["paid_time"]) if row["paid_time"] else None
            expiry = int(row["expiry"]) if row["expiry"] else None
        except Exception:
            created_time = (
                int(row["created_time"].timestamp()) if row["created_time"] else None
            )
            paid_time = int(row["paid_time"].timestamp()) if row["paid_time"] else None
            expiry = int(row["expiry"].timestamp()) if row["expiry"] else None

        payment_preimage = row.get("payment_preimage") or row.get("proof")  # type: ignore

        # parse change from row as json
        change = None
        if row["change"]:
            change = json.loads(row["change"])

        return cls(
            quote=row["quote"],
            method=row["method"],
            request=row["request"],
            checking_id=row["checking_id"],
            unit=row["unit"],
            amount=row["amount"],
            fee_reserve=row["fee_reserve"],
            state=MeltQuoteState(row["state"]),
            created_time=created_time,
            paid_time=paid_time,
            fee_paid=row["fee_paid"],
            change=change,
            expiry=expiry,
            payment_preimage=payment_preimage,
        )

    @classmethod
    def from_resp_wallet(
        cls, melt_quote_resp, mint: str, amount: int, unit: str, request: str
    ):
        # BEGIN: BACKWARDS COMPATIBILITY < 0.16.0: "paid" field to "state"
        if melt_quote_resp.state is None:
            if melt_quote_resp.paid is True:
                melt_quote_resp.state = MeltQuoteState.paid
            elif melt_quote_resp.paid is False:
                melt_quote_resp.state = MeltQuoteState.unpaid
        # END: BACKWARDS COMPATIBILITY < 0.16.0
        return cls(
            quote=melt_quote_resp.quote,
            method="bolt11",
            request=request,
            checking_id="",
            unit=unit,
            amount=amount,
            fee_reserve=melt_quote_resp.fee_reserve,
            state=MeltQuoteState(melt_quote_resp.state),
            mint=mint,
            change=melt_quote_resp.change,
        )

    @property
    def identifier(self) -> str:
        """Implementation of the abstract method from LedgerEventManager"""
        return self.quote

    @property
    def kind(self) -> JSONRPCSubscriptionKinds:
        return JSONRPCSubscriptionKinds.BOLT11_MELT_QUOTE

    @property
    def unpaid(self) -> bool:
        return self.state == MeltQuoteState.unpaid

    @property
    def pending(self) -> bool:
        return self.state == MeltQuoteState.pending

    @property
    def paid(self) -> bool:
        return self.state == MeltQuoteState.paid

    # method that is invoked when the `state` attribute is changed. to protect the state from being set to anything else if the current state is paid
    def __setattr__(self, name, value):
        # an unpaid quote can only be set to pending or paid
        if name == "state" and self.unpaid:
            if value not in [MeltQuoteState.pending, MeltQuoteState.paid]:
                raise Exception(
                    f"Cannot change state of an unpaid melt quote to {value}."
                )
        # a paid quote can not be changed
        if name == "state" and self.paid:
            raise Exception("Cannot change state of a paid melt quote.")

        if name == "paid":
            raise Exception(
                "MeltQuote does not support `paid` anymore! Use `state` instead."
            )
        super().__setattr__(name, value)


class MintQuoteState(Enum):
    unpaid = "UNPAID"
    paid = "PAID"
    pending = "PENDING"
    issued = "ISSUED"

    def __str__(self):
        return self.name


class MintQuote(LedgerEvent):
    quote: str
    method: str
    request: str
    checking_id: str
    unit: str
    amount: int
    state: MintQuoteState
    created_time: Union[int, None] = None
    paid_time: Union[int, None] = None
    expiry: Optional[int] = None
    mint: Optional[str] = None

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
            state=MintQuoteState(row["state"]),
            created_time=created_time,
            paid_time=paid_time,
        )

    @classmethod
    def from_resp_wallet(cls, mint_quote_resp, mint: str, amount: int, unit: str):
        # BEGIN: BACKWARDS COMPATIBILITY < 0.16.0: "paid" field to "state"
        if mint_quote_resp.state is None:
            if mint_quote_resp.paid is True:
                mint_quote_resp.state = MintQuoteState.paid
            elif mint_quote_resp.paid is False:
                mint_quote_resp.state = MintQuoteState.unpaid
        # END: BACKWARDS COMPATIBILITY < 0.16.0
        return cls(
            quote=mint_quote_resp.quote,
            method="bolt11",
            request=mint_quote_resp.request,
            checking_id="",
            unit=unit,
            amount=amount,
            state=MintQuoteState(mint_quote_resp.state),
            mint=mint,
            expiry=mint_quote_resp.expiry,
            created_time=int(time.time()),
        )

    @property
    def identifier(self) -> str:
        """Implementation of the abstract method from LedgerEventManager"""
        return self.quote

    @property
    def kind(self) -> JSONRPCSubscriptionKinds:
        return JSONRPCSubscriptionKinds.BOLT11_MINT_QUOTE

    @property
    def unpaid(self) -> bool:
        return self.state == MintQuoteState.unpaid

    @property
    def paid(self) -> bool:
        return self.state == MintQuoteState.paid

    @property
    def pending(self) -> bool:
        return self.state == MintQuoteState.pending

    @property
    def issued(self) -> bool:
        return self.state == MintQuoteState.issued

    def __setattr__(self, name, value):
        # un unpaid quote can only be set to paid
        if name == "state" and self.unpaid:
            if value != MintQuoteState.paid:
                raise Exception(
                    f"Cannot change state of an unpaid mint quote to {value}."
                )
        # a paid quote can only be set to pending or issued
        if name == "state" and self.paid:
            if value != MintQuoteState.pending and value != MintQuoteState.issued:
                raise Exception(f"Cannot change state of a paid mint quote to {value}.")
        # a pending quote can only be set to paid or issued
        if name == "state" and self.pending:
            if value not in [MintQuoteState.paid, MintQuoteState.issued]:
                raise Exception("Cannot change state of a pending mint quote.")
        # an issued quote cannot be changed
        if name == "state" and self.issued:
            raise Exception("Cannot change state of an issued mint quote.")

        if name == "paid":
            raise Exception(
                "MintQuote does not support `paid` anymore! Use `state` instead."
            )
        super().__setattr__(name, value)


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
    eur = 3
    btc = 4

    def str(self, amount: int) -> str:
        if self == Unit.sat:
            return f"{amount} sat"
        elif self == Unit.msat:
            return f"{amount} msat"
        elif self == Unit.usd:
            return f"${amount/100:.2f} USD"
        elif self == Unit.eur:
            return f"{amount/100:.2f} EUR"
        elif self == Unit.btc:
            return f"{amount/1e8:.8f} BTC"
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

    def to_float_string(self) -> str:
        if self.unit == Unit.usd or self.unit == Unit.eur:
            return self.cents_to_usd()
        elif self.unit == Unit.sat:
            return self.sat_to_btc()
        else:
            raise Exception("Amount must be in satoshis or cents")

    @classmethod
    def from_float(cls, amount: float, unit: Unit) -> "Amount":
        if unit == Unit.usd or unit == Unit.eur:
            return cls(unit, int(amount * 100))
        elif unit == Unit.sat:
            return cls(unit, int(amount * 1e8))
        else:
            raise Exception("Amount must be in satoshis or cents")

    def sat_to_btc(self) -> str:
        if self.unit != Unit.sat:
            raise Exception("Amount must be in satoshis")
        return f"{self.amount/1e8:.8f}"

    def cents_to_usd(self) -> str:
        if self.unit != Unit.usd and self.unit != Unit.eur:
            raise Exception("Amount must be in cents")
        return f"{self.amount/100:.2f}"

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
    input_fee_ppk: int = 0

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
        input_fee_ppk=0,
    ):
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.first_seen = first_seen
        self.active = active
        self.mint_url = mint_url
        self.input_fee_ppk = input_fee_ppk

        self.public_keys = public_keys
        # overwrite id by deriving it from the public keys
        if not id:
            self.id = derive_keyset_id(self.public_keys)
        else:
            self.id = id

        self.unit = Unit[unit]

        if id and id != self.id:
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
            input_fee_ppk=row["input_fee_ppk"],
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
    input_fee_ppk: int
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
        input_fee_ppk: Optional[int] = None,
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
        self.input_fee_ppk = input_fee_ppk or 0

        if self.input_fee_ppk < 0:
            raise Exception("Input fee must be non-negative.")

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

        # BEGIN: BACKWARDS COMPATIBILITY < 0.15.0
        # we overwrite keyset id only if it isn't already set in the database
        # loaded from the database. This is to allow for backwards compatibility
        # with old keysets with new id's and vice versa. This code and successive
        # `id_in_db or` parts can be removed if there are only new keysets in the mint (> 0.15.0)
        id_in_db = self.id

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
            self.id = id_in_db or derive_keyset_id_deprecated(self.public_keys)  # type: ignore
        elif self.version_tuple < (0, 15):
            self.private_keys = derive_keys_sha256(self.seed, self.derivation_path)
            logger.trace(
                f"WARNING: Using non-bip32 derivation for keyset {self.id} (backwards"
                " compatibility < 0.15)"
            )
            self.public_keys = derive_pubkeys(self.private_keys)  # type: ignore
            self.id = id_in_db or derive_keyset_id_deprecated(self.public_keys)  # type: ignore
        else:
            self.private_keys = derive_keys(self.seed, self.derivation_path)
            self.public_keys = derive_pubkeys(self.private_keys)  # type: ignore
            self.id = id_in_db or derive_keyset_id(self.public_keys)  # type: ignore


# ------- TOKEN -------


class Token(ABC):
    @property
    @abstractmethod
    def proofs(self) -> List[Proof]: ...

    @property
    @abstractmethod
    def amount(self) -> int: ...

    @property
    @abstractmethod
    def mint(self) -> str: ...

    @property
    @abstractmethod
    def keysets(self) -> List[str]: ...

    @property
    @abstractmethod
    def memo(self) -> Optional[str]: ...

    @memo.setter
    @abstractmethod
    def memo(self, memo: Optional[str]): ...

    @property
    @abstractmethod
    def unit(self) -> str: ...

    @unit.setter
    @abstractmethod
    def unit(self, unit: str): ...


class TokenV3Token(BaseModel):
    mint: Optional[str] = None
    proofs: List[Proof]

    def to_dict(self, include_dleq=False):
        return_dict = dict(proofs=[p.to_dict(include_dleq) for p in self.proofs])
        if self.mint:
            return_dict.update(dict(mint=self.mint))  # type: ignore
        return return_dict


@dataclass
class TokenV3(Token):
    """
    A Cashu token that includes proofs and their respective mints. Can include proofs from multiple different mints and keysets.
    """

    token: List[TokenV3Token] = field(default_factory=list)
    _memo: Optional[str] = None
    _unit: str = "sat"

    class Config:
        allow_population_by_field_name = True

    @property
    def proofs(self) -> List[Proof]:
        return [proof for token in self.token for proof in token.proofs]

    @property
    def amount(self) -> int:
        return sum([p.amount for p in self.proofs])

    @property
    def keysets(self) -> List[str]:
        return list({p.id for p in self.proofs})

    @property
    def mint(self) -> str:
        return self.mints[0]

    @property
    def mints(self) -> List[str]:
        return list({t.mint for t in self.token if t.mint})

    @property
    def memo(self) -> Optional[str]:
        return str(self._memo) if self._memo else None

    @memo.setter
    def memo(self, memo: Optional[str]):
        self._memo = memo

    @property
    def unit(self) -> str:
        return self._unit

    @unit.setter
    def unit(self, unit: str):
        self._unit = unit

    def serialize_to_dict(self, include_dleq=False):
        return_dict = dict(token=[t.to_dict(include_dleq) for t in self.token])
        if self.memo:
            return_dict.update(dict(memo=self.memo))  # type: ignore
        return_dict.update(dict(unit=self.unit))  # type: ignore
        return return_dict

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
            json.dumps(
                self.serialize_to_dict(include_dleq), separators=(",", ":")
            ).encode()
        ).decode()
        # remove padding
        tokenv3_serialized = tokenv3_serialized.rstrip("=")
        return tokenv3_serialized

    @classmethod
    def parse_obj(cls, token_dict: Dict[str, Any]):
        if not token_dict.get("token"):
            raise Exception("Token must contain proofs.")
        token: List[Dict[str, Any]] = token_dict.get("token") or []
        assert token, "Token must contain proofs."
        return cls(
            token=[
                TokenV3Token(
                    mint=t.get("mint"),
                    proofs=[Proof.from_dict(p) for p in t.get("proofs") or []],
                )
                for t in token
            ],
            _memo=token_dict.get("memo"),
            _unit=token_dict.get("unit") or "sat",
        )


class TokenV4DLEQ(BaseModel):
    """
    Discrete Log Equality (DLEQ) Proof
    """

    e: bytes
    s: bytes
    r: bytes


class TokenV4Proof(BaseModel):
    """
    Value token
    """

    a: int
    s: str  # secret
    c: bytes  # signature
    d: Optional[TokenV4DLEQ] = None  # DLEQ proof
    w: Optional[str] = None  # witness

    @classmethod
    def from_proof(cls, proof: Proof, include_dleq=False):
        return cls(
            a=proof.amount,
            s=proof.secret,
            c=bytes.fromhex(proof.C),
            d=(
                TokenV4DLEQ(
                    e=bytes.fromhex(proof.dleq.e),
                    s=bytes.fromhex(proof.dleq.s),
                    r=bytes.fromhex(proof.dleq.r),
                )
                if proof.dleq
                else None
            ),
            w=proof.witness,
        )


class TokenV4Token(BaseModel):
    # keyset ID
    i: bytes
    # proofs
    p: List[TokenV4Proof]


@dataclass
class TokenV4(Token):
    # mint URL
    m: str
    # unit
    u: str
    # tokens
    t: List[TokenV4Token]
    # memo
    d: Optional[str] = None

    @property
    def mint(self) -> str:
        return self.m

    def set_mint(self, mint: str):
        self.m = mint

    @property
    def memo(self) -> Optional[str]:
        return self.d

    @memo.setter
    def memo(self, memo: Optional[str]):
        self.d = memo

    @property
    def unit(self) -> str:
        return self.u

    @unit.setter
    def unit(self, unit: str):
        self.u = unit

    @property
    def amounts(self) -> List[int]:
        return [p.a for token in self.t for p in token.p]

    @property
    def amount(self) -> int:
        return sum(self.amounts)

    @property
    def proofs(self) -> List[Proof]:
        return [
            Proof(
                id=token.i.hex(),
                amount=p.a,
                secret=p.s,
                C=p.c.hex(),
                dleq=(
                    DLEQWallet(
                        e=p.d.e.hex(),
                        s=p.d.s.hex(),
                        r=p.d.r.hex(),
                    )
                    if p.d
                    else None
                ),
                witness=p.w,
            )
            for token in self.t
            for p in token.p
        ]

    @property
    def keysets(self) -> List[str]:
        return list({p.i.hex() for p in self.t})

    @classmethod
    def from_tokenv3(cls, tokenv3: TokenV3):
        if not len(tokenv3.mints) == 1:
            raise Exception("TokenV3 must contain proofs from only one mint.")

        proofs = tokenv3.proofs
        proofs_by_id: Dict[str, List[Proof]] = {}
        for proof in proofs:
            proofs_by_id.setdefault(proof.id, []).append(proof)

        cls.t = []
        for keyset_id, proofs in proofs_by_id.items():
            cls.t.append(
                TokenV4Token(
                    i=bytes.fromhex(keyset_id),
                    p=[
                        TokenV4Proof(
                            a=p.amount,
                            s=p.secret,
                            c=bytes.fromhex(p.C),
                            d=(
                                TokenV4DLEQ(
                                    e=bytes.fromhex(p.dleq.e),
                                    s=bytes.fromhex(p.dleq.s),
                                    r=bytes.fromhex(p.dleq.r),
                                )
                                if p.dleq
                                else None
                            ),
                            w=p.witness,
                        )
                        for p in proofs
                    ],
                )
            )

        # set memo
        cls.d = tokenv3.memo
        # set mint
        cls.m = tokenv3.mint
        # set unit
        cls.u = tokenv3.unit or "sat"
        return cls(t=cls.t, d=cls.d, m=cls.m, u=cls.u)

    def serialize_to_dict(self, include_dleq=False):
        return_dict: Dict[str, Any] = dict(t=[t.dict() for t in self.t])
        # strip dleq if needed
        if not include_dleq:
            for token in return_dict["t"]:
                for proof in token["p"]:
                    if "d" in proof:
                        del proof["d"]
        # strip witness if not present
        for token in return_dict["t"]:
            for proof in token["p"]:
                if not proof.get("w"):
                    del proof["w"]
        # optional memo
        if self.d:
            return_dict.update(dict(d=self.d))
        # mint
        return_dict.update(dict(m=self.m))
        # unit
        return_dict.update(dict(u=self.u))
        return return_dict

    def serialize(self, include_dleq=False) -> str:
        """
        Takes a TokenV4 and serializes it as "cashuB<cbor_urlsafe_base64>.
        """
        prefix = "cashuB"
        tokenv4_serialized = prefix
        # encode the token as a base64 string
        tokenv4_serialized += base64.urlsafe_b64encode(
            cbor2.dumps(self.serialize_to_dict(include_dleq))
        ).decode()
        # remove padding
        tokenv4_serialized = tokenv4_serialized.rstrip("=")
        return tokenv4_serialized

    @classmethod
    def deserialize(cls, tokenv4_serialized: str) -> "TokenV4":
        """
        Ingesta a serialized "cashuB<cbor_urlsafe_base64>" token and returns a TokenV4.
        """
        prefix = "cashuB"
        assert tokenv4_serialized.startswith(prefix), Exception(
            f"Token prefix not valid. Expected {prefix}."
        )
        token_base64 = tokenv4_serialized[len(prefix) :]
        # if base64 string is not a multiple of 4, pad it with "="
        token_base64 += "=" * (4 - len(token_base64) % 4)

        token = cbor2.loads(base64.urlsafe_b64decode(token_base64))
        return cls.parse_obj(token)

    def to_tokenv3(self) -> TokenV3:
        tokenv3 = TokenV3(_memo=self.d, _unit=self.u)
        for token in self.t:
            tokenv3.token.append(
                TokenV3Token(
                    mint=self.m,
                    proofs=[
                        Proof(
                            id=token.i.hex(),
                            amount=p.a,
                            secret=p.s,
                            C=p.c.hex(),
                            dleq=(
                                DLEQWallet(
                                    e=p.d.e.hex(),
                                    s=p.d.s.hex(),
                                    r=p.d.r.hex(),
                                )
                                if p.d
                                else None
                            ),
                            witness=p.w,
                        )
                        for p in token.p
                    ],
                )
            )
        return tokenv3

    @classmethod
    def parse_obj(cls, token_dict: dict):
        return cls(
            m=token_dict["m"],
            u=token_dict["u"],
            t=[TokenV4Token(**t) for t in token_dict["t"]],
            d=token_dict.get("d", None),
        )
