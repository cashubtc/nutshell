from typing import Dict, Mapping, Protocol, List

from ..core.base import Method, MintKeyset, Unit
from ..core.crypto.secp import PublicKey
from ..core.db import Database
from ..lightning.base import LightningBackend
from ..mint.crud import LedgerCrud
from .db.read import DbReadHelper
from .db.write import DbWriteHelper
from .events.events import LedgerEventManager


class SupportsSeed(Protocol):
    seed: str

class SupportsKeysets(Protocol):
    amounts: List[int]
    keyset: MintKeyset
    keysets: Dict[str, MintKeyset]
    derivation_path: str


class SupportsBackends(Protocol):
    backends: Mapping[Method, Mapping[Unit, LightningBackend]] = {}


class SupportsPubkey(Protocol):
    pubkey: PublicKey


class SupportsDb(Protocol):
    db: Database
    db_read: DbReadHelper
    db_write: DbWriteHelper
    crud: LedgerCrud


class SupportsEvents(Protocol):
    events: LedgerEventManager
