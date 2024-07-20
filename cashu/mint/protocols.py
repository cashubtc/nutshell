from typing import Dict, Mapping, Protocol

from ..core.base import Method, MintKeyset, Unit
from ..core.db import Database
from ..lightning.base import LightningBackend
from ..mint.crud import LedgerCrud
from .db.read import DbReadHelper
from .db.write import DbWriteHelper
from .events.events import LedgerEventManager


class SupportsKeysets(Protocol):
    keyset: MintKeyset
    keysets: Dict[str, MintKeyset]


class SupportsBackends(Protocol):
    backends: Mapping[Method, Mapping[Unit, LightningBackend]] = {}


class SupportsDb(Protocol):
    db: Database
    db_read: DbReadHelper
    db_write: DbWriteHelper
    crud: LedgerCrud


class SupportsEvents(Protocol):
    events: LedgerEventManager
