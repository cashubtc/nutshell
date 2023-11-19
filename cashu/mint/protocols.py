from typing import Dict, Protocol

from ..core.base import MintKeyset
from ..core.db import Database
from ..lightning.base import Wallet
from ..mint.crud import LedgerCrud


class SupportsKeysets(Protocol):
    keyset: MintKeyset
    keysets: Dict[str, MintKeyset]


class SupportLightning(Protocol):
    lightning: Wallet


class SupportsDb(Protocol):
    db: Database
    crud: LedgerCrud
