from typing import Dict, Protocol

from ..core.base import MintKeyset, Unit
from ..core.db import Database
from ..lightning.base import LightningWallet
from ..mint.crud import LedgerCrud


class SupportsKeysets(Protocol):
    keyset: MintKeyset
    keysets: Dict[str, MintKeyset]


class SupportLightning(Protocol):
    lightning: Dict[Unit, LightningWallet]


class SupportsDb(Protocol):
    db: Database
    crud: LedgerCrud
