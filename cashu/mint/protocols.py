from typing import Protocol

from ..core.base import MintKeyset, MintKeysets
from ..core.db import Database
from ..lightning.base import Wallet
from ..mint.crud import LedgerCrud


class SupportsKeysets(Protocol):
    keyset: MintKeyset
    keysets: MintKeysets


class SupportLightning(Protocol):
    lightning: Wallet


class SupportsDb(Protocol):
    db: Database
    crud: LedgerCrud
