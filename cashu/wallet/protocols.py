from typing import Protocol

from ..core.crypto.secp import PrivateKey
from ..core.db import Database


class SupportsPrivateKey(Protocol):
    private_key: PrivateKey


class SupportsDb(Protocol):
    db: Database


class SupportsKeysets(Protocol):
    keyset_id: str
