from typing import Dict, Protocol

import httpx

from ..core.base import Unit, WalletKeyset
from ..core.crypto.secp import PrivateKey
from ..core.db import Database


class SupportsPrivateKey(Protocol):
    private_key: PrivateKey


class SupportsDb(Protocol):
    db: Database


class SupportsKeysets(Protocol):
    keysets: Dict[str, WalletKeyset]  # holds keysets
    keyset_id: str
    unit: Unit


class SupportsHttpxClient(Protocol):
    httpx: httpx.AsyncClient


class SupportsMintURL(Protocol):
    url: str
