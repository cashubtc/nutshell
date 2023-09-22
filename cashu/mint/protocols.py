from typing import Protocol

from ..core.base import MintKeyset, MintKeysets


class SupportsKeysets(Protocol):
    keyset: MintKeyset
    keysets: MintKeysets
