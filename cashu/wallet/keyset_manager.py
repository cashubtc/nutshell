from typing import Any, Dict

from loguru import logger

from cashu.core.crypto.keys import (
    derive_keyset_short_id,
)


class KeysetManager:
    """
    Wallet-side manager for mapping between full keyset IDs and short keyset IDs (s_id).

    - s_id (short id) is 8 bytes (16 hex chars) for v2 keysets: version byte + first 7 bytes of hash
    - For v1 keysets (00...), the short id equals the full id (legacy behavior)

    The mint is agnostic of s_id. Wallets must expand short ids to full ids before use.
    """

    def __init__(self):
        self._short_to_full_cache: Dict[str, str] = {}
        self._full_to_short_cache: Dict[str, str] = {}

    def get_short_keyset_id(self, full_id: str) -> str:
        """
        Return the wallet-side short keyset id for a given full keyset id.
        - v1: passthrough
        - v2: 16-hex s_id (8 bytes)
        """
        if full_id in self._full_to_short_cache:
            return self._full_to_short_cache[full_id]

        short_id = derive_keyset_short_id(full_id)

        self._full_to_short_cache[full_id] = short_id
        self._short_to_full_cache[short_id] = full_id
        return short_id

    def get_full_keyset_id(self, short_id: str, keysets: Dict[str, Any] | None = None) -> str:
        """
        Resolve a short keyset id to the full keyset id.
        - First use in-memory cache
        - Then, if mapping not present, try to resolve from the known keysets of the currently selected mint
        - If ambiguous (multiple matches), raise
        - If not found, raise
        
        Args:
            short_id: The short keyset ID to resolve
            keysets: Optional dict of keysets (values must have .id attribute)
        """
        if short_id in self._short_to_full_cache:
            full = self._short_to_full_cache[short_id]
            logger.trace(f"Resolved short keyset id {short_id} -> {full}")
            return full

        # If caller provided a keyset listing, try resolution against it
        if keysets is not None:
            matches = [ks.id for ks in keysets.values() if ks.id.startswith(short_id)]
            if len(matches) == 1:
                full = matches[0]
                self._short_to_full_cache[short_id] = full
                self._full_to_short_cache[full] = self.get_short_keyset_id(full)
                logger.trace(f"Resolved short keyset id {short_id} -> {full}")
                return full
            elif len(matches) > 1:
                raise ValueError("Ambiguous short keyset id; use full id instead")

        raise KeyError("Unknown short keyset id; cannot resolve to full id")
