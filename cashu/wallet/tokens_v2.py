from typing import Dict, List

from cashu.core.base import Proof, TokenV4, TokenV4Token, TokenV4Proof, TokenV4DLEQ
from cashu.core.crypto.keys import derive_keyset_short_id, is_keyset_id_v2
from .keyset_manager import KeysetManager


class WalletTokensV2:
    """
    Wallet-side utilities to handle short keyset IDs in tokens.
    - The mint remains unaware of s_id; wallet expands to full IDs before processing.
    """

    def __init__(self):
        self.keyset_manager = KeysetManager()
        # Optional external caches for tests
        self._short_to_full_cache = self.keyset_manager._short_to_full_cache
        self._full_to_short_cache = self.keyset_manager._full_to_short_cache
        # Current mint keyset listing cache (optional, injectable by wallet)
        self._mint_keysets: Dict[str, str] | None = None

    async def expand_token_keysets(self, token: TokenV4, keysets_index: Dict[str, str] | None = None) -> TokenV4:
        """
        Expand short keyset IDs in a TokenV4 to full IDs using keyset manager.
        keysets_index: optional mapping from full_id -> unit (or any payload). Only prefixes are used for resolution.
        """
        # Build a minimal structure of known full IDs for prefix resolution
        ks_map: Dict[str, str] = {}
        if keysets_index:
            ks_map = {fid: fid for fid in keysets_index.keys()}

        new_tokens: List[TokenV4Token] = []
        for t in token.t:
            keyset_bytes = t.i
            keyset_hex = keyset_bytes.hex()
            if len(keyset_hex) == 16 and keyset_hex.startswith("01"):
                # Likely a short v2 id; resolve (cache-first; keysets(optional) if provided)
                full_id = await self.keyset_manager.get_full_keyset_id(
                    keyset_hex,
                    keysets={fid: type("K", (), {"id": fid}) for fid in ks_map} if ks_map else None,
                )
                new_tokens.append(TokenV4Token(i=bytes.fromhex(full_id), p=t.p))
            else:
                # Already full id
                new_tokens.append(t)
        return TokenV4(m=token.m, u=token.u, t=new_tokens, d=token.d)

    async def _make_tokenv4_with_short_ids(self, proofs: List[Proof]) -> TokenV4:
        """
        Build a TokenV4 from proofs, using short keyset IDs for v2 keysets (space savings).
        - v1 proofs keep full id
        - v2 proofs: replace full id with 8-byte short id
        """
        # Group proofs by keyset id
        by_id: Dict[str, List[Proof]] = {}
        for p in proofs:
            by_id.setdefault(p.id, []).append(p)

        tokens: List[TokenV4Token] = []
        for full_id, group in by_id.items():
            keyset_hex = full_id
            if is_keyset_id_v2(full_id):
                short_id = await self.keyset_manager.get_short_keyset_id(full_id)
                keyset_hex = short_id
            tokens.append(
                TokenV4Token(
                    i=bytes.fromhex(keyset_hex),
                    p=[
                        TokenV4Proof(
                            a=g.amount,
                            s=g.secret,
                            c=bytes.fromhex(g.C),
                            d=(
                                TokenV4DLEQ(
                                    e=bytes.fromhex(g.dleq.e),
                                    s=bytes.fromhex(g.dleq.s),
                                    r=bytes.fromhex(g.dleq.r),
                                )
                                if g.dleq
                                else None
                            ),
                            w=g.witness,
                        )
                        for g in group
                    ],
                )
            )
        # Build TokenV4, minimal fields
        mint_url = ""
        unit = "sat"
        return TokenV4(m=mint_url, u=unit, t=tokens, d=None)
