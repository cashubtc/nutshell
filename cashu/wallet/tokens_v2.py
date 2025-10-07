from typing import Dict, List

from cashu.core.base import Proof, TokenV4, TokenV4Token, TokenV4Proof, TokenV4DLEQ
from cashu.core.crypto.keys import derive_keyset_short_id, is_keyset_id_v2
from .keyset_manager import KeysetManager


# DEPRECATED: This helper is no longer used. Short keyset ID handling has been
# integrated into the wallet's TokenV4 creation path (see WalletProofs._make_tokenv4).
# The class remains temporarily to avoid import errors during transition. It will be
# removed in a subsequent cleanup once callers are updated.
class WalletTokensV2:  # pragma: no cover
    """
    Deprecated wallet-side utilities to handle short keyset IDs in tokens.
    Use WalletProofs._make_token/_make_tokenv4 instead.
    """

    def __init__(self):
        self.keyset_manager = KeysetManager()
        self._short_to_full_cache = self.keyset_manager._short_to_full_cache
        self._full_to_short_cache = self.keyset_manager._full_to_short_cache

    async def expand_token_keysets(self, token: TokenV4, keysets_index: Dict[str, str] | None = None) -> TokenV4:
        # Kept for backward compatibility; forwards to KeysetManager
        ks_map: Dict[str, str] = {}
        if keysets_index:
            ks_map = {fid: fid for fid in keysets_index.keys()}

        new_tokens: List[TokenV4Token] = []
        for t in token.t:
            keyset_hex = t.i.hex()
            if len(keyset_hex) == 16 and keyset_hex.startswith("01"):
                full_id = await self.keyset_manager.get_full_keyset_id(
                    keyset_hex,
                    keysets={fid: type("K", (), {"id": fid}) for fid in ks_map} if ks_map else None,
                )
                new_tokens.append(TokenV4Token(i=bytes.fromhex(full_id), p=t.p))
            else:
                new_tokens.append(t)
        return TokenV4(m=token.m, u=token.u, t=new_tokens, d=token.d)

    async def _make_tokenv4_with_short_ids(self, proofs: List[Proof]) -> TokenV4:
        # Deprecated shim; real implementation lives in WalletProofs._make_tokenv4
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
        return TokenV4(m="", u="sat", t=tokens, d=None)
