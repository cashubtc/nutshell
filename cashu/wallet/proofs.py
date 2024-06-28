from itertools import groupby
from typing import Dict, List, Optional

from loguru import logger

from ..core.base import (
    Proof,
    TokenV3,
    TokenV3Token,
    TokenV4,
    TokenV4Proof,
    TokenV4Token,
    Unit,
    WalletKeyset,
)
from ..core.db import Database
from ..wallet.crud import (
    get_keysets,
)
from .protocols import SupportsDb, SupportsKeysets


class WalletProofs(SupportsDb, SupportsKeysets):
    keyset_id: str
    db: Database

    @staticmethod
    def _get_proofs_per_keyset(proofs: List[Proof]):
        return {
            key: list(group) for key, group in groupby(proofs, lambda p: p.id) if key
        }

    async def _get_proofs_per_minturl(
        self, proofs: List[Proof], unit: Optional[Unit] = None
    ) -> Dict[str, List[Proof]]:
        ret: Dict[str, List[Proof]] = {}
        keyset_ids = set([p.id for p in proofs])
        for id in keyset_ids:
            if id is None:
                continue
            keysets_crud = await get_keysets(id=id, db=self.db)
            assert keysets_crud, f"keyset {id} not found"
            keyset: WalletKeyset = keysets_crud[0]
            if unit and keyset.unit != unit:
                continue
            assert keyset.mint_url
            if keyset.mint_url not in ret:
                ret[keyset.mint_url] = [p for p in proofs if p.id == id]
            else:
                ret[keyset.mint_url].extend([p for p in proofs if p.id == id])
        return ret

    def _get_proofs_per_unit(self, proofs: List[Proof]) -> Dict[Unit, List[Proof]]:
        ret: Dict[Unit, List[Proof]] = {}
        for proof in proofs:
            if proof.id not in self.keysets:
                logger.error(f"Keyset {proof.id} not found in wallet.")
                continue
            unit = self.keysets[proof.id].unit
            if unit not in ret:
                ret[unit] = [proof]
            else:
                ret[unit].append(proof)
        return ret

    def _get_proofs_keysets(self, proofs: List[Proof]) -> List[str]:
        """Extracts all keyset ids from a list of proofs.

        Args:
            proofs (List[Proof]): List of proofs to get the keyset id's of
        """
        keysets: List[str] = [proof.id for proof in proofs]
        return keysets

    async def _get_keyset_urls(self, keysets: List[str]) -> Dict[str, List[str]]:
        """Retrieves the mint URLs for a list of keyset id's from the wallet's database.
        Returns a dictionary from URL to keyset ID

        Args:
            keysets (List[str]): List of keysets.
        """
        mint_urls: Dict[str, List[str]] = {}
        for ks in set(keysets):
            keysets_db = await get_keysets(id=ks, db=self.db)
            keyset_db = keysets_db[0] if keysets_db else None
            if keyset_db and keyset_db.mint_url:
                mint_urls[keyset_db.mint_url] = (
                    mint_urls[keyset_db.mint_url] + [ks]
                    if mint_urls.get(keyset_db.mint_url)
                    else [ks]
                )
        return mint_urls

    async def serialize_proofs(
        self,
        proofs: List[Proof],
        include_mints=True,
        include_dleq=False,
        legacy=False,
        memo: Optional[str] = None,
    ) -> str:
        """Produces sharable token with proofs and mint information.

        Args:
            proofs (List[Proof]): List of proofs to be included in the token
            include_mints (bool, optional): Whether to include the mint URLs in the token. Defaults to True.
            legacy (bool, optional): Whether to produce a legacy V3 token. Defaults to False.

        Returns:
            str: Serialized Cashu token
        """

        tokenv3 = await self._make_tokenv3(proofs, include_mints, memo)
        if legacy:
            return tokenv3.serialize(include_dleq)
        else:
            tokenv4 = await self._make_token(proofs, include_dleq, memo)
            return tokenv4.serialize(include_dleq)

    async def _make_tokenv3(
        self, proofs: List[Proof], include_mints=True, memo: Optional[str] = None
    ) -> TokenV3:
        """
        Takes list of proofs and produces a TokenV3 by looking up
        the mint URLs by the keyset id from the database.

        Args:
            proofs (List[Proof]): List of proofs to be included in the token
            include_mints (bool, optional): Whether to include the mint URLs in the token. Defaults to True.

        Returns:
            TokenV3: TokenV3 object
        """
        token = TokenV3()

        if include_mints:
            # we create a map from mint url to keyset id and then group
            # all proofs with their mint url to build a tokenv3

            # extract all keysets from proofs
            keysets = self._get_proofs_keysets(proofs)
            # get all mint URLs for all unique keysets from db
            mint_urls = await self._get_keyset_urls(keysets)

            # append all url-grouped proofs to token
            for url, ids in mint_urls.items():
                mint_proofs = [p for p in proofs if p.id in ids]
                token.token.append(TokenV3Token(mint=url, proofs=mint_proofs))
        else:
            token_proofs = TokenV3Token(proofs=proofs)
            token.token.append(token_proofs)

        if memo:
            token.memo = memo
        return token

    async def _make_tokenv4(
        self, proofs: List[Proof], include_dleq=False, memo: Optional[str] = None
    ) -> TokenV4:
        """
        Takes a list of proofs and returns a TokenV4

        Args:
            proofs (List[Proof]): List of proofs to be serialized

        Returns:
            TokenV4: TokenV4 object
        """

        # get all keysets from proofs
        keysets = self._get_proofs_keysets(proofs)
        # get all mint URLs for all unique keysets from db
        mint_urls = await self._get_keyset_urls(keysets)
        if len(mint_urls) > 1:
            raise ValueError("TokenV4 can only contain proofs from a single mint URL")
        mint_url = list(mint_urls.keys())[0]

        tokens: List[TokenV4Token] = []
        for keyset in keysets:
            proofs_keyset = [p for p in proofs if p.id == keyset]
            tokenv4_proofs = []
            for proof in proofs_keyset:
                tokenv4_proofs.append(TokenV4Proof.from_proof(proof, include_dleq))
            tokenv4_token = TokenV4Token(i=bytes.fromhex(keyset), p=tokenv4_proofs)
            tokens.append(tokenv4_token)

        return TokenV4(m=mint_url, t=tokens, d=memo)

    async def _make_token(
        self, proofs: List[Proof], include_dleq=False, memo: Optional[str] = None
    ) -> TokenV4:
        """
        Takes a list of proofs and returns a TokenV4

        Args:
            proofs (List[Proof]): List of proofs to be serialized

        Returns:
            TokenV4: TokenV4 object
        """

        return await self._make_tokenv4(proofs, include_dleq, memo)
