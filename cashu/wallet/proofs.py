from itertools import groupby
from typing import Dict, List, Optional, Tuple

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
        keyset_ids = {p.id for p in proofs}
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

    def _get_proofs_keyset_ids(self, proofs: List[Proof]) -> List[str]:
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

    async def _get_proofs_keysets(self, proofs: List[Proof]) -> Dict[str, WalletKeyset]:
        keyset_ids = self._get_proofs_keyset_ids(proofs)
        keysets_dict = {}
        async with self.db.get_connection() as conn:
            for keyset_id in keyset_ids:
                keyset = await get_keysets(id=keyset_id, db=self.db, conn=conn)
                if len(keyset) == 1:
                    keysets_dict[keyset_id] = keyset[0]
        return keysets_dict

    async def _get_proofs_mint_unit(self, proofs: List[Proof]) -> Tuple[str, Unit]:
        """Helper function that extracts the mint URL and unit from a list of proofs. It raises an exception if the proofs are from multiple mints or units.

        Args:
            proofs (List[Proof]): List of proofs to extract the mint URL and unit from.

        Raises:
            Exception: If the proofs are from multiple mints or units.
            Exception: If the proofs are from an unknown mint or keyset.

        Returns:
            Tuple[str, Unit]: Mint URL and `Unit` of the proofs
        """
        proofs_keysets = await self._get_proofs_keysets(proofs)
        mint_urls = [k.mint_url for k in proofs_keysets.values()]
        if not mint_urls:
            raise Exception("Proofs from unknown mint or keyset.")
        if len(set(mint_urls)) != 1:
            raise Exception("Proofs from multiple mints.")
        mint_url = mint_urls[0]
        if not mint_url:
            raise Exception("No mint URL found for keyset")
        proofs_units = [k.unit for k in proofs_keysets.values()]
        if len(set(proofs_units)) != 1:
            raise Exception("Proofs from multiple units.")
        unit = proofs_units[0]
        return mint_url, unit

    async def serialize_proofs(
        self,
        proofs: List[Proof],
        include_dleq=False,
        legacy=False,
        memo: Optional[str] = None,
    ) -> str:
        """Produces sharable token with proofs and mint information.

        Args:
            proofs (List[Proof]): List of proofs to be included in the token
            legacy (bool, optional): Whether to produce a legacy V3 token. Defaults to False.
        Returns:
            str: Serialized Cashu token
        """
        # DEPRECATED: legacy token for base64 keysets
        try:
            _ = [bytes.fromhex(p.id) for p in proofs]
        except ValueError:
            logger.debug("Proof with base64 keyset, using legacy token serialization")
            legacy = True

        if legacy:
            tokenv3 = await self._make_tokenv3(proofs, memo)
            return tokenv3.serialize(include_dleq)
        else:
            tokenv4 = await self._make_token(proofs, include_dleq, memo)
            return tokenv4.serialize(include_dleq)

    async def _make_tokenv3(
        self, proofs: List[Proof], memo: Optional[str] = None
    ) -> TokenV3:
        """
        Takes list of proofs and produces a TokenV3 by looking up
        the mint URLs by the keyset id from the database.

        Args:
            proofs (List[Proof]): List of proofs to be included in the token
            memo (Optional[str], optional): Memo to be included in the token. Defaults to None.
        Returns:
            TokenV3: TokenV3 object
        """

        # extract all keysets IDs from proofs
        keyset_ids = self._get_proofs_keyset_ids(proofs)
        keysets = {k.id: k for k in self.keysets.values() if k.id in keyset_ids}
        if not keysets:
            raise ValueError("No keysets found for proofs")
        assert (
            len({k.unit for k in keysets.values()}) == 1
        ), "All keysets must have the same unit"
        unit = keysets[list(keysets.keys())[0]].unit

        token = TokenV3()
        token.memo = memo
        token.unit = unit.name
        assert token.memo == memo, f"Memo not set correctly: {token.memo}"
        # get all mint URLs for all unique keysets from db
        mint_urls = await self._get_keyset_urls(list(keysets.keys()))

        # append all url-grouped proofs to token
        for url, ids in mint_urls.items():
            mint_proofs = [p for p in proofs if p.id in ids]
            token.token.append(TokenV3Token(mint=url, proofs=mint_proofs))

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
        keyset_ids = set(self._get_proofs_keyset_ids(proofs))
        try:
            keysets = [self.keysets[i] for i in keyset_ids]
        except KeyError:
            raise ValueError("Keysets of proofs are not loaded in wallet")
        # we make sure that all proofs are from keysets of the same mint
        if len({k.mint_url for k in keysets}) > 1:
            raise ValueError("TokenV4 can only contain proofs from a single mint URL")
        mint_url = keysets[0].mint_url
        if not mint_url:
            raise ValueError("No mint URL found for keyset")

        # we make sure that all keysets have the same unit
        if len({k.unit for k in keysets}) > 1:
            raise ValueError(
                "TokenV4 can only contain proofs from keysets with the same unit"
            )
        unit_str = keysets[0].unit.name

        tokens: List[TokenV4Token] = []
        for keyset_id in keyset_ids:
            proofs_keyset = [p for p in proofs if p.id == keyset_id]
            tokenv4_proofs = []
            for proof in proofs_keyset:
                tokenv4_proofs.append(TokenV4Proof.from_proof(proof, include_dleq))
            tokenv4_token = TokenV4Token(i=bytes.fromhex(keyset_id), p=tokenv4_proofs)
            tokens.append(tokenv4_token)

        return TokenV4(m=mint_url, u=unit_str, t=tokens, d=memo)

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
