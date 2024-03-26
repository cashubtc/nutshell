import base64
import json
from itertools import groupby
from typing import Dict, List, Optional

from loguru import logger

from ..core.base import (
    Proof,
    TokenV2,
    TokenV2Mint,
    TokenV3,
    TokenV3Token,
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
        keysets: List[str] = [proof.id for proof in proofs if proof.id]
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

    async def _make_token(self, proofs: List[Proof], include_mints=True) -> TokenV3:
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
        return token

    async def serialize_proofs(
        self, proofs: List[Proof], include_mints=True, include_dleq=False, legacy=False
    ) -> str:
        """Produces sharable token with proofs and mint information.

        Args:
            proofs (List[Proof]): List of proofs to be included in the token
            include_mints (bool, optional): Whether to include the mint URLs in the token. Defaults to True.
            legacy (bool, optional): Whether to produce a legacy V2 token. Defaults to False.

        Returns:
            str: Serialized Cashu token
        """

        if legacy:
            # V2 tokens
            token_v2 = await self._make_token_v2(proofs, include_mints)
            return await self._serialize_token_base64_tokenv2(token_v2)

            # # deprecated code for V1 tokens
            # proofs_serialized = [p.to_dict() for p in proofs]
            # return base64.urlsafe_b64encode(
            #     json.dumps(proofs_serialized).encode()
            # ).decode()

        # V3 tokens
        token = await self._make_token(proofs, include_mints)
        return token.serialize(include_dleq)

    async def _make_token_v2(self, proofs: List[Proof], include_mints=True) -> TokenV2:
        """
        Takes list of proofs and produces a TokenV2 by looking up
        the keyset id and mint URLs from the database.
        """
        # build token
        token = TokenV2(proofs=proofs)

        # add mint information to the token, if requested
        if include_mints:
            # dummy object to hold information about the mint
            mints: Dict[str, TokenV2Mint] = {}
            # dummy object to hold all keyset id's we need to fetch from the db later
            keysets: List[str] = [proof.id for proof in proofs if proof.id]
            # iterate through unique keyset ids
            for id in set(keysets):
                # load the keyset from the db
                keysets_db = await get_keysets(id=id, db=self.db)
                keyset_db = keysets_db[0] if keysets_db else None
                if keyset_db and keyset_db.mint_url and keyset_db.id:
                    # we group all mints according to URL
                    if keyset_db.mint_url not in mints:
                        mints[keyset_db.mint_url] = TokenV2Mint(
                            url=keyset_db.mint_url,
                            ids=[keyset_db.id],
                        )
                    else:
                        # if a mint URL has multiple keysets, append to the already existing list
                        mints[keyset_db.mint_url].ids.append(keyset_db.id)
            if len(mints) > 0:
                # add mints grouped by url to the token
                token.mints = list(mints.values())
        return token

    async def _serialize_token_base64_tokenv2(self, token: TokenV2) -> str:
        """
        Takes a TokenV2 and serializes it in urlsafe_base64.

        Args:
            token (TokenV2): TokenV2 object to be serialized

        Returns:
            str: Serialized token
        """
        # encode the token as a base64 string
        token_base64 = base64.urlsafe_b64encode(
            json.dumps(token.to_dict()).encode()
        ).decode()
        return token_base64
