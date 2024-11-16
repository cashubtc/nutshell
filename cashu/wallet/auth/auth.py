# from ..v1_api import LedgerAPI
import hashlib
import os
from typing import List

import httpx
from loguru import logger

from ...core.base import Proof
from ...core.crypto.secp import PrivateKey
from ...core.settings import settings
from ..errors import BalanceTooLowError
from ..wallet import Wallet


class WalletAuth(Wallet):
    oidc_discovery_url: str
    oidc_discovery_json: dict

    def __init__(
        self, url: str, db: str, name: str = "auth", unit: str = "auth", **kwargs
    ):
        super().__init__(url, db, name, unit)

    # overload with_db
    @classmethod
    async def with_db(
        cls,
        *args,
        **kwargs,
    ):
        # set skip_db_read=True
        kwargs["skip_db_read"] = True
        return await super().with_db(*args, **kwargs)

    async def init_wallet(self):
        # quirk: load mint info from original api_prefix path first
        await self.load_mint_info(reload=True)
        if not self.mint_info.requires_clear_auth():
            raise Exception("Mint does not require clear auth.")

        # quirk: from now on we use the blind auth api_prefix for all following requests
        self.api_prefix = "/v1/auth/blind"
        await self.load_mint_keysets()
        await self.activate_keyset()
        await self.load_proofs()

        self.oidc_discovery_url = self.mint_info.oidc_discovery_url()
        self.oidc_discovery_json = await self._get_oicd_discovery_json()
        self.oidc_token_endpoint = self.oidc_discovery_json["token_endpoint"]

    async def _get_oicd_discovery_json(self) -> dict:
        response = httpx.get(self.oidc_discovery_url)
        response.raise_for_status()
        return response.json()

    def _get_jwt(self) -> str:
        data = {
            "grant_type": "password",
            "client_id": "cashu-client",
            "username": "asd@asd.com",
            "password": "asdasd",
        }
        response = httpx.post(self.oidc_token_endpoint, data=data)
        if response.status_code == 200:
            token_info: dict = response.json()
            access_token = token_info["access_token"]
        else:
            logger.error(f"Failed to obtain token: {response.text}")
        response.raise_for_status()
        return access_token

    async def spend_auth_token(self) -> str:
        try:
            auth_proofs, _ = await self.select_to_send(self.proofs, 1, offline=True)
        except BalanceTooLowError:
            logger.debug("Balance too low. Requesting new blind auth tokens.")
            await self.mint_blind_auth_proofs()
            auth_proofs, _ = await self.select_to_send(self.proofs, 1, offline=True)
        except Exception as e:
            raise e
        blind_auth_token = await self.serialize_proofs(auth_proofs)
        await self.invalidate(auth_proofs)
        return blind_auth_token

    async def mint_blind_auth_proofs(self) -> List[Proof]:
        clear_auth_token = self._get_jwt()
        amounts = settings.mint_auth_max_blind_tokens * [1]
        secrets = [hashlib.sha256(os.urandom(32)).hexdigest() for _ in amounts]
        rs = [PrivateKey(privkey=os.urandom(32), raw=True) for _ in amounts]
        derivation_paths = ["" for _ in amounts]
        outputs, rs = self._construct_outputs(amounts, secrets, rs)

        promises = await self.blind_mint_blind_auth(clear_auth_token, outputs)

        new_proofs = await self._construct_proofs(
            promises, secrets, rs, derivation_paths
        )
        return new_proofs
