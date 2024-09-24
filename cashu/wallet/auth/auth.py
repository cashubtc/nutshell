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
    def __init__(
        self, url: str, db: str, name: str = "auth", unit: str = "auth", **kwargs
    ):
        super().__init__(url, db, name, unit)

    def _get_jwt(self) -> str:
        token_url = (
            "http://localhost:8080/realms/nutshell/protocol/openid-connect/token"
        )
        data = {
            "grant_type": "password",
            "client_id": "cashu-client",
            "username": "asd@asd.com",
            "password": "asdasd",
        }
        response = httpx.post(token_url, data=data)
        if response.status_code == 200:
            token_info: dict = response.json()
            access_token = token_info["access_token"]
            print("Access Tokens:", access_token)
        else:
            print("Failed to obtain token:", response.status_code, response.text)
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
        amounts = settings.mint_auth_blind_max_tokens_mint * [1]
        secrets = [hashlib.sha256(os.urandom(32)).hexdigest() for _ in amounts]
        rs = [PrivateKey(privkey=os.urandom(32), raw=True) for _ in amounts]
        derivation_paths = ["" for _ in amounts]
        outputs, rs = self._construct_outputs(amounts, secrets, rs)

        promises = await self.blind_auth_mint(clear_auth_token, outputs)

        new_proofs = await self._construct_proofs(
            promises, secrets, rs, derivation_paths
        )
        return new_proofs
