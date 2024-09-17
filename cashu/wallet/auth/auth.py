# from ..v1_api import LedgerAPI
import datetime
import hashlib
import os

import jwt
from loguru import logger

from ...core.base import Amount
from ...core.crypto.secp import PrivateKey
from ...core.helpers import sum_proofs
from ...core.settings import settings
from ..errors import BalanceTooLowError
from ..wallet import Wallet


class WalletAuth(Wallet):
    def __init__(self, url: str, db: str, name: str = "auth", unit: str = "auth"):
        super().__init__(url, db, name, unit)

    def _create_jwt(self, user_id: str) -> str:
        payload = {
            "user_id": user_id,
            "exp": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(hours=1),
        }

        secret = "your_secret_key"

        # Encode and sign the JWT
        token = jwt.encode(payload, secret, algorithm="HS256")
        return token

    async def spend_auth_token(self) -> str:
        try:
            auth_proofs, _ = await self.select_to_send(self.proofs, 1, offline=True)
        except BalanceTooLowError:
            logger.debug("Balance too low. Requesting new blind auth tokens.")
            await self.mint_blind_auth_proofs()
            auth_proofs, _ = await self.select_to_send(self.proofs, 1, offline=True)
        blind_auth_token = await self.serialize_proofs(auth_proofs)
        await self.invalidate(auth_proofs)
        return blind_auth_token

    async def mint_blind_auth_proofs(self) -> None:
        # # TODO: For development
        # clear_auth_token_dict: dict = {
        #     "user_id": "user_id_here",
        #     "auth": "new_auth_token",
        # }
        # auth_proofs: List[Proof] = []
        # try:
        #     auth_proofs, _ = await self.select_to_send(self.proofs, 1)
        #     blind_auth_token = await self.serialize_proofs(auth_proofs)
        #     clear_auth_token_dict["auth"] = blind_auth_token
        # except BalanceTooLowError as e:
        #     logger.error(f"Error getting auth token: {e}")
        #     # new user
        #     clear_auth_token_dict["user_id"] = hashlib.sha256(
        #         os.urandom(32)
        #     ).hexdigest()
        #     clear_auth_token_dict["auth"] = "new_auth_token"

        clear_auth_token = self._create_jwt("user_id_here")
        amounts = settings.auth_blind_max_tokens_mint * [1]
        secrets = [hashlib.sha256(os.urandom(32)).hexdigest() for _ in amounts]
        rs = [PrivateKey(privkey=os.urandom(32), raw=True) for _ in amounts]
        derivation_paths = ["" for _ in amounts]
        outputs, rs = self._construct_outputs(amounts, secrets, rs)

        promises = await self.blind_auth_mint(clear_auth_token, outputs)

        new_proofs = await self._construct_proofs(
            promises, secrets, rs, derivation_paths
        )
        print(f"Minted {Amount(self.unit, sum_proofs(new_proofs))} blind auth proofs.")
        # if auth_proofs:
        #     await self.invalidate(auth_proofs)

        # print(new_proofs)
        print(f"Balance: {Amount(self.unit, self.available_balance)}")

        blind_auth = await self.spend_auth_token()
        print(f"Blind auth: {blind_auth}")
