import datetime
from typing import List, Optional

import jwt
from loguru import logger

from ...core.base import TokenV4
from ...core.db import Database
from ...core.models import BlindedMessage, BlindedSignature
from ...core.settings import settings
from ..crud import LedgerCrudSqlite
from ..ledger import Ledger
from .base import User
from .crud import AuthLedgerCrud, AuthLedgerCrudSqlite


class AuthLedger(Ledger):
    auth_crud: AuthLedgerCrud

    def __init__(
        self,
        db: Database,
        seed: str,
        seed_decryption_key: Optional[str] = None,
        derivation_path="",
        amounts: Optional[List[int]] = None,
        crud=LedgerCrudSqlite(),
    ):
        super().__init__(
            db=db,
            seed=seed,
            backends=None,
            seed_decryption_key=seed_decryption_key,
            derivation_path=derivation_path,
            crud=crud,
            amounts=amounts,
        )

        self.auth_crud = AuthLedgerCrudSqlite()

    async def verify_auth(self, auth_token_str: str) -> User:
        """Verify the clear-auth JWT token and return the user.

        Checks:
            - Token not expired.
            - Token signature valid.
            - User exists.

        Args:
            auth_token (str): _description_

        Returns:
            User: _description_
        """
        secret = "your_secret_key"
        try:
            decoded = jwt.decode(
                auth_token_str, secret, algorithms=["HS256"], verify=True
            )
            logger.trace(f"Decoded JWT: {decoded}")
        except jwt.ExpiredSignatureError as e:
            logger.error("Token has expired")
            raise e
        except jwt.InvalidSignatureError as e:
            logger.error("Invalid signature")
            raise e
        except jwt.InvalidTokenError as e:
            logger.error("Invalid token")
            raise e
        except Exception as e:
            raise e
        # TEMP: For testing purposes only.
        user_id = decoded["user_id"]

        # blind_auth_token = clear_auth_token["auth"]
        # if blind_auth_token == "new_auth_token":
        #     print("New auth token.")
        #     user = User(id=user_id)
        #     await self.auth_crud.create_user(user=user, db=self.db)
        # else:
        user = await self.auth_crud.get_user(user_id=user_id, db=self.db)
        if not user:
            logger.info(f"Creating new user: {user_id}")
            user = User(id=user_id)
            await self.auth_crud.create_user(user=user, db=self.db)

        # rate limit
        auth_rate_limit_seconds = 10
        if (
            user.last_access
            and user.last_access
            > datetime.datetime.now()
            - datetime.timedelta(seconds=auth_rate_limit_seconds)
        ):
            raise Exception("Rate limit exceeded.")

        # await self.melt_blind_auth_token(blind_auth_token)

        return user

    async def auth_mint(
        self,
        *,
        outputs: List[BlindedMessage],
        auth_token: str,
    ) -> List[BlindedSignature]:
        """Mints auth tokens. Returns a list of promises.

        Args:
            outputs (List[BlindedMessage]): Outputs to sign.
            auth_token (str): Clear-auth token.

        Raises:
            Exception: Invalid auth.
            Exception: Output verification failed.
            Exception: Output quota exceeded.

        Returns:
            List[BlindedSignature]: _description_
        """

        if len(outputs) > settings.auth_blind_max_tokens_mint:
            raise Exception(
                f"Too many outputs. You can only mint {settings.auth_blind_max_tokens_mint} tokens."
            )

        try:
            user = await self.verify_auth(auth_token)
        except Exception as e:
            raise e

        await self._verify_outputs(outputs)
        promises = await self._generate_promises(outputs)

        # update last_access timestamp of the user
        await self.auth_crud.update_user(user_id=user.id, db=self.db)

        return promises

    async def blind_auth_melt(self, *, blind_auth_token) -> None:
        """Melts the proofs of a blind auth token. Returns if successful, raises an exception otherwise.

        Args:
            proofs (List[Proof]): Proofs to melt (must be a list of length 1).

        Raises:
            Exception: Proof already spent or pending.
        """
        logger.trace("Blind auth token:", blind_auth_token)
        proofs = TokenV4.deserialize(blind_auth_token).proofs
        if len(proofs) != 1:
            raise Exception("Need exactly one blind auth proof.")
        await self.db_write._verify_spent_proofs_and_set_pending(proofs)
        await self._invalidate_proofs(proofs=proofs)
        await self.db_write._unset_proofs_pending(proofs)
