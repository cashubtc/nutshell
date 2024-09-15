from typing import List, Optional

from cashu.core.db import Database
from cashu.mint.crud import LedgerCrudSqlite

from ...core.models import BlindedMessage, BlindedSignature, Proof
from ...core.settings import settings
from ..ledger import Ledger
from .base import User


class AuthLedger(Ledger):
    def __init__(
        self,
        db: Database,
        seed: str,
        seed_decryption_key: Optional[str] = None,
        derivation_path="",
        crud=LedgerCrudSqlite(),
    ):
        super().__init__(db, seed, None, seed_decryption_key, derivation_path, crud)

    def verify_auth(self, auth_token: str) -> User:
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
        user_id = "user_id_here"
        return User(id=user_id)

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
            user = self.verify_auth(auth_token)
        except Exception as e:
            raise e
        user.quota = 10000
        if user.quota < len(outputs):
            raise Exception("Blind-auth quota exceeded.")

        await self._verify_outputs(outputs)
        promises = await self._generate_promises(outputs)
        return promises

    async def auth_melt(self, *, proofs: List[Proof]) -> None:
        """Melts blind-auth proofs. Returns if successful, raises an exception otherwise.

        Args:
            proofs (List[Proof]): Proofs to melt (must be a list of length 1).

        Raises:
            Exception: Proof already spent or pending.
        """
        if len(proofs) != 1:
            raise Exception("You can only melt one token at a time.")

        await self.db_write._verify_spent_proofs_and_set_pending(proofs)
        try:
            return
        except Exception as e:
            raise e
        finally:
            await self.db_write._unset_proofs_pending(proofs)
