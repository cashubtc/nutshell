from typing import List, Optional

from cashu.core.db import Database
from cashu.mint.crud import LedgerCrudSqlite

from ...core.models import BlindedMessage, BlindedSignature
from ...core.settings import settings
from ..ledger import Ledger


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

    def verify_auth(self, auth: str) -> bool:
        return True

    async def auth_mint(
        self,
        *,
        outputs: List[BlindedMessage],
        auth: str,
    ) -> List[BlindedSignature]:
        # check auth
        if not self.verify_auth(auth):
            raise Exception("Invalid auth.")
        if len(outputs) > settings.auth_blind_max_tokens_mint:
            raise Exception(
                f"Too many outputs. You can only mint {settings.auth_blind_max_tokens_mint} tokens."
            )
        await self._verify_outputs(outputs)
        promises = await self._generate_promises(outputs)
        return promises
