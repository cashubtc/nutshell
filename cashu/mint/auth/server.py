from typing import Optional

from cashu.core.db import Database
from cashu.mint.crud import LedgerCrudSqlite

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

    async def startup_ledger(self):
        await self.init_keysets()
