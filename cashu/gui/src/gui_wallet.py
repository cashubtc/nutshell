from cashu.core.helpers import sum_proofs
from cashu.core.migrations import migrate_databases
from cashu.wallet import migrations
from cashu.wallet.wallet import Wallet


class GuiWallet(Wallet):
    _balance: float
    _available: float

    def __init__(self, url: str, db: str, name: str = "no_name"):
        super().__init__(url, db, name)

    @property
    def balance(self):
        return self._balance

    @property
    def available(self):
        return self._available

    async def init(self):
        await migrate_databases(self.db, migrations)
        await self.load_proofs()
        try:
            self._balance = sum_proofs(self.proofs)
            self._available = sum_proofs([p for p in self.proofs if not p.reserved])
        except Exception as e:
            print(e)
