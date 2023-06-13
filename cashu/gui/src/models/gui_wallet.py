from cashu.core.helpers import sum_proofs
from cashu.core.migrations import migrate_databases
from cashu.gui.src.mint_repository import MintRepository
from cashu.gui.src.models.gui_mint_balance import GuiMintBalance
from cashu.wallet import migrations
from cashu.wallet.wallet import Wallet


class GuiWallet(Wallet):
    _balance: float
    _available: float
    _balance_per_mint: list[GuiMintBalance]

    def __init__(self, url: str, db: str, name: str = "no_name"):
        super().__init__(url, db, name)

    @property
    def balance(self):
        return self._balance

    @property
    def available(self):
        return self._available

    @property
    def balance_per_mint(self) -> list[GuiMintBalance]:
        return self._balance_per_mint

    async def init(self):
        await migrate_databases(self.db, migrations)
        await self.load_proofs()
        try:
            self._balance = sum_proofs(self.proofs)
            self._available = sum_proofs([p for p in self.proofs if not p.reserved])

            all_data = await self.balance_per_minturl()
            repo = MintRepository()
            self._balance_per_mint = []

            for url in all_data.keys():
                data_for_mint = all_data[url]
                if "127.0.0.1" in url:
                    url = url.replace("127.0.0.1", "localhost")

                mint_name = repo.get_mint_per_url(url).name
                self._balance_per_mint.append(
                    GuiMintBalance(
                        mint_name,
                        data_for_mint["balance"],
                        data_for_mint["available"],
                        100 / self.balance * data_for_mint["balance"],
                    )
                )

        except Exception as e:
            print(e)
