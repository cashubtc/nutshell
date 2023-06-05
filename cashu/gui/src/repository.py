from os import listdir, path

from genericpath import isdir

from cashu.core.settings import settings
from cashu.gui.src.gui_wallet import GuiWallet


class CashuRepository:
    _wallets: list[GuiWallet] = []

    async def init(self):
        dirs = [
            d
            for d in listdir(settings.cashu_dir)
            if isdir(path.join(settings.cashu_dir, d))
        ]

        try:
            dirs.remove("mint")
        except ValueError:
            pass

        for dir in dirs:
            wallet = GuiWallet("localhost", path.join(settings.cashu_dir, dir), dir)
            try:
                await wallet.init()
                self._wallets.append(wallet)
            except Exception as e:
                print(e)

    def list_wallets(self) -> list[GuiWallet]:
        return self._wallets
