from os import listdir, path
from typing import Union

from genericpath import isdir

from cashu.core.base import Proof
from cashu.core.settings import settings
from cashu.gui.src.mint_repository import MintRepository
from cashu.gui.src.models.gui_mint import GuiMint
from cashu.gui.src.models.gui_wallet import GuiWallet

DEFAULT_WALLET_NAME = "wallet"


class WalletRepository:
    _instance = None
    _current_wallet: GuiWallet
    _current_mint: GuiMint
    _wallet_names: list[str] = []

    def __new__(cls, *args, **kwargs):
        if not isinstance(cls._instance, cls):
            cls._instance = super(WalletRepository, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    @property
    def mint(self) -> GuiMint:
        return self._current_mint

    @property
    def wallet(self) -> GuiWallet:
        return self._current_wallet

    async def init(self, mint: GuiMint):
        self._current_mint = mint

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
            self._wallet_names.append(dir)
            if dir == DEFAULT_WALLET_NAME:
                wallet = GuiWallet(
                    self._current_mint.url, path.join(settings.cashu_dir, dir), dir
                )
                await wallet.init()
                await wallet.load_mint()
                self._current_wallet = wallet

    async def _recreate_wallet(self, wallet_name, mint_name):
        if self._current_mint.name == mint_name and self.wallet.name == wallet_name:
            return

        print(f"recreate_wallet({wallet_name}, {mint_name})")
        self._current_mint = MintRepository().get_mint_per_name(mint_name)
        self._current_wallet = GuiWallet(
            self._current_mint.url,
            path.join(settings.cashu_dir, wallet_name),
            wallet_name,
        )
        await self._current_wallet.init()
        await self._current_wallet.load_mint()

    async def set_wallet(self, wallet_name: str):
        if self._current_wallet.name == wallet_name:
            return

        await self._recreate_wallet(wallet_name, self._current_mint)

    async def set_mint(self, mint_name: str):
        if self._current_mint.name == mint_name:
            return

        await self._recreate_wallet(self._current_wallet.name, mint_name)

    async def gen_invoice(self, amount: int) -> str:
        if amount == None or amount < 0:
            raise Exception("Amount must be greater than 0")

        try:
            invoice = await self._current_wallet.request_mint(amount)
            if invoice.pr:
                return invoice.pr
        except:
            raise

    async def mint_tokens_by_invoice_hash(
        self,
        amount: int,
        hash: Union[None, str] = None,
    ) -> list[Proof]:
        wallet = wallet if wallet != None else self._current_wallet

        if amount and hash:
            return await wallet.mint(amount, hash)

    def get_wallets(self) -> list[str]:
        return self._wallet_names
