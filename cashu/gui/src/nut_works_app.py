import flet as f

from cashu.gui.src.controls.overview_card import OverviewCard
from cashu.gui.src.mint_repository import MintRepository
from cashu.gui.src.wallet_repository import WalletRepository


class NutWorksApp:
    _selected_wallet: str
    _selected_mint: str

    def __init__(self, page: f.Page):
        self.page = page
        self.mint_repo = MintRepository()
        self.wallet_repo = WalletRepository()

    async def init(self):
        await self.wallet_repo.init(self.mint_repo.default_mint)

        self.appbar = self._build_app_bar()
        self.page.appbar = self.appbar

        self.page.vertical_alignment = f.CrossAxisAlignment.START
        await self._update_page()

        await self.page.update_async()

    async def _update_page(self):
        await self.page.clean_async()
        await self.page.add_async(
            f.Column(
                alignment=f.MainAxisAlignment.END,
                controls=[
                    OverviewCard(self.wallet_repo.wallet),
                ],
            ),
        )

        await self.page.update_async()

    def _build_app_bar(self, title: str = "NutWorks"):
        async def on_wallet_changed(e: f.ControlEvent):
            try:
                if self.wallet_repo.wallet.name == e.data:
                    return

                await self.wallet_repo.set_wallet(e.data)
                self._selected_wallet = e.data
                await self._update_page()
            except NotImplementedError:
                pass

        async def on_mint_changed(e: f.ControlEvent):
            try:
                if self.wallet_repo.mint.name == e.data:
                    return

                await self.wallet_repo.set_mint(e.data)
                self._selected_mint = e.data
                await self._update_page()
            except NotImplementedError:
                pass

        wallet_dd = f.Dropdown(
            content_padding=f.padding.symmetric(vertical=16, horizontal=8),
            width=120,
            label="Wallet",
            value=self.wallet_repo.wallet.name,
            options=[f.dropdown.Option(w) for w in self.wallet_repo.get_wallets()],
            on_change=on_wallet_changed,
        )

        mint_dd = f.Dropdown(
            content_padding=f.padding.symmetric(vertical=16, horizontal=8),
            width=120,
            label="Mint",
            value=self.wallet_repo.mint.name,
            options=[f.dropdown.Option(mint.name) for mint in self.mint_repo.mint_list],
            on_change=on_mint_changed,
        )

        return f.AppBar(
            leading=f.Icon(f.icons.WALLET_MEMBERSHIP),
            leading_width=100,
            title=f.Text(title, size=32, text_align="start"),
            center_title=False,
            toolbar_height=75,
            actions=[
                f.Container(content=wallet_dd, margin=f.margin.only(right=8)),
                f.Container(content=mint_dd, margin=f.margin.only(right=8)),
            ],
        )
