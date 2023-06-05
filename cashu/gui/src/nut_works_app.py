import flet as f

from cashu.gui.src.repository import CashuRepository, GuiWallet


class NutWorksApp:
    current_page = "0"

    def __init__(self, page: f.Page):
        self.page = page
        self.repo = CashuRepository()

    async def init(self):
        await self.repo.init()

        self.nw_pages = {
            "0": [self._build_app_bar(), f.Text("Balances go here")],
            "1": [self._build_app_bar(), f.Text("Sending goes here")],
            "2": [self._build_app_bar(), f.Text("Receiving goes here")],
        }

        self.appbar = self._build_app_bar()
        self.page.navigation_bar = self._build_nav_bar()
        self.page.appbar = self.appbar
        await self.page.add_async(*self.nw_pages[self.current_page])
        await self.page.update_async()

    def _build_app_bar(self, title: str = "NutWorks"):
        def on_wallet_changed(e):
            try:
                self.page.update()
            except NotImplementedError as e:
                pass

        dd = f.Dropdown(
            content_padding=f.padding.all(16),
            width=100,
            label="Wallet",
            options=[f.dropdown.Option(w.name) for w in self.repo.list_wallets()],
            on_change=on_wallet_changed,
        )

        return f.AppBar(
            leading=f.Icon(f.icons.WALLET_MEMBERSHIP),
            leading_width=100,
            title=f.Text(title, size=32, text_align="start"),
            center_title=False,
            toolbar_height=75,
            actions=[
                f.Container(
                    content=dd,
                    margin=f.margin.only(left=50, right=25),
                )
            ],
        )

    def _build_nav_bar(self):
        async def on_nav(e):
            # important, remove old controls
            await self.page.remove_async(*self.nw_pages[self.current_page])
            self.current_page = e.data
            await self.page.add_async(*self.nw_pages[self.current_page])
            await self.page.update_async()

        return f.NavigationBar(
            on_change=on_nav,
            destinations=[
                f.NavigationDestination(icon=f.icons.WALLET, label="Balance"),
                f.NavigationDestination(icon=f.icons.SEND, label="Send"),
                f.NavigationDestination(icon=f.icons.RECEIPT, label="Receive"),
            ],
        )
