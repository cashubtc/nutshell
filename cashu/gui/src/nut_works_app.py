from sqlite3 import IntegrityError

import flet as f

from cashu.gui.src.controls.confirm_pay_ln_invoice_dialog import (
    ConfirmPayLnInvoiceDialog,
)
from cashu.gui.src.controls.default_dialog import DefaultDialog
from cashu.gui.src.controls.overview_card import OverviewCard
from cashu.gui.src.controls.send_dialog import SendData, SendDialog, SendType
from cashu.gui.src.controls.show_text_dialog import ShowTextDialog
from cashu.gui.src.mint_repository import MintRepository
from cashu.gui.src.wallet_repository import WalletRepository

# TODO: Improve Dialog handling when Flet is updated with enhanced
#       Dialog API. Should be available for next release.


class NutWorksApp:
    _selected_wallet: str
    _selected_mint: str

    def __init__(self, page: f.Page):
        self.page = page
        self.mint_repo = MintRepository()
        self.wallet_repo = WalletRepository()
        self._show_text_dlg = DefaultDialog()
        self._pay_invoice_dlg = DefaultDialog()
        self._send_dlg = DefaultDialog()

    async def init(self):
        await self.wallet_repo.init(self.mint_repo.default_mint)
        self.page.vertical_alignment = f.CrossAxisAlignment.START
        self._selected_mint = self.mint_repo.default_mint.name

        await self._build_page()

    async def _build_page(self):
        await self.page.clean_async()
        self.page.appbar = self._build_app_bar()
        await self.page.add_async(
            f.Column(
                alignment=f.MainAxisAlignment.END,
                controls=[
                    OverviewCard(
                        self.wallet_repo.wallet,
                        self._on_overview_card_mint_change,
                        self._selected_mint,
                        self._on_send_clicked,
                        self._on_receive_clicked,
                    ),
                ],
            ),
        )

        await self.page.update_async()

    async def _on_overview_card_mint_change(self, name: str):
        await self.wallet_repo.set_mint(name)
        self._selected_mint = name

        await self._build_page()

    def _build_app_bar(self, title: str = "NutWorks"):
        async def on_wallet_changed(e: f.ControlEvent):
            try:
                if self.wallet_repo.wallet.name == e.data:
                    return

                await self.wallet_repo.set_wallet(e.data)
                self._selected_wallet = e.data
                await self._build_page()
            except NotImplementedError:
                pass

        async def on_mint_changed(e: f.ControlEvent):
            try:
                if self.wallet_repo.mint.name == e.data:
                    return

                await self.wallet_repo.set_mint(e.data)
                self._selected_mint = e.data
                await self._build_page()
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

    async def _on_send_clicked(self, e: f.ControlEvent):
        self._send_dlg = SendDialog(
            on_dismiss=lambda: self._close_dlg(),
            on_confirm=self._on_send_confirmed,
        )
        self.page.dialog = self._send_dlg
        self._send_dlg.open()

        await self._build_page()

    async def _on_send_confirmed(self, data: SendData):
        w = self.wallet_repo.wallet

        if data.type == SendType.TOKEN:
            res = await w.get_token_string(data.amount_sat)
            await self._close_dlg(build_page=False)
            self._show_text_dlg = ShowTextDialog(on_dismiss=lambda: self._close_dlg())
            self._show_text_dlg.open(res)
            self.page.dialog = self._show_text_dlg

        if data.type == SendType.LIGHTNING:
            amount, fees = await w.get_pay_amount_with_fees(data.invoice)
            await self._close_dlg(build_page=False)
            self._pay_invoice_dlg = ConfirmPayLnInvoiceDialog(
                amount=amount,
                fees=fees,
                invoice=data.invoice,
                on_confirm=self._on_pay_invoice_confirm,
                on_dismiss=lambda _: self._close_dlg(),
            )
            self._pay_invoice_dlg.open()
            self.page.dialog = self._pay_invoice_dlg

        await self._build_page()

    def _on_receive_clicked(self, e: f.ControlEvent):
        print("receive clicked")

    async def _close_dlg(self, build_page: bool = True):
        self._send_dlg.close()
        self._pay_invoice_dlg.close()
        self._show_text_dlg.close()

        if build_page:
            await self._build_page()

    async def _on_pay_invoice_confirm(self, invoice: str, amount: int, fee: int):
        w = self.wallet_repo.wallet
        try:
            await w.pay_lightning(invoice, amount, fee)
        except IntegrityError as e:
            print(e)
            pass
        except Exception as e:
            sb = f.SnackBar(
                f.Text(f"Error: {e}"),
                bgcolor=f.colors.RED,
                duration=10000,
                action="Close",
                on_action=lambda _: self._close_snackbar(),
            )
            self.page.snack_bar = sb
            self.page.snack_bar.open = True

        await self._close_dlg()

    async def _close_snackbar(self):
        self.page.snack_bar.open = False
        await self._build_page()
