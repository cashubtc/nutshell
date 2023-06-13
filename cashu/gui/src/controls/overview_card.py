import flet as f
from cashu.gui.src.controls.balance_pie_chart import BalancePieChart

from cashu.gui.src.models.gui_wallet import GuiWallet


class OverviewCard(f.UserControl):
    _wallet: GuiWallet

    def __init__(self, wallet: GuiWallet):
        self._wallet = wallet
        super().__init__()

    def build(self):
        return f.Card(
            content=f.Container(content=self._build_body(), padding=10),
        )

    def _build_body(self):
        return f.Column(
            controls=[
                f.Row(
                    alignment=f.MainAxisAlignment.SPACE_EVENLY,
                    controls=[
                        f.Column(
                            controls=[
                                f.Text(
                                    f"TOTAL BALANCE",
                                    style=f.TextThemeStyle.DISPLAY_MEDIUM,
                                ),
                                f.Row(
                                    controls=[
                                        self._build_header_text("Available"),
                                        self._build_balance_text(
                                            self._wallet.available
                                        ),
                                    ]
                                ),
                                f.Row(
                                    controls=[
                                        self._build_header_text("Total"),
                                        self._build_balance_text(self._wallet.balance),
                                    ]
                                ),
                            ]
                        ),
                        f.Container(
                            width=300,
                            height=300,
                            content=BalancePieChart(self._wallet.balance_per_mint),
                        ),
                    ],
                ),
                f.Container(height=26),
                f.Row(
                    alignment=f.MainAxisAlignment.END,
                    controls=[
                        f.FilledTonalButton(text="Send"),
                        f.FilledTonalButton(text="Receive"),
                    ],
                ),
            ]
        )

    def _build_header_text(self, text: str):
        return f.Container(
            width=150,
            content=f.Text(text, style=f.TextThemeStyle.HEADLINE_MEDIUM),
        )

    def _build_balance_text(self, balance: float):
        return f.Text(f"{balance}", style=f.TextThemeStyle.HEADLINE_MEDIUM)
