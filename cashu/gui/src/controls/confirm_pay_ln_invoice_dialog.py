from typing import Callable

import flet as f


class ConfirmPayLnInvoiceDialog(f.UserControl):
    def __init__(
        self,
        invoice: str,
        amount: int,
        fees: int,
        on_dismiss: Callable[[str], None],
        on_confirm: Callable[[str, int, int], None],
    ) -> None:
        self._invoice = invoice
        self._amount = amount
        self._fees = fees
        self._on_dismiss = on_dismiss
        self._on_confirm = on_confirm
        self._dlg = f.AlertDialog(
            modal=True,
            title=f.Text("Pay LN Invoice?"),
            content=f.Text(f"Invoice Amount: {self._amount}\nMax Fees: {self._fees}"),
            actions=[
                f.TextButton("Confirm", on_click=self._confirm_pay),
                f.TextButton("Cancel", on_click=self._on_dismiss_pay),
            ],
            actions_alignment=f.MainAxisAlignment.END,
            on_dismiss=lambda _: self._on_dismiss(),
        )

        super().__init__()

    async def _confirm_pay(self, _):
        await self._on_confirm(self._invoice, self._amount, self._fees)

    async def _on_dismiss_pay(self, _):
        await self._on_dismiss(self._invoice)

    def build(self):
        return self._dlg

    def open(self):
        self._dlg.open = True

    def close(self):
        self._dlg.open = False
