from typing import Callable, Tuple

import flet as f

from cashu.gui.src.constants import TransactionType


class ReceiveData:
    type: TransactionType = TransactionType.TOKEN
    amount_sat: int = 0
    token: str = ""

    def infer_type(self):
        res, err = self.validate()
        if not res:
            raise RuntimeError(f"Invalid data: {err}")

        if self.amount_sat > 0:
            self.type = TransactionType.LIGHTNING
            return

        if self.token != "":
            self.type = TransactionType.TOKEN
            return

        self.type = TransactionType.NOSTR_KEY

    def validate(self) -> Tuple[int, str]:
        if self.amount_sat > 0 and self.token != "":
            return False, "Amount and token cannot both be set"

        if self.amount_sat == 0 and self.token == "":
            return False, "One of amount or token must both be set"

        return True, ""


class ReceiveDialogContent(f.UserControl):
    def __init__(self) -> None:
        self._receive_data: ReceiveData = ReceiveData()
        self._error = False
        self._error_msg = ""

        super().__init__()

    @property
    def receive_data(self):
        return self._receive_data

    def build(self):
        return f.Column(
            horizontal_alignment=f.CrossAxisAlignment.CENTER,
            tight=True,
            controls=[
                f.TextField(
                    key="amount",
                    label="Amount",
                    hint_text="Amount For Invoice",
                    on_change=self._on_text_changed,
                    suffix_text="sat",
                    autofocus=True,
                    keyboard_type=f.KeyboardType.NUMBER,
                ),
                f.Text("or", style=f.TextThemeStyle.HEADLINE_SMALL),
                f.TextField(
                    key="token",
                    label="Token",
                    hint_text="Paste a token",
                    on_change=self._on_text_changed,
                ),
                f.Text(self._error_msg if self._error else ""),
            ],
        )

    async def _on_text_changed(self, e: f.ControlEvent):
        if e.control.key == "amount":
            try:
                value = int(e.control.value)
                self._receive_data.amount_sat = value
                self._error = False
            except ValueError:
                self._error = True
        elif e.control.key == "token":
            t = e.control.value.strip()
            self._receive_data.token = t
        else:
            RuntimeError(f"Unknown key {e.control.key}")

        success, error_msg = self._receive_data.validate()
        if not success:
            self._error = True
            self._error_msg = error_msg
            return

        self._receive_data.infer_type()


class ReceiveDialog(f.UserControl):
    def __init__(self, on_dismiss: Callable, on_confirm: Callable) -> None:
        self._on_dismiss = on_dismiss
        self._on_confirm = on_confirm
        self._content = ReceiveDialogContent()
        self._dlg = f.AlertDialog(
            modal=True,
            title=f.Text("Receive Funds"),
            content=self._content,
            actions=[
                f.TextButton("OK", on_click=self._confirm_receive),
                f.TextButton("Cancel", on_click=self._on_dismiss_receive),
            ],
            actions_alignment=f.MainAxisAlignment.END,
            on_dismiss=lambda e: self._on_dismiss(),
        )

        super().__init__()

    async def _confirm_receive(self, _):
        await self._on_confirm(self._content.receive_data)

    async def _on_dismiss_receive(self, _):
        await self._on_dismiss()

    def build(self):
        return self._dlg

    def open(self):
        self._dlg.open = True

    def close(self):
        self._dlg.open = False
