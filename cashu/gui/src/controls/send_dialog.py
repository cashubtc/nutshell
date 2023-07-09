from enum import IntEnum
from typing import Callable, Tuple

import flet as f


class SendType(IntEnum):
    TOKEN = 0
    LIGHTNING = 1
    NOSTR_KEY = 2


class SendData:
    type: SendType = SendType.TOKEN
    amount_sat: int = 0
    invoice: str = ""

    def infer_type(self):
        res, err = self.validate()
        if not res:
            raise RuntimeError(f"Invalid data: {err}")

        if self.amount_sat > 0:
            self.type = SendType.TOKEN
            return

        if self.invoice != "":
            self.type = SendType.LIGHTNING
            return

        self.type = SendType.NOSTR_KEY

    def validate(self) -> Tuple[int, str]:
        if self.amount_sat > 0 and self.invoice != "":
            return False, "Amount and invoice cannot both be set"

        if self.amount_sat == 0 and self.invoice == "":
            return False, "One of amount or invoice must both be set"

        return True, ""


class SendDialogContent(f.UserControl):
    def __init__(self) -> None:
        self._send_data: SendData = SendData()
        self._error = False
        self._error_msg = ""

        super().__init__()

    @property
    def send_data(self):
        return self._send_data

    def build(self):
        return f.Column(
            horizontal_alignment=f.CrossAxisAlignment.CENTER,
            tight=True,
            controls=[
                f.TextField(
                    key="amount",
                    label="Amount",
                    hint_text="Amount",
                    on_change=self._on_text_changed,
                    suffix_text="sat",
                    autofocus=True,
                    keyboard_type=f.KeyboardType.NUMBER,
                ),
                f.Text("or", style=f.TextThemeStyle.HEADLINE_SMALL),
                f.TextField(
                    key="invoice",
                    label="Invoice",
                    hint_text="Invoice",
                    on_change=self._on_text_changed,
                ),
                f.Text(self._error_msg if self._error else ""),
            ],
        )

    async def _on_text_changed(self, e: f.ControlEvent):
        if e.control.key == "amount":
            try:
                value = int(e.control.value)
                self._send_data.amount_sat = value
                self._error = False
            except ValueError:
                self._error = True
        elif e.control.key == "invoice":
            invoice = e.control.value.strip()
            self._send_data.invoice = invoice
        else:
            RuntimeError(f"Unknown key {e.control.key}")

        success, error_msg = self._send_data.validate()
        if not success:
            self._error = True
            self._error_msg = error_msg
            return

        self._send_data.infer_type()


class SendDialog(f.UserControl):
    def __init__(self, on_dismiss: Callable, on_confirm: Callable) -> None:
        self._on_dismiss = on_dismiss
        self._on_confirm = on_confirm
        self._content = SendDialogContent()
        self._dlg = f.AlertDialog(
            modal=True,
            title=f.Text("Send Funds"),
            content=self._content,
            actions=[
                f.TextButton("OK", on_click=self._confirm_send),
                f.TextButton("Cancel", on_click=self._on_dismiss_send),
            ],
            actions_alignment=f.MainAxisAlignment.END,
            on_dismiss=lambda e: self._on_dismiss(),
        )

        super().__init__()

    async def _confirm_send(self, _):
        await self._on_confirm(self._content.send_data)

    async def _on_dismiss_send(self, _):
        await self._on_dismiss()

    def build(self):
        return self._dlg

    def open(self):
        self._dlg.open = True

    def close(self):
        self._dlg.open = False
