from typing import Callable

import flet as f
import pyclip


class ShowTextDialog(f.UserControl):
    """
    This class displays a the given text and offers copy to clipboard functionality
    """

    def __init__(self, on_dismiss: Callable) -> None:
        self._on_dismiss = on_dismiss
        self._dlg = f.AlertDialog(
            modal=True,
            title=f.Text("Please confirm"),
            actions=[
                f.IconButton(icon=f.icons.COPY, on_click=self._on_copy),
                f.TextButton("OK", on_click=self._on_dismiss_dlg),
            ],
            actions_alignment=f.MainAxisAlignment.END,
            on_dismiss=lambda e: self._on_dismiss(),
        )

        super().__init__()

    def _on_copy(self, _):
        pyclip.copy(self._text)

    async def _on_dismiss_dlg(self, _):
        await self._on_dismiss()

    def build(self):
        return self._dlg

    def open(self, text: str):
        if text is None or text == "":
            raise ValueError("Text data cannot be empty")

        self._text = text
        self._dlg.content = f.TextField(value=text, read_only=True, max_lines=3)
        self._dlg.open = True

    def close(self):
        self._dlg.open = False
