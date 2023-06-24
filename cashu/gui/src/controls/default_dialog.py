from typing import Callable

import flet as f


class DefaultDialog(f.UserControl):
    def __init__(self, on_dismiss: Callable = None) -> None:
        self._on_dismiss = on_dismiss
        self._dlg = f.AlertDialog(on_dismiss=lambda e: self._on_dismiss(), open=False)

        super().__init__()

    async def _on_dismiss_dlg(self, _):
        await self._on_dismiss()

    def build(self):
        return self._dlg

    def open(self):
        self._dlg.open = True

    def close(self):
        self._dlg.open = False
