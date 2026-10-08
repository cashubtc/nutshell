from __future__ import annotations

import re
from importlib import metadata
from typing import Iterable, Optional

from .base import PaymentMethodPlugin

PAYMENT_METHOD_PATTERN = re.compile(r"^[a-z0-9_-]+$")
PAYMENT_METHOD_ENTRY_POINT = "cashu.payment_methods"


class PaymentMethodRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, PaymentMethodPlugin] = {}

    @staticmethod
    def validate_method(method: str) -> str:
        if not method or not PAYMENT_METHOD_PATTERN.fullmatch(method):
            raise ValueError("payment method must match [a-z0-9_-]+")
        return method

    def register(self, plugin: PaymentMethodPlugin, *, replace: bool = False) -> None:
        method = self.validate_method(plugin.method)
        if method in self._plugins and not replace:
            raise ValueError(f"payment method '{method}' is already registered")
        self._plugins[method] = plugin

    def get(self, method: str) -> PaymentMethodPlugin:
        self.validate_method(method)
        try:
            return self._plugins[method]
        except KeyError as exc:
            raise ValueError(f"unsupported payment method '{method}'") from exc

    def maybe_get(self, method: str) -> Optional[PaymentMethodPlugin]:
        return self._plugins.get(method)

    def methods(self) -> tuple[str, ...]:
        return tuple(self._plugins)

    def load_entry_points(self, allowlist: Iterable[str]) -> None:
        allowed = set(allowlist)
        if not allowed:
            return
        entry_points = metadata.entry_points()
        selected = entry_points.select(group=PAYMENT_METHOD_ENTRY_POINT)
        found: set[str] = set()
        for entry_point in selected:
            if entry_point.name not in allowed:
                continue
            loaded = entry_point.load()
            plugin = loaded() if isinstance(loaded, type) else loaded
            if not isinstance(plugin, PaymentMethodPlugin):
                raise TypeError(
                    f"entry point '{entry_point.name}' did not provide a PaymentMethodPlugin"
                )
            self.register(plugin)
            found.add(entry_point.name)
        missing = allowed - found
        if missing:
            raise ValueError(
                "payment method plugins not installed: " + ", ".join(sorted(missing))
            )


payment_method_registry = PaymentMethodRegistry()
