"""Authenticated, expiring continuation values for mint quote lookup."""

import base64
import hmac
import json
import secrets
import time
from hashlib import sha256
from typing import List

from pydantic import BaseModel, ConfigDict, Field

from ..core.constants import MAX_QUOTE_ID_LEN
from ..core.errors import CashuError

CURSOR_LIFETIME_SECONDS = 3600


class _CursorData(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    scope: str
    after: str = Field(min_length=1, max_length=MAX_QUOTE_ID_LEN)
    expires_at: int


class QuoteLookupCursor:
    def __init__(self):
        # Restarting the ledger invalidates outstanding cursors. Wallets can
        # restart their scan; no persistent cursor state or mint key is needed.
        self._key = secrets.token_bytes(32)

    @staticmethod
    def _scope(method: str, pubkeys: List[str]) -> str:
        scope = json.dumps([method, sorted(pubkeys)], separators=(",", ":"))
        return sha256(scope.encode()).hexdigest()

    def encode(self, method: str, pubkeys: List[str], after: str) -> str:
        payload = (
            _CursorData(
                scope=self._scope(method, pubkeys),
                after=after,
                expires_at=int(time.time()) + CURSOR_LIFETIME_SECONDS,
            )
            .model_dump_json()
            .encode()
        )
        encoded = base64.urlsafe_b64encode(payload).decode()
        signature = hmac.new(self._key, encoded.encode(), sha256).hexdigest()
        return f"{encoded}.{signature}"

    def decode(self, cursor: str, method: str, pubkeys: List[str]) -> str:
        try:
            encoded, signature = cursor.split(".")
            expected = hmac.new(self._key, encoded.encode(), sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError("invalid cursor signature")
            payload = base64.b64decode(encoded, altchars=b"-_", validate=True)
            data = _CursorData.model_validate_json(payload)
            if data.scope != self._scope(method, pubkeys):
                raise ValueError("mismatched cursor scope")
            if data.expires_at <= int(time.time()):
                raise ValueError("expired cursor")
            return data.after
        except (ValueError, TypeError) as exc:
            raise CashuError(
                "Mint quote lookup cursor is invalid, expired, or mismatched."
            ) from exc
