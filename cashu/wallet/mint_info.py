import json
import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from ..core.base import Method, Unit
from ..core.models import MintInfoContact, Nut15MppSupport
from ..core.nuts import BLIND_AUTH_NUT, CLEAR_AUTH_NUT, MPP_NUT, WEBSOCKETS_NUT


class MintInfo(BaseModel):
    name: Optional[str]
    pubkey: Optional[str]
    version: Optional[str]
    description: Optional[str]
    description_long: Optional[str]
    contact: Optional[List[MintInfoContact]]
    motd: Optional[str]
    icon_url: Optional[str]
    time: Optional[int]
    nuts: Dict[int, Any]

    def __str__(self):
        return f"{self.name} ({self.description})"

    @classmethod
    def from_json_str(cls, json_str: str):
        return cls.parse_obj(json.loads(json_str))

    def supports_nut(self, nut: int) -> bool:
        if self.nuts is None:
            return False
        return nut in self.nuts

    def supports_mpp(self, method: str, unit: Unit) -> bool:
        if not self.nuts:
            return False
        nut_15 = self.nuts.get(MPP_NUT)
        if not nut_15 or not self.supports_nut(MPP_NUT) or not nut_15.get("methods"):
            return False

        for entry in nut_15["methods"]:
            entry_obj = Nut15MppSupport.parse_obj(entry)
            if entry_obj.method == method and entry_obj.unit == unit.name:
                return True

        return False

    def supports_websocket_mint_quote(self, method: Method, unit: Unit) -> bool:
        if not self.nuts or not self.supports_nut(WEBSOCKETS_NUT):
            return False
        websocket_settings = self.nuts[WEBSOCKETS_NUT]
        if not websocket_settings or "supported" not in websocket_settings:
            return False
        websocket_supported = websocket_settings["supported"]
        for entry in websocket_supported:
            if entry["method"] == method.name and entry["unit"] == unit.name:
                if "bolt11_mint_quote" in entry["commands"]:
                    return True
        return False

    def requires_clear_auth(self) -> bool:
        return self.supports_nut(CLEAR_AUTH_NUT)

    def oidc_discovery_url(self) -> str:
        if not self.requires_clear_auth():
            return ""
        print(self.nuts[CLEAR_AUTH_NUT])
        return self.nuts[CLEAR_AUTH_NUT]["openid_discovery"]

    def required_clear_auth_paths(self) -> List[str]:
        if not self.requires_clear_auth():
            return []
        return self.nuts[CLEAR_AUTH_NUT]["paths"]

    def requires_clear_auth_path(self, path: str) -> bool:
        if not self.requires_clear_auth():
            return False
        path = "/" + path if not path.startswith("/") else path
        if any(re.match(pattern, path) for pattern in self.required_clear_auth_paths()):
            return True
        else:
            return False

    def requires_blind_auth(self) -> bool:
        return self.supports_nut(BLIND_AUTH_NUT)

    def required_blind_auth_paths(self) -> List[str]:
        if not self.requires_blind_auth():
            return []
        return self.nuts[BLIND_AUTH_NUT]["paths"]

    def requires_blind_auth_path(self, path: str) -> bool:
        if not self.requires_blind_auth():
            return False
        path = "/" + path if not path.startswith("/") else path
        if any(re.match(pattern, path) for pattern in self.required_blind_auth_paths()):
            return True
        else:
            return False
