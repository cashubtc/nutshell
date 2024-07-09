from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from cashu.core.nuts import MPP_NUT, WEBSOCKETS_NUT

from ..core.base import Method, Unit
from ..core.models import Nut15MppSupport


class MintInfo(BaseModel):
    name: Optional[str] = None
    pubkey: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    description_long: Optional[str] = None
    contact: Optional[List[List[str]]] = None
    motd: Optional[str] = None
    nuts: Optional[Dict[int, Any]] = None

    def __str__(self):
        return f"{self.name} ({self.description})"

    def supports_nut(self, nut: int) -> bool:
        if self.nuts is None:
            return False
        return nut in self.nuts

    def supports_mpp(self, method: str, unit: Unit) -> bool:
        if not self.nuts:
            return False
        nut_15 = self.nuts.get(MPP_NUT)
        if not nut_15 or not self.supports_nut(MPP_NUT):
            return False

        for entry in nut_15:
            entry_obj = Nut15MppSupport.model_validate(entry)
            if entry_obj.method == method and entry_obj.unit == unit.name:
                return True

        return False

    def supports_websocket_mint_quote(self, method: Method, unit: Unit) -> bool:
        if not self.nuts or not self.supports_nut(WEBSOCKETS_NUT):
            return False
        websocket_settings = self.nuts[WEBSOCKETS_NUT]
        if not websocket_settings:
            return False
        for entry in websocket_settings:
            if entry["method"] == method.name and entry["unit"] == unit.name:
                if "bolt11_mint_quote" in entry["commands"]:
                    return True
        return False
