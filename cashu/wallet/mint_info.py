from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from ..core.base import Unit
from ..core.models import Nut15MppSupport


class MintInfo(BaseModel):
    name: Optional[str]
    pubkey: Optional[str]
    version: Optional[str]
    description: Optional[str]
    description_long: Optional[str]
    contact: Optional[List[List[str]]]
    motd: Optional[str]
    nuts: Optional[Dict[int, Any]]

    def __str__(self):
        return f"{self.name} ({self.description})"

    def supports_nut(self, nut: int) -> bool:
        if self.nuts is None:
            return False
        return nut in self.nuts

    def supports_mpp(self, method: str, unit: Unit) -> bool:
        if not self.nuts:
            return False
        nut_15 = self.nuts.get(15)
        if not nut_15 or not self.supports_nut(15):
            return False

        for entry in nut_15:
            entry_obj = Nut15MppSupport.parse_obj(entry)
            if entry_obj.method == method and entry_obj.unit == unit.name:
                return True

        return False
