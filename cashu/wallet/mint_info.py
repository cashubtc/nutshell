from typing import Any, Dict, List, Optional

from ..core.base import GetInfoResponse


class MintInfo:
    name: Optional[str] = None
    pubkey: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    description_long: Optional[str] = None
    contact: Optional[List[List[str]]] = None
    motd: Optional[str] = None
    nuts: Optional[Dict[int, Any]] = None

    def __init__(self, info_response: GetInfoResponse):
        self.name = info_response.name
        self.pubkey = info_response.pubkey
        self.version = info_response.version
        self.description = info_response.description
        self.description_long = info_response.description_long
        self.contact = info_response.contact
        self.motd = info_response.motd
        self.nuts = info_response.nuts

    def __str__(self):
        return f"{self.name} ({self.description})"

    def supports_nut(self, nut: int) -> bool:
        if self.nuts is None:
            return False
        return nut in self.nuts

    def supports_mpp(self) -> bool:
        return self.supports_nut(15)
