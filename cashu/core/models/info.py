from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class MintMethodBolt11OptionSetting(BaseModel):
    description: Optional[bool] = None


class MintMethodSetting(BaseModel):
    method: str
    unit: str
    method_name: Optional[str] = None
    min_amount: Optional[int] = None
    max_amount: Optional[int] = None
    options: Optional[MintMethodBolt11OptionSetting] = None


class MeltMethodSetting(BaseModel):
    method: str
    unit: str
    method_name: Optional[str] = None
    min_amount: Optional[int] = None
    max_amount: Optional[int] = None


class MintInfoContact(BaseModel):
    method: str
    info: str


class MintInfoProtectedEndpoint(BaseModel):
    method: str
    path: str


class GetInfoResponse(BaseModel):
    name: Optional[str] = None
    pubkey: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    description_long: Optional[str] = None
    contact: Optional[List[MintInfoContact]] = None
    motd: Optional[str] = None
    icon_url: Optional[str] = None
    tos_url: Optional[str] = None
    urls: Optional[List[str]] = None
    time: Optional[int] = None
    nuts: Optional[Dict[int, Any]] = None

    def supports(self, nut: int) -> Optional[bool]:
        return nut in self.nuts if self.nuts else None


class Nut15MppSupport(BaseModel):
    method: str
    unit: str
