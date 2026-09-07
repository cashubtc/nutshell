from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict


class MintMethodBolt11OptionSetting(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: Optional[bool] = None


class MintMethodSetting(BaseModel):
    method: str
    unit: str
    method_name: Optional[str] = None
    min_amount: Optional[int] = None
    max_amount: Optional[int] = None
    # BOLT11 historically exposes an attribute-based options model. Keep this
    # field open so other methods may publish their own typed option model.
    options: Optional[Union[MintMethodBolt11OptionSetting, Dict[str, Any]]] = None


class MeltMethodSetting(BaseModel):
    method: str
    unit: str
    method_name: Optional[str] = None
    min_amount: Optional[int] = None
    max_amount: Optional[int] = None
    options: Optional[Dict[str, Any]] = None


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
    max_array_length: Optional[int] = None
    nuts: Optional[Dict[int, Any]] = None

    def supports(self, nut: int) -> Optional[bool]:
        return nut in self.nuts if self.nuts else None


class Nut15MppSupport(BaseModel):
    method: str
    unit: str
