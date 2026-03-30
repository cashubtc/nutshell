from typing import Any, Dict, List, Optional

from pydantic import BaseModel, model_validator


class MintMethodBolt11OptionSetting(BaseModel):
    description: Optional[bool] = None


class MintMethodSetting(BaseModel):
    method: str
    unit: str
    min_amount: Optional[int] = None
    max_amount: Optional[int] = None
    options: Optional[MintMethodBolt11OptionSetting] = None


class MeltMethodSetting(BaseModel):
    method: str
    unit: str
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

    # BEGIN DEPRECATED: NUT-06 contact field change
    # NUT-06 PR: https://github.com/cashubtc/nuts/pull/117
    @model_validator(mode="before")
    @classmethod
    def preprocess_deprecated_contact_field(cls, values: dict):
        if "contact" in values and values["contact"]:
            if isinstance(values["contact"][0], list):
                values["contact"] = [
                    MintInfoContact(method=method, info=info)
                    for method, info in values["contact"]
                    if method and info
                ]
        return values

    # END DEPRECATED: NUT-06 contact field change


class Nut15MppSupport(BaseModel):
    method: str
    unit: str


class GetInfoResponse_deprecated(BaseModel):
    name: Optional[str] = None
    pubkey: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    description_long: Optional[str] = None
    contact: Optional[List[List[str]]] = None
    nuts: Optional[List[str]] = None
    motd: Optional[str] = None
    parameter: Optional[dict] = None
