from typing import Dict, List, Optional

from pydantic import BaseModel


class KeysResponseKeyset(BaseModel):
    id: str
    unit: str
    active: bool
    input_fee_ppk: Optional[int] = None
    keys: Dict[int, str]
    final_expiry: Optional[int] = None


class KeysResponse(BaseModel):
    keysets: List[KeysResponseKeyset]


class KeysetsResponseKeyset(BaseModel):
    id: str
    unit: str
    active: bool
    input_fee_ppk: Optional[int] = None
    final_expiry: Optional[int] = None


class KeysetsResponse(BaseModel):
    keysets: list[KeysetsResponseKeyset]
