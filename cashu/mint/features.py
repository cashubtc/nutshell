from typing import Any, Dict, List

from fastapi import APIRouter

from ..core.base import (
    MintMeltMethodSetting,
)
from ..core.nuts import (
    DLEQ_NUT,
    FEE_RETURN_NUT,
    MELT_NUT,
    MINT_NUT,
    P2PK_NUT,
    RESTORE_NUT,
    SCRIPT_NUT,
    STATE_NUT,
    WEBSOCKETS_NUT,
)
from ..core.settings import settings
from ..mint.startup import ledger

router: APIRouter = APIRouter()


class LedgerFeatures:
    def mint_features(self) -> Dict[int, Dict[str, Any]]:
        # determine all method-unit pairs
        method_settings: Dict[int, List[MintMeltMethodSetting]] = {}
        for nut in [MINT_NUT, MELT_NUT]:
            method_settings[nut] = []
            for method, unit_dict in ledger.backends.items():
                for unit in unit_dict.keys():
                    setting = MintMeltMethodSetting(method=method.name, unit=unit.name)

                    if nut == MINT_NUT and settings.mint_max_peg_in:
                        setting.max_amount = settings.mint_max_peg_in
                        setting.min_amount = 0
                    elif nut == MELT_NUT and settings.mint_max_peg_out:
                        setting.max_amount = settings.mint_max_peg_out
                        setting.min_amount = 0

                    method_settings[nut].append(setting)

        supported_dict = dict(supported=True)

        mint_features: Dict[int, Dict[str, Any]] = {
            MINT_NUT: dict(
                methods=method_settings[MINT_NUT],
                disabled=settings.mint_peg_out_only,
            ),
            MELT_NUT: dict(
                methods=method_settings[MELT_NUT],
                disabled=False,
            ),
            STATE_NUT: supported_dict,
            FEE_RETURN_NUT: supported_dict,
            RESTORE_NUT: supported_dict,
            SCRIPT_NUT: supported_dict,
            P2PK_NUT: supported_dict,
            DLEQ_NUT: supported_dict,
            WEBSOCKETS_NUT: supported_dict,
        }
        return mint_features
