from typing import Any, Dict, List, Union

from cashu.mint.protocols import SupportsBackends

from ..core.models import (
    MintMeltMethodSetting,
)
from ..core.nuts import (
    DLEQ_NUT,
    FEE_RETURN_NUT,
    MELT_NUT,
    MINT_NUT,
    MPP_NUT,
    P2PK_NUT,
    RESTORE_NUT,
    SCRIPT_NUT,
    STATE_NUT,
    WEBSOCKETS_NUT,
)
from ..core.settings import settings


class LedgerFeatures(SupportsBackends):
    def mint_features(self) -> Dict[int, Union[List[Any], Dict[str, Any]]]:
        # determine all method-unit pairs
        method_settings: Dict[int, List[MintMeltMethodSetting]] = {}
        for nut in [MINT_NUT, MELT_NUT]:
            method_settings[nut] = []
            for method, unit_dict in self.backends.items():
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

        mint_features: Dict[int, Union[List[Any], Dict[str, Any]]] = {
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

        # signal which method-unit pairs support MPP
        mpp_features = []
        for method, unit_dict in self.backends.items():
            for unit in unit_dict.keys():
                if unit_dict[unit].supports_mpp:
                    mpp_features.append(
                        {
                            "method": method.name,
                            "unit": unit.name,
                            "mpp": True,
                        }
                    )

        if mpp_features:
            mint_features[MPP_NUT] = mpp_features

        return mint_features
