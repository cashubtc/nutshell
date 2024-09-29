from typing import Any, Dict, List, Union

from ..core.base import Method
from ..core.models import (
    MintMeltMethodSetting,
)
from ..core.nuts import (
    BLIND_AUTH_NUT,
    CLEAR_AUTH_NUT,
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
from ..mint.protocols import SupportsBackends


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

        # specify which websocket features are supported
        # these two are supported by default
        websocket_features: Dict[str, List[Dict[str, Union[str, List[str]]]]] = {
            "supported": []
        }
        # we check the backend to see if "bolt11_mint_quote" is supported as well
        for method, unit_dict in self.backends.items():
            if method == Method["bolt11"]:
                for unit in unit_dict.keys():
                    websocket_features["supported"].append(
                        {
                            "method": method.name,
                            "unit": unit.name,
                            "commands": ["bolt11_melt_quote", "proof_state"],
                        }
                    )
                    if unit_dict[unit].supports_incoming_payment_stream:
                        supported_features: List[str] = list(
                            websocket_features["supported"][-1]["commands"]
                        )
                        websocket_features["supported"][-1]["commands"] = (
                            supported_features + ["bolt11_mint_quote"]
                        )

        if websocket_features:
            mint_features[WEBSOCKETS_NUT] = websocket_features

        if settings.mint_require_auth:
            clear_auth_features: Dict[str, Union[bool, str, List[str]]] = {
                "required": True,
                "paths": [],
            }

            for path in settings.mint_require_clear_auth_paths_regex:
                clear_auth_features["paths"].append(path)  # type: ignore

            mint_features[CLEAR_AUTH_NUT] = clear_auth_features

            blind_auth_features: Dict[str, Union[bool, int, str, List[str]]] = {
                "required": True,
                "max_mint": settings.mint_auth_max_blind_tokens,
                "paths": [],
            }
            for path in settings.mint_require_blind_auth_paths_regex:
                blind_auth_features["paths"].append(path)  # type: ignore

            mint_features[BLIND_AUTH_NUT] = blind_auth_features

        return mint_features
