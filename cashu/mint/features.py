from typing import Any, Dict, List, Union

from ..core.base import Method
from ..core.models import (
    MeltMethodSetting,
    MintMethodSetting,
)
from ..core.nuts import (
    CACHE_NUT,
    DLEQ_NUT,
    FEE_RETURN_NUT,
    HTLC_NUT,
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
        mint_features = self.create_mint_features()
        mint_features = self.add_supported_features(mint_features)
        mint_features = self.add_mpp_features(mint_features)
        mint_features = self.add_websocket_features(mint_features)
        mint_features = self.add_cache_features(mint_features)

        return mint_features

    def create_mint_features(self) -> Dict[int, Union[List[Any], Dict[str, Any]]]:
        mint_method_settings: List[MintMethodSetting] = []
        for method, unit_dict in self.backends.items():
            for unit in unit_dict.keys():
                mint_setting = MintMethodSetting(method=method.name, unit=unit.name)
                if settings.mint_max_peg_in:
                    mint_setting.max_amount = settings.mint_max_peg_in
                    mint_setting.min_amount = 0
                mint_method_settings.append(mint_setting)
                mint_setting.description = unit_dict[unit].supports_description
        melt_method_settings: List[MeltMethodSetting] = []
        for method, unit_dict in self.backends.items():
            for unit in unit_dict.keys():
                melt_setting = MeltMethodSetting(method=method.name, unit=unit.name)
                if settings.mint_max_peg_out:
                    melt_setting.max_amount = settings.mint_max_peg_out
                    melt_setting.min_amount = 0
                melt_method_settings.append(melt_setting)

        mint_features: Dict[int, Union[List[Any], Dict[str, Any]]] = {
            MINT_NUT: dict(
                methods=mint_method_settings,
                disabled=settings.mint_peg_out_only,
            ),
            MELT_NUT: dict(
                methods=melt_method_settings,
                disabled=False,
            ),
        }
        return mint_features

    def add_supported_features(
        self, mint_features: Dict[int, Union[List[Any], Dict[str, Any]]]
    ):
        supported_dict = dict(supported=True)
        mint_features[STATE_NUT] = supported_dict
        mint_features[FEE_RETURN_NUT] = supported_dict
        mint_features[RESTORE_NUT] = supported_dict
        mint_features[SCRIPT_NUT] = supported_dict
        mint_features[P2PK_NUT] = supported_dict
        mint_features[DLEQ_NUT] = supported_dict
        mint_features[HTLC_NUT] = supported_dict
        return mint_features

    def add_mpp_features(
        self, mint_features: Dict[int, Union[List[Any], Dict[str, Any]]]
    ):
        # signal which method-unit pairs support MPP
        mpp_features = []
        for method, unit_dict in self.backends.items():
            for unit in unit_dict.keys():
                if unit_dict[unit].supports_mpp:
                    mpp_features.append({"method": method.name, "unit": unit.name})

        if mpp_features:
            mint_features[MPP_NUT] = dict(methods=mpp_features)

        return mint_features

    def add_websocket_features(
        self, mint_features: Dict[int, Union[List[Any], Dict[str, Any]]]
    ):
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

        return mint_features

    def add_cache_features(
        self, mint_features: Dict[int, Union[List[Any], Dict[str, Any]]]
    ):
        if settings.mint_redis_cache_enabled:
            cache_features: dict[str, list[dict[str, str]] | int] = {
                "cached_endpoints": [
                    {
                        "method": "POST",
                        "path": "/v1/mint/bolt11",
                    },
                    {
                        "method": "POST",
                        "path": "/v1/melt/bolt11",
                    },
                    {
                        "method": "POST",
                        "path": "/v1/swap",
                    },
                ]
            }
            if settings.mint_redis_cache_ttl:
                cache_features["ttl"] = settings.mint_redis_cache_ttl

            mint_features[CACHE_NUT] = cache_features
        return mint_features
