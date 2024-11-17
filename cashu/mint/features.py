from typing import Any, Dict, List, Union

from ..core.base import Method
from ..core.mint_info import MintInfo
from ..core.models import (
    MeltMethodSetting,
    MintInfoContact,
    MintInfoProtectedEndpoint,
    MintMethodSetting,
)
from ..core.nuts import (
    BLIND_AUTH_NUT,
    CLEAR_AUTH_NUT,
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
from ..mint.protocols import SupportsBackends, SupportsPubkey


class LedgerFeatures(SupportsBackends, SupportsPubkey):
    @property
    def mint_info(self) -> MintInfo:
        contact_info = [
            MintInfoContact(method=m, info=i)
            for m, i in settings.mint_info_contact
            if m and i
        ]
        return MintInfo(
            name=settings.mint_info_name,
            pubkey=self.pubkey.serialize().hex() if self.pubkey else None,
            version=f"Nutshell/{settings.version}",
            description=settings.mint_info_description,
            description_long=settings.mint_info_description_long,
            contact=contact_info,
            nuts=self.mint_features,
            icon_url=settings.mint_info_icon_url,
            motd=settings.mint_info_motd,
            time=None,
        )

    @property
    def mint_features(self) -> Dict[int, Union[List[Any], Dict[str, Any]]]:
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

        supported_dict = dict(supported=True)

        mint_features: Dict[int, Union[List[Any], Dict[str, Any]]] = {
            MINT_NUT: dict(
                methods=mint_method_settings,
                disabled=settings.mint_peg_out_only,
            ),
            MELT_NUT: dict(
                methods=melt_method_settings,
                disabled=False,
            ),
            STATE_NUT: supported_dict,
            FEE_RETURN_NUT: supported_dict,
            RESTORE_NUT: supported_dict,
            SCRIPT_NUT: supported_dict,
            P2PK_NUT: supported_dict,
            DLEQ_NUT: supported_dict,
            HTLC_NUT: supported_dict,
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
            mint_features[MPP_NUT] = dict(methods=mpp_features)

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

        # signal authentication features
        if settings.mint_require_auth:
            if not settings.mint_auth_oicd_discovery_url:
                raise Exception(
                    "Missing OpenID Connect discovery URL: MINT_AUTH_OICD_DISCOVERY_URL"
                )
            clear_auth_features: Dict[str, Union[bool, str, List[str]]] = {
                "openid_discovery": settings.mint_auth_oicd_discovery_url,
                "protected_endpoints": [],
            }

            for endpoint in [
                MintInfoProtectedEndpoint(method=e[0], path=e[1])
                for e in settings.mint_require_clear_auth_paths
            ]:
                clear_auth_features["protected_endpoints"].append(endpoint.dict())  # type: ignore

            mint_features[CLEAR_AUTH_NUT] = clear_auth_features

            blind_auth_features: Dict[str, Union[bool, int, str, List[str]]] = {
                "max_mint": settings.mint_auth_max_blind_tokens,
                "protected_endpoints": [],
            }
            for endpoint in [
                MintInfoProtectedEndpoint(method=e[0], path=e[1])
                for e in settings.mint_require_blind_auth_paths
            ]:
                blind_auth_features["protected_endpoints"].append(endpoint.dict())  # type: ignore

            mint_features[BLIND_AUTH_NUT] = blind_auth_features

        return mint_features
