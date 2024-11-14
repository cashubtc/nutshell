import os
import sys
from pathlib import Path
from typing import List, Optional

from environs import Env  # type: ignore
from pydantic import BaseSettings, Extra, Field

env = Env()

VERSION = "0.16.3"


def find_env_file():
    # env file: default to current dir, else home dir
    env_file = os.path.join(os.getcwd(), ".env")
    if not os.path.isfile(env_file):
        env_file = os.path.join(str(Path.home()), ".cashu", ".env")
    if os.path.isfile(env_file):
        env.read_env(env_file, recurse=False, override=True)
    else:
        env_file = ""
    return env_file


class CashuSettings(BaseSettings):
    env_file: str = Field(default=None)
    lightning_fee_percent: float = Field(default=1.0)
    lightning_reserve_fee_min: int = Field(default=2000)
    max_order: int = Field(default=64)

    class Config(BaseSettings.Config):
        env_file = find_env_file()
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = Extra.ignore

        # def __init__(self, env_file=None):
        #     self.env_file = env_file or self.env_file


class EnvSettings(CashuSettings):
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    cashu_dir: str = Field(default=os.path.join(str(Path.home()), ".cashu"))
    debug_profiling: bool = Field(default=False)
    debug_mint_only_deprecated: bool = Field(default=False)
    db_backup_path: Optional[str] = Field(default=None)
    db_connection_pool: bool = Field(default=True)


class MintSettings(CashuSettings):
    mint_private_key: str = Field(default=None)
    mint_seed_decryption_key: Optional[str] = Field(default=None)
    mint_derivation_path: str = Field(default="m/0'/0'/0'")
    mint_derivation_path_list: List[str] = Field(default=[])
    mint_listen_host: str = Field(default="127.0.0.1")
    mint_listen_port: int = Field(default=3338)

    mint_database: str = Field(default="data/mint")
    mint_test_database: str = Field(default="test_data/test_mint")
    mint_max_secret_length: int = Field(default=512)

    mint_input_fee_ppk: int = Field(default=0)
    mint_disable_melt_on_error: bool = Field(default=False)


class MintDeprecationFlags(MintSettings):
    mint_inactivate_base64_keysets: bool = Field(default=False)


class MintBackends(MintSettings):
    mint_lightning_backend: str = Field(default="")  # deprecated
    mint_backend_bolt11_sat: str = Field(default="")
    mint_backend_bolt11_usd: str = Field(default="")
    mint_backend_bolt11_eur: str = Field(default="")

    mint_lnbits_endpoint: str = Field(default=None)
    mint_lnbits_key: str = Field(default=None)
    mint_strike_key: str = Field(default=None)
    mint_blink_key: str = Field(default=None)


class MintLimits(MintSettings):
    mint_rate_limit: bool = Field(
        default=False, title="Rate limit", description="IP-based rate limiter."
    )
    mint_global_rate_limit_per_minute: int = Field(
        default=60,
        gt=0,
        title="Global rate limit per minute",
        description="Number of requests an IP can make per minute to all endpoints.",
    )
    mint_transaction_rate_limit_per_minute: int = Field(
        default=20,
        gt=0,
        title="Transaction rate limit per minute",
        description="Number of requests an IP can make per minute to transaction endpoints.",
    )
    mint_max_request_length: int = Field(
        default=1000,
        gt=0,
        title="Maximum request length",
        description="Maximum length of REST API request arrays.",
    )

    mint_peg_out_only: bool = Field(
        default=False,
        title="Peg-out only",
        description="Mint allows no mint operations.",
    )
    mint_max_peg_in: int = Field(
        default=None,
        gt=0,
        title="Maximum peg-in",
        description="Maximum amount for a mint operation.",
    )
    mint_max_peg_out: int = Field(
        default=None,
        gt=0,
        title="Maximum peg-out",
        description="Maximum amount for a melt operation.",
    )
    mint_max_balance: int = Field(
        default=None,
        gt=0,
        title="Maximum mint balance",
        description="Maximum mint balance.",
    )
    mint_websocket_read_timeout: int = Field(
        default=10 * 60,
        gt=0,
        title="Websocket read timeout",
        description="Timeout for reading from a websocket.",
    )


class FakeWalletSettings(MintSettings):
    fakewallet_brr: bool = Field(default=True)
    fakewallet_delay_outgoing_payment: Optional[float] = Field(default=3.0)
    fakewallet_delay_incoming_payment: Optional[float] = Field(default=3.0)
    fakewallet_stochastic_invoice: bool = Field(default=False)
    fakewallet_payment_state: Optional[str] = Field(default="SETTLED")
    fakewallet_payment_state_exception: Optional[bool] = Field(default=False)
    fakewallet_pay_invoice_state: Optional[str] = Field(default="SETTLED")
    fakewallet_pay_invoice_state_exception: Optional[bool] = Field(default=False)


class MintInformation(CashuSettings):
    mint_info_name: str = Field(default="Cashu mint")
    mint_info_description: str = Field(default=None)
    mint_info_description_long: str = Field(default=None)
    mint_info_contact: List[List[str]] = Field(default=[])
    mint_info_motd: str = Field(default=None)
    mint_info_icon_url: str = Field(default=None)
    mint_info_urls: List[str] = Field(default=None)


class WalletSettings(CashuSettings):
    tor: bool = Field(default=False)
    socks_host: str = Field(default=None)  # deprecated
    socks_port: int = Field(default=9050)  # deprecated
    socks_proxy: str = Field(default=None)
    http_proxy: str = Field(default=None)
    mint_url: str = Field(default=None)
    mint_host: str = Field(default="8333.space")
    mint_port: int = Field(default=3338)
    wallet_name: str = Field(default="wallet")
    wallet_unit: str = Field(default="sat")
    wallet_use_deprecated_h2c: bool = Field(default=False)
    api_port: int = Field(default=4448)
    api_host: str = Field(default="127.0.0.1")

    nostr_private_key: str = Field(default=None)
    nostr_relays: List[str] = Field(
        default=[
            "wss://nostr-pub.wellorder.net",
            "wss://relay.damus.io",
            "wss://nostr.mom",
            "wss://relay.snort.social",
            "wss://nostr.mutinywallet.com",
            "wss://relay.minibits.cash",
            "wss://nos.lol",
            "wss://relay.nostr.band",
            "wss://relay.bitcoiner.social",
            "wss://140.f7z.io",
            "wss://relay.primal.net",
        ]
    )

    locktime_delta_seconds: int = Field(default=86400)  # 1 day
    proofs_batch_size: int = Field(default=1000)

    wallet_target_amount_count: int = Field(default=3)


class WalletDeprecationFlags(CashuSettings):
    wallet_inactivate_base64_keysets: bool = Field(
        default=True,
        title="Inactivate legacy base64 keysets",
        description="If you turn on this flag, old bas64 keysets will be ignored and the wallet will ony use new keyset versions.",
    )


class LndRestFundingSource(MintSettings):
    mint_lnd_rest_endpoint: Optional[str] = Field(default=None)
    mint_lnd_rest_cert: Optional[str] = Field(default=None)
    mint_lnd_rest_cert_verify: bool = Field(default=True)
    mint_lnd_rest_macaroon: Optional[str] = Field(default=None)
    mint_lnd_rest_admin_macaroon: Optional[str] = Field(default=None)
    mint_lnd_rest_invoice_macaroon: Optional[str] = Field(default=None)
    mint_lnd_enable_mpp: bool = Field(default=True)


class LndRPCFundingSource(MintSettings):
    mint_lnd_rpc_endpoint: Optional[str] = Field(default=None)
    mint_lnd_rpc_cert: Optional[str] = Field(default=None)
    mint_lnd_rpc_macaroon: Optional[str] = Field(default=None)


class CLNRestFundingSource(MintSettings):
    mint_clnrest_url: Optional[str] = Field(default=None)
    mint_clnrest_cert: Optional[str] = Field(default=None)
    mint_clnrest_rune: Optional[str] = Field(default=None)
    mint_clnrest_enable_mpp: bool = Field(default=True)


class CoreLightningRestFundingSource(MintSettings):
    mint_corelightning_rest_url: Optional[str] = Field(default=None)
    mint_corelightning_rest_macaroon: Optional[str] = Field(default=None)
    mint_corelightning_rest_cert: Optional[str] = Field(default=None)


class Settings(
    EnvSettings,
    LndRPCFundingSource,
    LndRestFundingSource,
    CoreLightningRestFundingSource,
    CLNRestFundingSource,
    FakeWalletSettings,
    MintLimits,
    MintBackends,
    MintDeprecationFlags,
    MintSettings,
    MintInformation,
    WalletSettings,
    WalletDeprecationFlags,
    CashuSettings,
):
    version: str = Field(default=VERSION)

    # def __init__(self, env_file=None):
    #     super().Config(env_file=env_file)


settings = Settings()


def startup_settings_tasks():
    # set env_file (this does not affect the settings module, it's just for reading)
    settings.env_file = find_env_file()

    if not settings.debug:
        # set traceback limit
        sys.tracebacklimit = 0

    # replace ~ with home directory in cashu_dir
    settings.cashu_dir = settings.cashu_dir.replace("~", str(Path.home()))

    # set mint_url if only mint_host is set
    if not settings.mint_url:
        if settings.mint_host in ["localhost", "127.0.0.1"] and settings.mint_port:
            # localhost without https
            settings.mint_url = f"http://{settings.mint_host}:{settings.mint_port}"
        else:
            settings.mint_url = f"https://{settings.mint_host}:{settings.mint_port}"

    # backwards compatibility: set socks_proxy from socks_host and socks_port
    if settings.socks_host and settings.socks_port:
        settings.socks_proxy = f"socks5://{settings.socks_host}:{settings.socks_port}"

    # backwards compatibility: set mint_backend_bolt11_sat from mint_lightning_backend
    if settings.mint_lightning_backend:
        settings.mint_backend_bolt11_sat = settings.mint_lightning_backend


startup_settings_tasks()
