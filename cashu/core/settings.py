import os
import sys
from pathlib import Path
from typing import List, Optional

from environs import Env  # type: ignore
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

env = Env()

VERSION = "0.19.2"


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
    env_file: Optional[str] = Field(default=None)
    lightning_fee_percent: float = Field(default=1.0)
    lightning_reserve_fee_min: int = Field(default=2000)
    max_order: int = Field(default=64)

    model_config = SettingsConfigDict(
        env_file=find_env_file(),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


class EnvSettings(CashuSettings):
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    cashu_dir: str = Field(default=os.path.join(str(Path.home()), ".cashu"))
    debug_profiling: bool = Field(default=False)
    debug_mint_only_deprecated: bool = Field(default=False)
    db_backup_path: Optional[str] = Field(default=None)
    db_connection_pool: bool = Field(default=True)


class MintSettings(CashuSettings):
    mint_private_key: Optional[str] = Field(default=None)
    mint_seed_decryption_key: Optional[str] = Field(default=None)
    mint_derivation_path: str = Field(default="m/0'/0'/0'")
    mint_derivation_path_list: List[str] = Field(default=[])
    mint_listen_host: str = Field(default="127.0.0.1")
    mint_listen_port: int = Field(default=3338)

    mint_database: str = Field(default="data/mint")
    mint_test_database: str = Field(default="test_data/test_mint")
    mint_max_secret_length: int = Field(default=1024)
    mint_max_witness_length: int = Field(default=1024)

    mint_input_fee_ppk: int = Field(default=100)
    mint_disable_melt_on_error: bool = Field(default=False)

    mint_regular_tasks_interval_seconds: int = Field(
        default=3600,
        gt=0,
        title="Regular tasks interval",
        description="Interval (in seconds) for running regular tasks like the invoice checker.",
    )

    mint_retry_exponential_backoff_base_delay: int = Field(default=1)
    mint_retry_exponential_backoff_max_delay: int = Field(default=10)


class MintWatchdogSettings(MintSettings):
    mint_watchdog_enabled: bool = Field(
        default=False,
        title="Balance watchdog",
        description="The watchdog shuts down the mint if the balance of the mint and the backend do not match.",
    )
    mint_watchdog_balance_check_interval_seconds: float = Field(default=60)
    mint_watchdog_ignore_mismatch: bool = Field(
        default=False,
        description="Ignore watchdog errors and continue running. Use this to recover from a watchdog error.",
    )


class MintDeprecationFlags(MintSettings):
    mint_inactivate_base64_keysets: bool = Field(default=False)


class MintBackends(MintSettings):
    mint_lightning_backend: str = Field(default="")  # deprecated
    mint_backend_bolt11_sat: str = Field(default="")
    mint_backend_bolt11_msat: str = Field(default="")
    mint_backend_bolt11_usd: str = Field(default="")
    mint_backend_bolt11_eur: str = Field(default="")

    mint_lnbits_endpoint: Optional[str] = Field(default=None)
    mint_lnbits_key: Optional[str] = Field(default=None)
    mint_strike_key: Optional[str] = Field(default=None)
    mint_blink_key: Optional[str] = Field(default=None)


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

    mint_peg_out_only: bool = Field(  # deprecated for mint_bolt11_disable_mint
        default=False,
        title="Disable minting tokens with bolt11",
        description="Mint allows no bolt11 minting operations.",
    )
    mint_bolt11_disable_mint: bool = Field(
        default=False,
        title="Disable minting tokens with bolt11",
        description="Mint allows no bolt11 minting operations.",
    )
    mint_bolt11_disable_melt: bool = Field(
        default=False,
        title="Disable melting tokens with bolt11",
        description="Mint allows no bolt11 melting operations.",
    )

    mint_max_peg_in: Optional[int] = Field(  # deprecated for mint_max_mint_bolt11_sat
        default=None,
        ge=0,
        title="Maximum peg-in",
        description="Maximum amount for a mint operation.",
    )
    mint_max_peg_out: Optional[int] = Field(  # deprecated for mint_max_melt_bolt11_sat
        default=None,
        ge=0,
        title="Maximum peg-out",
        description="Maximum amount for a melt operation.",
    )
    mint_max_mint_bolt11_sat: Optional[int] = Field(
        default=None,
        ge=0,
        title="Maximum mint amount for bolt11 in satoshis",
        description="Maximum amount for a bolt11 mint operation in satoshis.",
    )
    mint_max_melt_bolt11_sat: Optional[int] = Field(
        default=None,
        ge=0,
        title="Maximum melt amount for bolt11 in satoshis",
        description="Maximum amount for a bolt11 melt operation in satoshis.",
    )
    mint_max_balance: Optional[int] = Field(
        default=None,
        ge=0,
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
    fakewallet_balance_sat: int = Field(default=1337)
    fakewallet_balance_usd: int = Field(default=1337)
    fakewallet_balance_eur: int = Field(default=1337)


class MintInformation(CashuSettings):
    mint_info_name: str = Field(default="Cashu mint")
    mint_info_description: Optional[str] = Field(default=None)
    mint_info_description_long: Optional[str] = Field(default=None)
    mint_info_contact: List[List[str]] = Field(default=[])
    mint_info_motd: Optional[str] = Field(default=None)
    mint_info_icon_url: Optional[str] = Field(default=None)
    mint_info_urls: Optional[List[str]] = Field(default=None)
    mint_info_tos_url: Optional[str] = Field(default=None)


class MintManagementRPCSettings(MintSettings):
    mint_rpc_server_enable: bool = Field(
        default=False, description="Enable the management RPC server."
    )
    mint_rpc_server_ca: Optional[str] = Field(
        default=None,
        description="CA certificate file path for the management RPC server.",
    )
    mint_rpc_server_cert: Optional[str] = Field(
        default=None,
        description="Server certificate file path for the management RPC server.",
    )
    mint_rpc_server_key: Optional[str] = Field(default=None)
    mint_rpc_server_addr: str = Field(
        default="localhost", description="Address for the management RPC server."
    )
    mint_rpc_server_port: int = Field(
        default=8086, gt=0, lt=65536, description="Port for the management RPC server."
    )
    mint_rpc_server_mutual_tls: bool = Field(
        default=True, description="Require client certificates."
    )


class WalletSettings(CashuSettings):
    tor: bool = Field(default=False)
    socks_host: Optional[str] = Field(default=None)  # deprecated
    socks_port: int = Field(default=9050)  # deprecated
    socks_proxy: Optional[str] = Field(default=None)
    http_proxy: Optional[str] = Field(default=None)
    mint_url: Optional[str] = Field(default=None)
    mint_host: str = Field(default="8333.space")
    mint_port: int = Field(default=3338)
    wallet_name: str = Field(default="wallet")
    wallet_unit: str = Field(default="sat")
    wallet_use_deprecated_h2c: bool = Field(default=False)
    wallet_verbose_requests: bool = Field(default=False)
    api_port: int = Field(default=4448)
    api_host: str = Field(default="127.0.0.1")
    npub_cash_hostname: str = Field(default="npubx.cash")

    locktime_delta_seconds: int = Field(default=86400)  # 1 day
    proofs_batch_size: int = Field(default=200)

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


class CLNRPCFundingSource(MintSettings):
    mint_cln_rpc_socket: Optional[str] = Field(
        default="~/.lightning/bitcoin/lightning-rpc"
    )
    mint_cln_rpc_enable_mpp: bool = Field(default=True)


class CoreLightningRestFundingSource(MintSettings):
    mint_corelightning_rest_url: Optional[str] = Field(default=None)
    mint_corelightning_rest_macaroon: Optional[str] = Field(default=None)
    mint_corelightning_rest_cert: Optional[str] = Field(default=None)


class AuthSettings(MintSettings):
    mint_auth_database: str = Field(default="data/mint")
    mint_require_auth: bool = Field(default=False)
    mint_auth_oicd_discovery_url: Optional[str] = Field(default=None)
    mint_auth_oicd_client_id: str = Field(default="cashu-client")
    mint_auth_rate_limit_per_minute: int = Field(
        default=5,
        title="Auth rate limit per minute",
        description="Number of requests a user can authenticate per minute.",
    )
    mint_auth_max_blind_tokens: int = Field(default=100, gt=0)
    mint_require_clear_auth_paths: List[List[str]] = [
        ["POST", "/v1/auth/blind/mint"],
    ]
    mint_require_blind_auth_paths: List[List[str]] = [
        ["POST", "/v1/swap"],
        ["POST", "/v1/mint/quote/bolt11"],
        ["POST", "/v1/mint/bolt11"],
        ["POST", "/v1/melt/bolt11"],
    ]


class MintRedisCache(MintSettings):
    mint_redis_cache_enabled: bool = Field(default=False)
    mint_redis_cache_url: Optional[str] = Field(default=None)
    mint_redis_cache_ttl: Optional[int] = Field(default=60 * 60 * 24 * 7)  # 1 week


class Settings(
    EnvSettings,
    LndRPCFundingSource,
    LndRestFundingSource,
    CLNRPCFundingSource,
    CoreLightningRestFundingSource,
    CLNRestFundingSource,
    FakeWalletSettings,
    MintLimits,
    MintBackends,
    AuthSettings,
    MintRedisCache,
    MintDeprecationFlags,
    MintManagementRPCSettings,
    MintWatchdogSettings,
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

    # backwards compatibility: mint_max_peg_in and mint_max_peg_out to mint_max_mint_bolt11_sat and mint_max_melt_bolt11_sat
    if settings.mint_max_peg_in:
        settings.mint_max_mint_bolt11_sat = settings.mint_max_peg_in
    if settings.mint_max_peg_out:
        settings.mint_max_melt_bolt11_sat = settings.mint_max_peg_out

    # backwards compatibility: set mint_bolt11_disable_mint from mint_peg_out_only
    if settings.mint_peg_out_only:
        settings.mint_bolt11_disable_mint = True


startup_settings_tasks()
