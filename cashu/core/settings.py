import os
import sys
from pathlib import Path
from typing import List

from environs import Env  # type: ignore
from pydantic import BaseSettings, Extra, Field

env = Env()

VERSION = "0.12.1"


def find_env_file():
    # env file: default to current dir, else home dir
    env_file = os.path.join(os.getcwd(), ".env")
    if not os.path.isfile(env_file):
        env_file = os.path.join(str(Path.home()), ".cashu", ".env")
    if os.path.isfile(env_file):
        env.read_env(env_file)
    else:
        env_file = ""
    return env_file


class CashuSettings(BaseSettings):
    env_file: str = Field(default=None)
    lightning: bool = Field(default=True)
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
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=3338)
    cashu_dir: str = Field(default=os.path.join(str(Path.home()), ".cashu"))


class MintSettings(CashuSettings):
    mint_private_key: str = Field(default=None)
    mint_derivation_path: str = Field(default="0/0/0/0")
    mint_listen_host: str = Field(default="127.0.0.1")
    mint_listen_port: int = Field(default=3338)
    mint_lightning_backend: str = Field(default="LNbitsWallet")
    mint_database: str = Field(default="data/mint")
    mint_peg_out_only: bool = Field(default=False)
    mint_max_peg_in: int = Field(default=None)
    mint_max_peg_out: int = Field(default=None)

    mint_lnbits_endpoint: str = Field(default=None)
    mint_lnbits_key: str = Field(default=None)


class MintInformation(CashuSettings):
    mint_info_name: str = Field(default="Cashu mint")
    mint_info_description: str = Field(default=None)
    mint_info_description_long: str = Field(default=None)
    mint_info_contact: List[List[str]] = Field(default=[["", ""]])
    mint_info_nuts: List[str] = Field(default=["NUT-07", "NUT-08", "NUT-09"])
    mint_info_motd: str = Field(default=None)


class WalletSettings(CashuSettings):
    lightning: bool = Field(default=True)
    tor: bool = Field(default=True)
    socks_host: str = Field(default=None)
    socks_port: int = Field(default=9050)
    mint_url: str = Field(default=None)
    mint_host: str = Field(default="8333.space")
    mint_port: int = Field(default=3338)
    wallet_name: str = Field(default="wallet")

    api_port: int = Field(default=4448)
    api_host: str = Field(default="127.0.0.1")

    nostr_private_key: str = Field(default=None)
    nostr_relays: List[str] = Field(
        default=[
            "wss://nostr-pub.wellorder.net",
            "wss://relay.damus.io",
            "wss://nostr.zebedee.cloud",
            "wss://relay.snort.social",
            "wss://nostr.fmt.wiz.biz",
        ]
    )


class Settings(
    EnvSettings, MintSettings, MintInformation, WalletSettings, CashuSettings
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


startup_settings_tasks()
