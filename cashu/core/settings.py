import os
import sys
from pathlib import Path
from typing import List, Union

from environs import Env  # type: ignore

env = Env()

# env file: default to current dir, else home dir
ENV_FILE = os.path.join(os.getcwd(), ".env")
if not os.path.isfile(ENV_FILE):
    ENV_FILE = os.path.join(str(Path.home()), ".cashu", ".env")
if os.path.isfile(ENV_FILE):
    env.read_env(ENV_FILE)
else:
    ENV_FILE = ""
    env.read_env(recurse=False)

DEBUG = env.bool("DEBUG", default=False)
if not DEBUG:
    sys.tracebacklimit = 0

CASHU_DIR = env.str("CASHU_DIR", default=os.path.join(str(Path.home()), ".cashu"))
CASHU_DIR = CASHU_DIR.replace("~", str(Path.home()))
assert len(CASHU_DIR), "CASHU_DIR not defined"

TOR = env.bool("TOR", default=True)

SOCKS_HOST = env.str("SOCKS_HOST", default=None)
SOCKS_PORT = env.int("SOCKS_PORT", default=9050)

LIGHTNING = env.bool("LIGHTNING", default=True)
LIGHTNING_FEE_PERCENT = env.float("LIGHTNING_FEE_PERCENT", default=1.0)
assert LIGHTNING_FEE_PERCENT >= 0, "LIGHTNING_FEE_PERCENT must be at least 0"
LIGHTNING_RESERVE_FEE_MIN = env.float("LIGHTNING_RESERVE_FEE_MIN", default=2000)

MINT_PRIVATE_KEY = env.str("MINT_PRIVATE_KEY", default=None)

MINT_SERVER_HOST = env.str("MINT_SERVER_HOST", default="127.0.0.1")
MINT_SERVER_PORT = env.int("MINT_SERVER_PORT", default=3338)

MINT_URL = env.str("MINT_URL", default=None)
MINT_HOST = env.str("MINT_HOST", default="8333.space")
MINT_PORT = env.int("MINT_PORT", default=3338)

MINT_LIGHTNING_BACKEND = env.str("MINT_LIGHTNING_BACKEND", default="FakeWallet")
MINT_DATABASE = env.str("MINT_DATABASE", default="data/mint")

if not MINT_URL:
    if MINT_HOST in ["localhost", "127.0.0.1"]:
        MINT_URL = f"http://{MINT_HOST}:{MINT_PORT}"
    else:
        MINT_URL = f"https://{MINT_HOST}:{MINT_PORT}"

LNBITS_ENDPOINT = env.str("LNBITS_ENDPOINT", default=None)
LNBITS_KEY = env.str("LNBITS_KEY", default=None)

NOSTR_PRIVATE_KEY = env.str("NOSTR_PRIVATE_KEY", default=None)
NOSTR_RELAYS = env.list(
    "NOSTR_RELAYS",
    default=[
        "wss://nostr-pub.wellorder.net",
        "wss://relay.damus.io",
        "wss://nostr.zebedee.cloud",
        "wss://relay.snort.social",
        "wss://nostr.fmt.wiz.biz",
    ],
)

MAX_ORDER = 64
VERSION = "0.9.4"


from pydantic import BaseSettings, Extra, Field, validator


def find_env_file():
    # env file: default to current dir, else home dir
    ENV_FILE = os.path.join(os.getcwd(), ".env")
    if not os.path.isfile(ENV_FILE):
        ENV_FILE = os.path.join(str(Path.home()), ".cashu", ".env")
    if os.path.isfile(ENV_FILE):
        env.read_env(ENV_FILE)
    else:
        ENV_FILE = ""
    return ENV_FILE


class CashuSettings(BaseSettings):
    env_file: str = Field(default=None)
    lightning: bool = Field(default=True)
    lightning_fee_percent: float = Field(default=1.0)
    lightning_reserve_fee_min: int = Field(default=2000)
    max_order: int = Field(default=64)

    class Config:
        env_file = find_env_file()
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = Extra.ignore

        # def __init__(self, env_file=None):
        #     self.env_file = env_file or self.env_file


class EnvSettings(CashuSettings):
    debug: bool = Field(default=False)
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=5000)
    cashu_dir: str = Field(default=os.path.join(str(Path.home()), ".cashu"))


class MintSettings(CashuSettings):
    mint_private_key: str = Field(default=None)
    mint_listen_host: str = Field(default="127.0.0.1")
    mint_listen_port: int = Field(default=3338)
    mint_lightning_backend: str = Field(default="FakeWallet")
    mint_database: str = Field(default="data/mint")

    mint_lnbits_endpoint: str = Field(default=None)
    mint_lnbits_key: str = Field(default=None)


class WalletSettings(CashuSettings):
    lightning: bool = Field(default=True)
    tor: bool = Field(default=True)
    socks_host: str = Field(default=None)
    socks_port: int = Field(default=9050)
    mint_url: str = Field(default=None)
    mint_host: str = Field(default="8333.space")
    mint_port: int = Field(default=3338)

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


class Settings(EnvSettings, MintSettings, WalletSettings, CashuSettings):
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
        if settings.mint_host in ["localhost", "127.0.0.1"]:
            # localhost without https
            settings.mint_url = f"http://{MINT_HOST}:{MINT_PORT}"
        else:
            settings.mint_url = f"https://{MINT_HOST}:{MINT_PORT}"


startup_settings_tasks()
