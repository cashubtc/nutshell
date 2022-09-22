from pathlib import Path

from environs import Env  # type: ignore

env = Env()
env.read_env()

DEBUG = env.bool("DEBUG", default=False)
CASHU_DIR = env.str("CASHU_DIR", default="~/.cashu")
CASHU_DIR = CASHU_DIR.replace("~", str(Path.home()))
assert len(CASHU_DIR), "CASHU_DIR not defined"

LIGHTNING = env.bool("LIGHTNING", default=True)
LIGHTNING_FEE_PERCENT = env.float("LIGHTNING_FEE_PERCENT", default=1.0)
assert LIGHTNING_FEE_PERCENT >= 0, "LIGHTNING_FEE_PERCENT must be at least 0"
LIGHTNING_RESERVE_FEE_MIN = env.float("LIGHTNING_RESERVE_FEE_MIN", default=4000)

MINT_PRIVATE_KEY = env.str("MINT_PRIVATE_KEY", default=None)

MINT_SERVER_HOST = env.str("MINT_SERVER_HOST", default="127.0.0.1")
MINT_SERVER_PORT = env.int("MINT_SERVER_PORT", default=3338)

MINT_HOST = env.str("MINT_HOST", default="8333.space")
MINT_PORT = env.int("MINT_PORT", default=3338)

if MINT_HOST in ["localhost", "127.0.0.1"]:
    MINT_URL = f"http://{MINT_HOST}:{MINT_PORT}"
else:
    MINT_URL = f"https://{MINT_HOST}:{MINT_PORT}"

LNBITS_ENDPOINT = env.str("LNBITS_ENDPOINT", default=None)
LNBITS_KEY = env.str("LNBITS_KEY", default=None)

MAX_ORDER = 64
