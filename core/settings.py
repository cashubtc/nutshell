from environs import Env  # type: ignore

env = Env()
env.read_env()

DEBUG = env.bool("DEBUG", default=False)

MINT_PRIVATE_KEY = env.str("MINT_PRIVATE_KEY")

MINT_SERVER_HOST = env.str("MINT_SERVER_HOST", default="127.0.0.1")
MINT_SERVER_PORT = env.int("MINT_SERVER_PORT", default=3338)

MINT_HOST = env.str("MINT_HOST", default="127.0.0.1")
MINT_PORT = env.int("MINT_PORT", default=3338)

if MINT_HOST == "127.0.0.1":
    MINT_URL = f"http://{MINT_HOST}:{MINT_PORT}"
else:
    MINT_URL = f"http://{MINT_HOST}:{MINT_PORT}"

LNBITS_ENDPOINT = env.str("LNBITS_ENDPOINT", default=None)
LNBITS_KEY = env.str("LNBITS_KEY", default=None)

MAX_ORDER = 64
