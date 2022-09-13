from environs import Env  # type: ignore

env = Env()
env.read_env()

DEBUG = env.bool("DEBUG", default=False)

MINT_HOST = env.str("MINT_HOST", default="127.0.0.1")
MINT_PORT = env.int("MINT_PORT", default=3338)

MAX_ORDER = 64
