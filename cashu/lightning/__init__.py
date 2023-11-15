# type: ignore
from ..core.settings import settings
from .fake import FakeWallet  # noqa: F401
from .lnbits import LNbitsWallet  # noqa: F401
from .lndrest import LndRestWallet  # noqa: F401

if settings.mint_lightning_backend is None:
    raise Exception("MINT_LIGHTNING_BACKEND not configured")
