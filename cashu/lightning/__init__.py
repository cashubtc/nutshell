# type: ignore
from ..core.settings import settings
from .blink import BlinkWallet  # noqa: F401
from .corelightningrest import CoreLightningRestWallet  # noqa: F401
from .fake import FakeWallet  # noqa: F401
from .lnbits import LNbitsWallet  # noqa: F401
from .lndrest import LndRestWallet  # noqa: F401
from .strike import StrikeWallet  # noqa: F401

if settings.mint_backend_bolt11_sat is None or settings.mint_backend_bolt11_usd is None:
    raise Exception("MINT_BACKEND_BOLT11_SAT or MINT_BACKEND_BOLT11_USD not set")
