# type: ignore
from ..core.settings import settings
from .blink import BlinkWallet  # noqa: F401
from .clnrest import CLNRestWallet  # noqa: F401
from .corelightningrest import CoreLightningRestWallet  # noqa: F401
from .fake import FakeWallet  # noqa: F401
from .lnbits import LNbitsWallet  # noqa: F401
from .lnd_grpc.lnd_grpc import LndRPCWallet  # noqa: F401
from .lndrest import LndRestWallet  # noqa: F401
from .strike import StrikeWallet  # noqa: F401

backend_settings = [
    settings.mint_backend_bolt11_sat,
    settings.mint_backend_bolt11_usd,
    settings.mint_backend_bolt11_eur,
]
if all([s is None for s in backend_settings]):
    raise Exception(
        "MINT_BACKEND_BOLT11_SAT or MINT_BACKEND_BOLT11_USD or MINT_BACKEND_BOLT11_EUR not set"
    )
