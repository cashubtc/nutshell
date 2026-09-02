"""Payment-method plugins used by the mint and wallet.

Implementations register a :class:`PaymentMethodPlugin`; the built-in BOLT11
adapter preserves the existing Lightning backend and wire behavior.
"""

from .base import PaymentMethodPlugin
from .bolt11 import bolt11_payment_method
from .grpc_processor import GrpcPaymentProcessor
from .registry import PaymentMethodRegistry, payment_method_registry

# Built-ins use the same registry as third-party plugins. Importing the payment
# package is therefore sufficient for library users; no mint startup side effect
# is required to make BOLT11 available.
if payment_method_registry.maybe_get(bolt11_payment_method.method) is None:
    payment_method_registry.register(bolt11_payment_method)

__all__ = [
    "PaymentMethodPlugin",
    "PaymentMethodRegistry",
    "GrpcPaymentProcessor",
    "payment_method_registry",
]
