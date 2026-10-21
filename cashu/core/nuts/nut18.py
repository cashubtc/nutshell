import base64

import cbor2

from ..base import PaymentRequest
from .nut26 import deserialize as deserialize_bech32m


def serialize(pr: PaymentRequest) -> str:
    """Serialize to NUT-18 CBOR + base64url format."""
    obj = pr.model_dump(exclude_none=True)
    data = cbor2.dumps(obj)
    encoded = base64.urlsafe_b64encode(data).decode().rstrip("=")
    return "creqA" + encoded


def deserialize(creq: str) -> PaymentRequest:
    """Deserialize a NUT-18 (CBOR) or NUT-26 (Bech32m) payment request."""
    if creq.lower().startswith("creqb1"):
        return deserialize_bech32m(creq)

    if not creq.startswith("creqA"):
        raise ValueError("Invalid prefix, expected 'creqA'")

    data_str = creq[5:]
    # Restore padding if needed
    padded = data_str + "=" * (-len(data_str) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    obj = cbor2.loads(decoded)
    return PaymentRequest(**obj)
