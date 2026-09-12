import base64
from typing import List, Optional

import cbor2

from ..base import PaymentRequest, SupportedMethod, Unit
from ..mint_info import MintInfo
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


def method_fee(
    sm: Optional[List[SupportedMethod]], mint_info: MintInfo, unit: Unit
) -> Optional[int]:
    """
    The fee a payer owes for the methods `sm` requested, which is the lowest `mf`
    among the listed methods `mint_info` can melt in `unit`. Returns 0 when `sm`
    is unset, i.e. the request makes no method requirement, and `None` when the
    mint can melt via none of the listed methods.
    """
    if not sm:
        return 0

    fees = [
        entry.mf or 0 for entry in sm if mint_info.supports_melt_method(entry.mn, unit)
    ]
    return min(fees) if fees else None
