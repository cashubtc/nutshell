import hashlib
from unittest.mock import Mock

import pytest
from coincurve.context import Context
from coincurve.utils import GROUP_ORDER_INT

from cashu.core.crypto import secp
from cashu.core.crypto.b_dhke import hash_to_curve
from cashu.core.crypto.secp import PrivateKey, PublicKey
from cashu.core.p2bk import ecdh_shared_secret


def scalar_bytes(value: int) -> bytes:
    return value.to_bytes(32, "big")


def raw_multiply(point: PublicKey, scalar: bytes) -> bytes:
    """Unmasked native multiplication, used only as a correctness reference."""
    result = secp.ffi.new("secp256k1_pubkey *", point.public_key[0])
    assert secp.lib.secp256k1_ec_pubkey_tweak_mul(point.context.ctx, result, scalar)
    return PublicKey(result, point.context).format()


@pytest.mark.parametrize("scalar", [1, 2, 1 << 127, 1 << 255, GROUP_ORDER_INT - 1])
def test_masked_multiply_matches_native(scalar):
    point = hash_to_curve(b"masked multiplication test")
    original = point.format()
    result = point.multiply(scalar_bytes(scalar))
    assert result.format() == raw_multiply(point, scalar_bytes(scalar))
    assert point.format() == original
    assert result is not point


def test_masked_multiply_matches_native_for_varied_points():
    for i in range(64):
        point = hash_to_curve(f"masked-point-{i}".encode())
        scalar = hashlib.sha256(f"masked-scalar-{i}".encode()).digest()
        assert point.multiply(scalar).format() == raw_multiply(point, scalar)


def test_masked_multiply_draws_fresh_mask(monkeypatch):
    point = hash_to_curve(b"fresh mask test")
    masks = Mock(side_effect=[scalar_bytes(7), scalar_bytes(11)])
    monkeypatch.setattr(secp.os, "urandom", masks)
    first = point.multiply(scalar_bytes(3))
    second = point.multiply(scalar_bytes(3))
    assert first.format() == second.format() == raw_multiply(point, scalar_bytes(3))
    assert masks.call_count == 2
    masks.assert_called_with(32)


def test_masked_multiply_retries_invalid_masks_and_zero_sum(monkeypatch):
    point = hash_to_curve(b"mask retry test")
    masks = Mock(
        side_effect=[
            scalar_bytes(0),
            scalar_bytes(GROUP_ORDER_INT),
            scalar_bytes(GROUP_ORDER_INT - 3),
            scalar_bytes(7),
        ]
    )
    monkeypatch.setattr(secp.os, "urandom", masks)
    assert point.multiply(scalar_bytes(3)).format() == raw_multiply(
        point, scalar_bytes(3)
    )
    assert masks.call_count == 4


def test_masked_multiply_wraps_scalar_sum(monkeypatch):
    point = hash_to_curve(b"mask wraparound test")
    monkeypatch.setattr(secp.os, "urandom", lambda _: scalar_bytes(7))
    scalar = scalar_bytes(GROUP_ORDER_INT - 1)
    assert point.multiply(scalar).format() == raw_multiply(point, scalar)


def test_masked_multiply_preserves_update_and_context():
    context = Context()
    point = PublicKey(hash_to_curve(b"update test").format(), context)
    expected = raw_multiply(point, scalar_bytes(3))
    result = point.multiply(scalar_bytes(3), update=True)
    assert result is point
    assert point.format() == expected
    assert point.context is context
    assert point.multiply(scalar_bytes(3)).context is context


@pytest.mark.parametrize(
    "scalar",
    [b"", scalar_bytes(0), scalar_bytes(GROUP_ORDER_INT), b"\xff" * 32, b"\x01" * 33],
)
def test_masked_multiply_rejects_invalid_scalar_before_rng(monkeypatch, scalar):
    point = hash_to_curve(b"invalid scalar test")
    original = point.format()
    random_bytes = Mock(side_effect=AssertionError("must reject before drawing a mask"))
    monkeypatch.setattr(secp.os, "urandom", random_bytes)
    with pytest.raises(ValueError):
        point.multiply(scalar, update=True)
    assert point.format() == original
    random_bytes.assert_not_called()


def test_masked_multiply_rng_failure_does_not_mutate_point(monkeypatch):
    point = hash_to_curve(b"rng failure test")
    original = point.format()
    monkeypatch.setattr(secp.os, "urandom", Mock(side_effect=OSError("rng failure")))
    with pytest.raises(OSError, match="rng failure"):
        point.multiply(scalar_bytes(3), update=True)
    assert point.format() == original


def test_short_scalar_operator_and_p2bk_use_masking(monkeypatch):
    point = hash_to_curve(b"entry points test")
    key = PrivateKey(scalar_bytes(3))
    expected = raw_multiply(point, key.secret)
    masks = Mock(side_effect=[scalar_bytes(7), scalar_bytes(11), scalar_bytes(13)])
    monkeypatch.setattr(secp.os, "urandom", masks)
    assert point.multiply(b"\x03").format() == expected
    assert (point * key).format() == expected
    assert ecdh_shared_secret(point, key) == expected[1:]
    assert masks.call_count == 3
