import hashlib
from unittest.mock import Mock

import pytest
from coincurve.context import Context
from coincurve.utils import GROUP_ORDER_INT

from cashu.core.crypto.b_dhke import hash_to_curve
from cashu.core.crypto.secp import PrivateKey, PublicKey
from cashu.core.p2bk import ecdh_shared_secret


def scalar_bytes(value: int) -> bytes:
    return value.to_bytes(32, "big")


def mock_masks(monkeypatch, masks):
    """Control fresh keys through Coincurve's public constructor in tests."""
    draw = Mock(side_effect=masks)
    original_init = PrivateKey.__init__

    def init(self, secret=None, *args, **kwargs):
        if secret is None:
            secret = draw()
        original_init(self, secret, *args, **kwargs)

    monkeypatch.setattr(PrivateKey, "__init__", init)
    return draw


@pytest.mark.parametrize("scalar", [1, 2, 1 << 127, 1 << 255, GROUP_ORDER_INT - 1])
def test_masked_multiply_matches_coincurve(scalar):
    point = hash_to_curve(b"masked multiplication test")
    original = point.format()
    key = PrivateKey(scalar_bytes(scalar))
    result = point * key
    assert result.format() == point.multiply(key.secret).format()
    assert point.format() == original
    assert result is not point


def test_masked_multiply_matches_coincurve_for_varied_points():
    for i in range(64):
        point = hash_to_curve(f"masked-point-{i}".encode())
        key = PrivateKey(hashlib.sha256(f"masked-scalar-{i}".encode()).digest())
        assert (point * key).format() == point.multiply(key.secret).format()


def test_masked_multiply_draws_fresh_mask(monkeypatch):
    point = hash_to_curve(b"fresh mask test")
    key = PrivateKey(scalar_bytes(3))
    draws = mock_masks(monkeypatch, [scalar_bytes(7), scalar_bytes(11)])
    first = point * key
    second = point * key
    assert first.format() == second.format() == point.multiply(key.secret).format()
    assert draws.call_count == 2


def test_masked_multiply_retries_invalid_masks_and_zero_sum(monkeypatch):
    point = hash_to_curve(b"mask retry test")
    key = PrivateKey(scalar_bytes(3))
    draws = mock_masks(
        monkeypatch,
        [
            scalar_bytes(0),
            scalar_bytes(GROUP_ORDER_INT),
            scalar_bytes(GROUP_ORDER_INT - 3),
            scalar_bytes(7),
        ],
    )
    assert (point * key).format() == point.multiply(key.secret).format()
    assert draws.call_count == 4


def test_masked_multiply_wraps_scalar_sum(monkeypatch):
    point = hash_to_curve(b"mask wraparound test")
    key = PrivateKey(scalar_bytes(GROUP_ORDER_INT - 1))
    mock_masks(monkeypatch, [scalar_bytes(7)])
    assert (point * key).format() == point.multiply(key.secret).format()


def test_masked_multiply_preserves_inputs_and_context():
    context = Context()
    point = PublicKey(hash_to_curve(b"context test").format(), context)
    key = PrivateKey(scalar_bytes(3))
    original_point = point.format()
    original_secret = key.secret
    original_key_pubkey = key.public_key.format()
    result = point * key
    assert result.format() == point.multiply(key.secret).format()
    assert result.context is context
    assert point.format() == original_point
    assert key.secret == original_secret
    assert key.public_key.format() == original_key_pubkey


@pytest.mark.parametrize("scalar", [None, 3, b"\x03"])
def test_masked_multiply_requires_private_key_before_rng(monkeypatch, scalar):
    point = hash_to_curve(b"invalid scalar type test")
    draws = mock_masks(monkeypatch, AssertionError("must reject before drawing a mask"))
    with pytest.raises(TypeError, match="non privatekey"):
        point * scalar
    draws.assert_not_called()


def test_masked_multiply_rng_failure_does_not_mutate_inputs(monkeypatch):
    point = hash_to_curve(b"rng failure test")
    key = PrivateKey(scalar_bytes(3))
    original_point = point.format()
    original_secret = key.secret
    mock_masks(monkeypatch, OSError("rng failure"))
    with pytest.raises(OSError, match="rng failure"):
        point * key
    assert point.format() == original_point
    assert key.secret == original_secret


def test_p2bk_uses_masked_operator(monkeypatch):
    point = hash_to_curve(b"p2bk masking test")
    key = PrivateKey(scalar_bytes(3))
    expected = point.multiply(key.secret).format()[1:]
    draws = mock_masks(monkeypatch, [scalar_bytes(7)])
    assert ecdh_shared_secret(point, key) == expected
    draws.assert_called_once_with()


def test_coincurve_multiply_keeps_its_original_behavior(monkeypatch):
    point = PrivateKey(scalar_bytes(7)).public_key
    expected = PrivateKey(scalar_bytes(21)).public_key.format()
    draws = mock_masks(monkeypatch, AssertionError("Coincurve must stay unmodified"))
    result = point.multiply(b"\x03", update=True)
    assert result is point
    assert point.format() == expected
    draws.assert_not_called()
