import pytest
from cryptography.exceptions import InvalidTag

from cashu.core.nuts.nut342 import decrypt_d_gap, encrypt_d_gap


@pytest.mark.parametrize("d_gap", [0, 1, 2**16, 2**32 - 1])
def test_d_gap_encryption_round_trip(d_gap: int):
    blinding_factor = bytes.fromhex("01" * 32)
    encrypted = encrypt_d_gap(d_gap, blinding_factor)

    assert len(bytes.fromhex(encrypted)) == 32
    assert decrypt_d_gap(encrypted, blinding_factor) == d_gap


def test_d_gap_encryption_uses_random_nonce():
    blinding_factor = bytes.fromhex("02" * 32)
    assert encrypt_d_gap(42, blinding_factor) != encrypt_d_gap(42, blinding_factor)


def test_d_gap_decryption_rejects_wrong_blinding_factor():
    encrypted = encrypt_d_gap(42, bytes.fromhex("03" * 32))
    with pytest.raises(InvalidTag):
        decrypt_d_gap(encrypted, bytes.fromhex("04" * 32))


@pytest.mark.parametrize("d_gap", [-1, 2**32])
def test_d_gap_encryption_rejects_out_of_range(d_gap: int):
    with pytest.raises(ValueError, match="unsigned 32-bit"):
        encrypt_d_gap(d_gap, bytes.fromhex("05" * 32))
