"""Tests for keyset amounts deserialization validation (Issue #928)."""
import json
from unittest.mock import MagicMock

import pytest


def make_keyset_row(**overrides):
    """Create a minimal keyset row dict for testing."""
    defaults = {
        "id": "test_id",
        "derivation_path": "m/0/0/0",
        "seed": "testseed",
        "encrypted_seed": "",
        "seed_encryption_method": "",
        "valid_from": "2024-01-01",
        "valid_to": "2025-01-01",
        "first_seen": "2024-01-01",
        "active": 1,
        "unit": "sat",
        "version": "1.0.0",
        "input_fee_ppk": 0,
        "amounts": json.dumps([1, 2, 4, 8, 16]),
        "balance": 0,
        "fees_paid": 0,
        "final_expiry": None,
    }
    defaults.update(overrides)
    return defaults


class TestAmountsValidation:
    def test_valid_amounts_accepted(self):
        """Valid integer list should pass validation."""
        from cashu.core.base import MintKeyset

        valid = [1, 2, 4, 8, 16, 32, 64]
        result = MintKeyset._validate_amounts(valid)
        assert result == valid

    def test_non_list_rejected(self):
        """Non-list amounts should raise ValueError."""
        from cashu.core.base import MintKeyset

        with pytest.raises(ValueError, match="amounts must be a list"):
            MintKeyset._validate_amounts({"1": 100})

    def test_negative_amounts_rejected(self):
        """Negative amounts should raise ValueError."""
        from cashu.core.base import MintKeyset

        with pytest.raises(ValueError, match="Invalid amount value"):
            MintKeyset._validate_amounts([1, 2, -5])

    def test_non_integer_amounts_rejected(self):
        """Non-integer amounts should raise ValueError."""
        from cashu.core.base import MintKeyset

        with pytest.raises(ValueError, match="Invalid amount value"):
            MintKeyset._validate_amounts([1, 2, "malicious"])

    def test_empty_list_accepted(self):
        """Empty amounts list should be valid."""
        from cashu.core.base import MintKeyset

        result = MintKeyset._validate_amounts([])
        assert result == []

    def test_string_rejected(self):
        """String amounts should raise ValueError."""
        from cashu.core.base import MintKeyset

        with pytest.raises(ValueError, match="amounts must be a list"):
            MintKeyset._validate_amounts("not a list")
