"""Tests for keyset amounts deserialization validation (Issue #928)."""
import json
from unittest.mock import MagicMock, patch

import pytest


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

    def test_parse_amounts_handles_json_decode_error(self):
        """_parse_amounts should fall back to defaults on invalid JSON."""
        from cashu.core.base import MintKeyset

        with patch("cashu.core.base.settings") as mock_settings:
            mock_settings.max_order = 5
            result = MintKeyset._parse_amounts("not valid json{{{")
            assert result == [1, 2, 4, 8, 16]

    def test_parse_amounts_handles_valid_json(self):
        """_parse_amounts should parse valid JSON amounts."""
        from cashu.core.base import MintKeyset

        result = MintKeyset._parse_amounts(json.dumps([1, 2, 4]))
        assert result == [1, 2, 4]
