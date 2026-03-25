"""Tests for MeltQuote outputs deserialization validation (Issue #927)."""
import json
from unittest.mock import MagicMock

import pytest


def make_melt_quote_row(**overrides):
    """Create a minimal melt quote row dict for testing."""
    defaults = {
        "quote": "test_quote_id",
        "method": "bolt11",
        "request": "lnbc1...",
        "checking_id": "check_123",
        "unit": "sat",
        "amount": 100,
        "fee_reserve": 10,
        "state": "UNPAID",
        "created_time": 1700000000,
        "paid_time": None,
        "fee_paid": 0,
        "payment_preimage": None,
        "proof": None,
        "outputs": None,
        "expiry": None,
    }
    defaults.update(overrides)

    class FakeRow:
        def __init__(self, data):
            self._data = data
        def __getitem__(self, key):
            return self._data[key]
        def get(self, key, default=None):
            return self._data.get(key, default)
        def keys(self):
            return self._data.keys()

    return FakeRow(defaults)


class TestOutputsValidation:
    def test_valid_outputs_accepted(self):
        from cashu.core.base import MeltQuote

        outputs = [{"amount": 1, "id": "abc", "B_": "deadbeef"}]
        row = make_melt_quote_row(outputs=json.dumps(outputs))
        quote = MeltQuote.from_row(row)
        assert quote.outputs is not None

    def test_null_outputs_accepted(self):
        from cashu.core.base import MeltQuote

        row = make_melt_quote_row(outputs=None)
        quote = MeltQuote.from_row(row)
        assert quote.outputs is None

    def test_invalid_json_outputs_sets_none(self):
        from cashu.core.base import MeltQuote

        row = make_melt_quote_row(outputs="not valid json{{{")
        quote = MeltQuote.from_row(row)
        assert quote.outputs is None

    def test_non_list_outputs_sets_none(self):
        from cashu.core.base import MeltQuote

        row = make_melt_quote_row(outputs=json.dumps({"malicious": True}))
        quote = MeltQuote.from_row(row)
        assert quote.outputs is None

    def test_empty_list_outputs_accepted(self):
        from cashu.core.base import MeltQuote

        row = make_melt_quote_row(outputs=json.dumps([]))
        quote = MeltQuote.from_row(row)
        assert quote.outputs == []
