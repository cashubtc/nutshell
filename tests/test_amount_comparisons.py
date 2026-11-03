import operator
from types import SimpleNamespace

import pytest

from cashu.core.base import Amount, Unit


@pytest.mark.parametrize("as_amount", [False, True])
@pytest.mark.parametrize(
    "other, equal, greater_equal",
    [(0, False, True), (41, False, True), (42, True, True), (43, False, False)],
)
def test_amount_comparisons(as_amount, other, equal, greater_equal):
    amount = Amount(Unit.sat, 42)
    operand = Amount(Unit.sat, other) if as_amount else other

    assert (amount == operand) is equal
    assert (amount >= operand) is greater_equal


@pytest.mark.parametrize("compare", [operator.eq, operator.ge])
@pytest.mark.parametrize("unit", [Unit.msat, Unit.usd])
def test_amount_comparisons_reject_mismatched_units(compare, unit):
    with pytest.raises(Exception, match="^Units must be the same$"):
        compare(Amount(Unit.sat, 42), Amount(unit, 42))


@pytest.mark.parametrize(
    "other", [None, "42", object(), SimpleNamespace(unit=Unit.sat, amount=42)]
)
def test_amount_equality_rejects_unrelated_types(other):
    assert (Amount(Unit.sat, 42) == other) is False


@pytest.mark.parametrize("as_amount", [False, True])
def test_zero_amount_comparisons(as_amount):
    zero = Amount(Unit.sat, 0)
    operand = Amount(Unit.sat, 0) if as_amount else 0

    assert (zero == operand) is True
    assert (zero >= operand) is True
