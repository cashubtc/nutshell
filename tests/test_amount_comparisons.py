import operator
from types import SimpleNamespace

import pytest

from cashu.core.base import Amount, Unit

COMPARISONS = (operator.eq, operator.lt, operator.le, operator.gt, operator.ge)


@pytest.mark.parametrize("as_amount", [False, True])
@pytest.mark.parametrize(
    "value, other", [(0, 0), (42, 0), (42, 41), (42, 42), (42, 43)]
)
@pytest.mark.parametrize("compare", COMPARISONS)
def test_amount_comparisons(as_amount, value, other, compare):
    amount = Amount(Unit.sat, value)
    operand = Amount(Unit.sat, other) if as_amount else other

    assert compare(amount, operand) is compare(value, other)


@pytest.mark.parametrize("compare", COMPARISONS)
@pytest.mark.parametrize("unit", [Unit.msat, Unit.usd])
def test_amount_comparisons_reject_mismatched_units(compare, unit):
    with pytest.raises(Exception, match="^Units must be the same$"):
        compare(Amount(Unit.sat, 42), Amount(unit, 42))


@pytest.mark.parametrize(
    "other", [None, "42", object(), SimpleNamespace(unit=Unit.sat, amount=42)]
)
def test_amount_equality_rejects_unrelated_types(other):
    assert (Amount(Unit.sat, 42) == other) is False
