import json
from typing import Any

import pytest

from cashu.core.errors import TransactionError
from cashu.core.htlc import HTLCSecret
from cashu.core.nuts import nut10
from cashu.core.p2pk import P2PKSecret, SigFlags
from cashu.mint.conditions import LedgerSpendingConditions
from tests.mint.spending_conditions_test_helpers import proof

VALID_PUBKEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
SAME_X_DIFFERENT_PREFIX = "03" + VALID_PUBKEY[2:]
VALID_HTLC_HASH = "11" * 32


@pytest.fixture(autouse=True, scope="session")
def mint():
    # Override the autouse server fixture: these tests are pure validation tests.
    yield


def nut10_secret(
    *,
    kind: str = "P2PK",
    data: str = VALID_PUBKEY,
    tags: list | None = None,
) -> str:
    payload: dict[str, Any] = {"nonce": "n", "data": data}
    if tags is not None:
        payload["tags"] = tags
    return json.dumps([kind, payload])


@pytest.mark.parametrize(
    "raw_secret",
    [
        "ordinary-secret",
        json.dumps("ordinary-secret"),
        json.dumps({"kind": "P2PK"}),
        json.dumps([1, {"data": VALID_PUBKEY}]),
    ],
)
def test_parse_spending_condition_accepts_ordinary_secrets(raw_secret: str):
    assert nut10.parse_spending_condition(raw_secret) is None


def test_parse_spending_condition_returns_typed_conditions():
    p2pk = nut10.parse_spending_condition(nut10_secret())
    htlc = nut10.parse_spending_condition(
        nut10_secret(kind="HTLC", data=VALID_HTLC_HASH)
    )

    assert isinstance(p2pk, P2PKSecret)
    assert isinstance(htlc, HTLCSecret)


@pytest.mark.parametrize(
    ("raw_secret", "error"),
    [
        ('["P2PK",{', "malformed NUT-10 secret"),
        ("['P2PK', {'nonce': 'n'}]", "malformed NUT-10 secret"),
        (json.dumps(["P2PK", {"nonce": "n"}]), "invalid data field"),
        (
            json.dumps(
                [
                    "P2PK",
                    {"nonce": "n", "data": VALID_PUBKEY, "unexpected": "value"},
                ]
            ),
            "unexpected payload field",
        ),
        (nut10_secret(kind="UNKNOWN"), "unsupported NUT-10 secret kind"),
        (
            nut10_secret(tags=[["locktime", 123]]),
            "invalid tag",
        ),
        (nut10_secret(tags=[[]]), "invalid tag"),
        (
            nut10_secret(
                tags=[
                    ["sigflag", SigFlags.SIG_INPUTS.value],
                    ["sigflag", SigFlags.SIG_INPUTS.value],
                ]
            ),
            "duplicate sigflag tag",
        ),
        (nut10_secret(tags=[["sigflag", "UNKNOWN"]]), "malformed NUT-10"),
        (nut10_secret(data="03aaff"), "invalid compressed public key"),
        (
            nut10_secret(data="02" + "ff" * 32),
            "invalid compressed public key",
        ),
        (
            nut10_secret(tags=[["pubkeys", VALID_PUBKEY]]),
            "pubkeys must be unique",
        ),
        (
            nut10_secret(tags=[["pubkeys", SAME_X_DIFFERENT_PREFIX]]),
            "unique x-coordinates",
        ),
        (nut10_secret(tags=[["n_sigs", "0"]]), "positive integer"),
        (nut10_secret(tags=[["n_sigs", "many"]]), "positive integer"),
        (nut10_secret(tags=[["n_sigs", "1_0"]]), "positive integer"),
        (nut10_secret(tags=[["locktime", "+1"]]), "locktime must be an integer"),
        (nut10_secret(tags=[["locktime", "1_0"]]), "locktime must be an integer"),
        (nut10_secret(tags=[["locktime", "١"]]), "locktime must be an integer"),
        (nut10_secret(tags=[["n_sigs", "2"]]), "exceeds available pubkeys"),
        (
            nut10_secret(
                tags=[
                    ["refund", SAME_X_DIFFERENT_PREFIX],
                    ["n_sigs_refund", "2"],
                ]
            ),
            "n_sigs_refund exceeds available pubkeys",
        ),
        (
            nut10_secret(kind="HTLC", data="not-a-hash"),
            "invalid HTLC hash",
        ),
    ],
)
def test_parse_spending_condition_rejects_malformed_candidates(
    raw_secret: str, error: str
):
    with pytest.raises(TransactionError, match=error):
        nut10.parse_spending_condition(raw_secret)


def test_non_numeric_string_locktime_is_rejected():
    with pytest.raises(TransactionError, match="locktime must be an integer"):
        nut10.parse_spending_condition(
            nut10_secret(
                tags=[
                    ["locktime", "not-a-timestamp"],
                    ["refund", SAME_X_DIFFERENT_PREFIX],
                ]
            )
        )


def test_duplicate_json_fields_are_rejected():
    raw_secret = f'["P2PK",{{"nonce":"n","data":"not-a-key","data":"{VALID_PUBKEY}"}}]'

    with pytest.raises(TransactionError, match="duplicate data field"):
        nut10.parse_spending_condition(raw_secret)


def test_mint_dispatch_rejects_malformed_condition_instead_of_downgrading_it():
    malformed = nut10_secret(tags=[["n_sigs", "many"]])

    with pytest.raises(TransactionError, match="positive integer"):
        LedgerSpendingConditions()._verify_input_output_spending_conditions(
            [proof(malformed)],
            [],
        )


def test_mint_dispatch_still_accepts_an_ordinary_secret():
    assert LedgerSpendingConditions()._verify_input_output_spending_conditions(
        [proof("ordinary-secret")],
        [],
    )
