import json

import pytest
from click.testing import CliRunner

from cashu.core.nuts.nut26 import serialize as nut26_serialize
from cashu.core.nuts.payment_request import NUT10Option, PaymentRequest
from cashu.core.settings import settings
from cashu.wallet.cli.cli import cli
from tests.helpers import is_fake


@pytest.fixture(autouse=True, scope="session")
def cli_prefix():
    return ["--wallet", "test_nut26_cli", "--host", settings.mint_url, "--tests"]


def _extract_json(output: str) -> dict:
    """Extract the first JSON object from CLI output that may include log lines."""
    start = output.index("{")
    return json.loads(output[start:])


def test_decode_nut26_simple(cli_prefix):
    """decode correctly parses a NUT-26 creqB1 string."""
    runner = CliRunner()
    pr = PaymentRequest(a=42, u="sat", d="NUT-26 test")
    creqb = nut26_serialize(pr)
    assert creqb.upper().startswith("CREQB1")

    result = runner.invoke(cli, [*cli_prefix, "decode", creqb])
    assert result.exception is None, f"Exception: {result.exception}"
    out = _extract_json(result.output)
    assert out["a"] == 42
    assert out["u"] == "sat"
    assert out["d"] == "NUT-26 test"


def test_decode_nut26_spec_vector(cli_prefix):
    """decode works with the NUT-26 spec test vector."""
    runner = CliRunner()
    spec_creqb = (
        "CREQB1QYQQWER9D4HNZV3NQGQQSQQQQQQQQQQRAQPSQQGQQSQQZQG9QQVXSAR5WPEN5"
        "TE0D45KUAPWV4UXZMTSD3JJUCM0D5RQQRJRDANXVET9YPCXZ7TDV4H8GXHR3TQ"
    )
    result = runner.invoke(cli, [*cli_prefix, "decode", spec_creqb])
    assert result.exception is None, f"Exception: {result.exception}"
    out = _extract_json(result.output)
    assert out["a"] == 1000
    assert out["u"] == "sat"


def test_decode_nut26_lowercase(cli_prefix):
    """decode handles a lowercase creqb1 string."""
    runner = CliRunner()
    pr = PaymentRequest(a=100, u="sat", d="lowercase test")
    creqb = nut26_serialize(pr).lower()

    result = runner.invoke(cli, [*cli_prefix, "decode", creqb])
    assert result.exception is None, f"Exception: {result.exception}"
    out = _extract_json(result.output)
    assert out["a"] == 100
    assert out["d"] == "lowercase test"


# ─── pay ─────────────────────────────────────────────────────────────
@pytest.mark.skipif(not is_fake, reason="only works with FakeWallet")
def test_pay_nut26_low_balance(mint, cli_prefix):
    """
    pay command parses a NUT-26 creqB1 request and attempts payment.
    Since we have no balance, we expect a 'Balance too low' error which
    proves the request was parsed and the payment path was entered.
    """
    runner = CliRunner()
    pr = PaymentRequest(a=999, u="sat", d="NUT-26 pay test")
    creqb = nut26_serialize(pr)

    result = runner.invoke(cli, [*cli_prefix, "pay", creqb, "-y"])

    print("\n--- NUT-26 PAY OUTPUT ---")
    print(result.output)
    print("------------------------\n")

    # Detected description from the request
    assert "Payment Request: NUT-26 pay test" in result.output
    # Detected amount
    assert "999" in result.output

    # Entered wallet logic → balance check
    if result.exception:
        assert "Balance too low" in str(result.exception)
    else:
        assert "cashuB" in result.output


@pytest.mark.skipif(not is_fake, reason="only works with FakeWallet")
def test_pay_nut26_wrong_mint(mint, cli_prefix):
    """pay rejects a NUT-26 request whose mint list doesn't include our mint."""
    runner = CliRunner()
    pr = PaymentRequest(a=10, u="sat", m=["https://other.mint/"])
    creqb = nut26_serialize(pr)

    result = runner.invoke(cli, [*cli_prefix, "pay", creqb, "-y"])

    assert "Error: Current mint" in result.output
    assert "not accepted" in result.output
    assert "cashuB" not in result.output


@pytest.mark.skipif(not is_fake, reason="only works with FakeWallet")
def test_pay_nut26_unsupported_lock(mint, cli_prefix):
    """pay rejects a NUT-26 request with an unsupported lock kind."""
    runner = CliRunner()
    pr = PaymentRequest(a=10, u="sat", nut10=NUT10Option(k="HTLC", d="hash"))
    creqb = nut26_serialize(pr)

    result = runner.invoke(cli, [*cli_prefix, "pay", creqb, "-y"])

    assert "Unsupported lock kind 'HTLC'" in result.output
    assert "cashuB" not in result.output
