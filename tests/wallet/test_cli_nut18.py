import pytest
from click.testing import CliRunner

from cashu.core.base import NUT10Option, PaymentRequest
from cashu.core.nuts.nut18 import deserialize, serialize
from cashu.core.settings import settings
from cashu.wallet.cli.cli import cli
from tests.helpers import is_fake


@pytest.fixture(autouse=True, scope="session")
def cli_prefix():
    # Use a unique wallet for this test
    return ["--wallet", "test_nut18_cli", "--host", settings.mint_url, "--tests"]


@pytest.mark.skipif(not is_fake, reason="only works with FakeWallet")
def test_pay_nut18_low_balance(mint, cli_prefix):
    """
    Test that the CLI correctly parses a NUT-18 request and attempts to pay it.
    (We expect low balance error since we didn't mint funds, but that proves it parses)
    """
    runner = CliRunner()

    # Create a request for 1337 sats (specific amount to grep)
    pr = PaymentRequest(a=1337, u="sat", d="Test Descr")
    creq = serialize(pr)

    result = runner.invoke(cli, [*cli_prefix, "pay", creq, "-y"])

    print("\n--- OUTPUT ---")
    print(result.output)
    print("--------------\n")

    # Assertions
    # 1. Detected request
    assert "Payment Request: Test Descr" in result.output
    # 2. Detected amount
    assert "1337" in result.output

    # 3. Executed wallet logic (balance check)
    # Since we have 0 balance, send() raises an exception.
    if result.exception:
        assert "Balance too low" in str(result.exception)
    else:
        # If we somehow had funds (e.g. reused wallet), we see a token
        assert "cashuB" in result.output


@pytest.mark.skipif(not is_fake, reason="only works with FakeWallet")
def test_pay_nut18_unsupported_lock(mint, cli_prefix):
    """
    Test that the CLI rejects NUT-18 requests with unsupported lock kinds (safety).
    """
    runner = CliRunner()

    # Request with "HTLC" kind (unsupported by this CLI flow for now)
    pr = PaymentRequest(a=10, u="sat", nut10=NUT10Option(k="HTLC", d="hash"))
    creq = serialize(pr)

    result = runner.invoke(cli, [*cli_prefix, "pay", creq, "-y"])

    assert "Unsupported lock kind 'HTLC'" in result.output
    # Should not print token (no payment made)
    assert "cashuB" not in result.output


@pytest.mark.skipif(not is_fake, reason="only works with FakeWallet")
def test_pay_nut18_wrong_mint(mint, cli_prefix):
    """
    Test that the CLI rejects NUT-18 requests if the current mint is not in the allowed list.
    """
    runner = CliRunner()

    # Request specifying a DIFFERENT mint
    pr = PaymentRequest(a=10, u="sat", m=["https://other.mint/"])
    creq = serialize(pr)

    result = runner.invoke(cli, [*cli_prefix, "pay", creq, "-y"])

    assert "Error: Current mint" in result.output
    assert "not accepted" in result.output
    assert "cashuB" not in result.output


@pytest.mark.skipif(not is_fake, reason="only works with FakeWallet")
def test_pay_nut18_preferred_mint_with_fee_reserve(mint, cli_prefix):
    """A non-strict (ms=False) mint list is accepted and adds the fee reserve."""
    runner = CliRunner()

    pr = PaymentRequest(
        a=10, u="sat", m=["https://other.mint/"], ms=False, fr=5
    )
    creq = serialize(pr)

    result = runner.invoke(cli, [*cli_prefix, "pay", creq, "-y"])

    # The mint outside the preferred list is not rejected ...
    assert "not accepted" not in result.output
    # ... and the fee reserve is added on top of the requested amount.
    assert "Adding fee reserve of 5 sat" in result.output


@pytest.mark.skipif(not is_fake, reason="only works with FakeWallet")
def test_pay_nut18_unsupported_method(mint, cli_prefix):
    """A request whose supported methods exclude bolt11 is rejected."""
    runner = CliRunner()

    pr = PaymentRequest(a=10, u="sat", sm=["bolt12"])
    creq = serialize(pr)

    result = runner.invoke(cli, [*cli_prefix, "pay", creq, "-y"])

    assert "does not support a requested method" in result.output
    assert "cashuB" not in result.output


def _extract_creq(output: str) -> str:
    """Pull the creqA payment request out of CLI output that may include logs."""
    for line in output.splitlines():
        if line.strip().startswith("creqA"):
            return line.strip()
    raise AssertionError(f"No creqA found in output:\n{output}")


@pytest.mark.skipif(not is_fake, reason="only works with FakeWallet")
def test_request_creates_payment_request(mint, cli_prefix):
    """The request command builds a NUT-18 request carrying the new fields."""
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            *cli_prefix, "request", "100",
            "-d", "Coffee",
            "-m", "https://mint.example.com",
            "--preferred",
            "-f", "2",
            "--method", "bolt11",
            "-s",
        ],
    )
    assert result.exception is None, f"Exception: {result.exception}"

    pr = deserialize(_extract_creq(result.output))
    assert pr.a == 100
    assert pr.u == "sat"
    assert pr.d == "Coffee"
    assert pr.m == ["https://mint.example.com"]
    assert pr.ms is False
    assert pr.fr == 2
    assert pr.sm == ["bolt11"]
    assert pr.s is True
