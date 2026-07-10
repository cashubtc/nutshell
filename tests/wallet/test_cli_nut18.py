import pytest
from click.testing import CliRunner

from cashu.core.base import NUT10Option, PaymentRequest, SupportedMethod
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


# ─── Method-fee quadrants ────────────────────────────────────────────
# The method fee applies only when paying from a mint outside the mint
# list, or when no mint list is set at all; when it applies, the payer
# owes the lowest `mf` among the listed methods their mint melts.

@pytest.mark.skipif(not is_fake, reason="only works with FakeWallet")
def test_pay_nut18_mint_in_list_zero_fee_method(mint, cli_prefix):
    """Mint is in the (strict) list; a zero-fee method adds nothing."""
    runner = CliRunner()

    pr = PaymentRequest(
        a=10, u="sat", m=[settings.mint_url], sm=[SupportedMethod(mn="bolt11")]
    )
    creq = serialize(pr)

    result = runner.invoke(cli, [*cli_prefix, "pay", creq, "-y"])

    assert "not accepted" not in result.output
    assert "Adding method fee" not in result.output


@pytest.mark.skipif(not is_fake, reason="only works with FakeWallet")
def test_pay_nut18_mint_in_list_priced_method_no_fee_applied(mint, cli_prefix):
    """Mint is in the list; a priced method's fee does NOT apply (mint ∈ m ⇒ no fee)."""
    runner = CliRunner()

    pr = PaymentRequest(
        a=10,
        u="sat",
        m=[settings.mint_url],
        sm=[SupportedMethod(mn="bolt11", mf=5)],
    )
    creq = serialize(pr)

    result = runner.invoke(cli, [*cli_prefix, "pay", creq, "-y"])

    assert "not accepted" not in result.output
    assert "Adding method fee" not in result.output


@pytest.mark.skipif(not is_fake, reason="only works with FakeWallet")
def test_pay_nut18_mint_outside_preferred_list_zero_fee_method(mint, cli_prefix):
    """Mint outside a preferred list with a zero-fee method: accepted, nothing added."""
    runner = CliRunner()

    pr = PaymentRequest(
        a=10,
        u="sat",
        m=["https://other.mint/"],
        mp=True,
        sm=[SupportedMethod(mn="bolt11")],
    )
    creq = serialize(pr)

    result = runner.invoke(cli, [*cli_prefix, "pay", creq, "-y"])

    assert "not accepted" not in result.output
    assert "Adding method fee" not in result.output


@pytest.mark.skipif(not is_fake, reason="only works with FakeWallet")
def test_pay_nut18_mint_outside_preferred_list_with_method_fee(mint, cli_prefix):
    """Mint outside a preferred list with a priced method: fee is added."""
    runner = CliRunner()

    pr = PaymentRequest(
        a=10,
        u="sat",
        m=["https://other.mint/"],
        mp=True,
        sm=[SupportedMethod(mn="bolt11", mf=5)],
    )
    creq = serialize(pr)

    result = runner.invoke(cli, [*cli_prefix, "pay", creq, "-y"])

    # The mint outside the preferred list is not rejected ...
    assert "not accepted" not in result.output
    # ... and the method fee is added on top of the requested amount.
    assert "Adding method fee of 5 sat" in result.output


@pytest.mark.skipif(not is_fake, reason="only works with FakeWallet")
def test_pay_nut18_unsupported_method(mint, cli_prefix):
    """A request whose supported methods exclude bolt11 is hard-rejected,
    regardless of the mint list."""
    runner = CliRunner()

    pr = PaymentRequest(a=10, u="sat", sm=[SupportedMethod(mn="bolt12")])
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
    assert pr.mp is True
    assert pr.sm == [SupportedMethod(mn="bolt11")]
    assert pr.s is True
