import pytest
from click.testing import CliRunner

from cashu.core.nuts.nut18 import PaymentRequest
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
    creq = pr.serialize()
    
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
