"""Opt-in interoperability tests using the released Rust CDK wallet."""

import os
import subprocess
from pathlib import Path

import pytest

from tests.conftest import SERVER_ENDPOINT
from tests.helpers import get_fake_invoice

pytestmark = pytest.mark.skipif(
    os.getenv("CASHU_TEST_CDK") != "1",
    reason="Run explicitly with make test-cdk-wallet (requires Rust)",
)


def test_cdk_wallet():
    subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "--manifest-path",
            str(Path(__file__).with_name("Cargo.toml")),
            "--test",
            "wallet",
            "--",
            "--test-threads=1",
            "--nocapture",
        ],
        env={
            **os.environ,
            "CDK_TEST_MINT_URL": SERVER_ENDPOINT,
            "CDK_TEST_INPUT_FEE_PPK": os.getenv("CDK_TEST_INPUT_FEE_PPK", "100"),
            "CDK_TEST_INVOICE": get_fake_invoice(16, "CDK wallet compatibility"),
        },
        timeout=600,
        check=True,
    )
