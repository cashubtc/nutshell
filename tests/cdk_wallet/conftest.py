"""Run the CDK suite against the same mint server used by the Python tests."""

import os

import pytest

from cashu.core.settings import settings
from tests.conftest import start_mint_server


@pytest.fixture(autouse=True, scope="session")
def mint():
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(settings, "mint_backend_bolt11_sat", "FakeWallet")
        patch.setattr(settings, "mint_backend_bolt11_usd", "FakeWallet")
        patch.setattr(
            settings,
            "mint_input_fee_ppk",
            int(os.getenv("CDK_TEST_INPUT_FEE_PPK", "100")),
        )
        # Allow CDK to subscribe before the simulated Lightning payment arrives.
        patch.setattr(settings, "fakewallet_delay_incoming_payment", 1)
        patch.setattr(settings, "fakewallet_delay_outgoing_payment", 0)
        with start_mint_server() as server:
            yield server
