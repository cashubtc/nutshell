import httpx
import pytest
import pytest_asyncio

from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.helpers import pay_if_regtest

BASE_URL = "http://localhost:3337"


@pytest_asyncio.fixture(scope="function")
async def wallet(ledger: Ledger):
    wallet1 = await Wallet.with_db(
        url=BASE_URL,
        db="test_data/wallet_mint_api",
        name="wallet_mint_api",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest.mark.asyncio
@pytest.mark.skipif(
    not settings.mint_cache_activate,
    reason="settings.mint_cache_activate is not set",
)
async def test_api_mint_cached_responses(wallet: Wallet):
    # Testing mint
    invoice = await wallet.request_mint(64)
    await pay_if_regtest(invoice.bolt11)

    quote_id = invoice.id
    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10010, 10011)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)
    outputs_payload = [o.dict() for o in outputs]
    response = httpx.post(
        f"{BASE_URL}/v1/mint/bolt11",
        json={"quote": quote_id, "outputs": outputs_payload},
        timeout=None,
    )
    response1 = httpx.post(
        f"{BASE_URL}/v1/mint/bolt11",
        json={"quote": quote_id, "outputs": outputs_payload},
        timeout=None,
    )
    assert response.status_code == 200, f"{response.status_code = }"
    assert response1.status_code == 200, f"{response1.status_code = }"
    assert response.text == response1.text
