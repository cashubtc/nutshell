import httpx
import pytest
import pytest_asyncio

from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.helpers import pay_if_regtest

BASE_URL = "http://localhost:3337"
invoice_32sat = "lnbc320n1pnsuamsdqqxqrrsssp5w3tlpw2zss396qh28l3a07u35zdx8nmknzryk89ackn23eywdu2spp5ckt298t835ejzh2xepyxlg57f54q27ffc2zjsjh3t5pmx4wghpcqne0vycw5dfalx5y45d2jtwqfwz437hduyccn9nxk2feay0ytxldjpf3fcjrcf5k2s56q3erj86ymlqdp703y89vt4lr4lun5z5duulcqwuwutn"

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
    not settings.mint_redis_cache_enabled,
    reason="settings.mint_redis_cache_enabled is False",
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

@pytest.mark.asyncio
@pytest.mark.skipif(
    not settings.mint_redis_cache_enabled,
    reason="settings.mint_redis_cache_enabled is False",
)
async def test_api_swap_cached_responses(wallet: Wallet):
    quote = await wallet.request_mint(64)
    await pay_if_regtest(quote.bolt11)
    
    minted = await wallet.mint(64, quote.id)
    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10010, 10011)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)
    inputs_payload = [i.dict() for i in minted]
    outputs_payload = [o.dict() for o in outputs]
    response = httpx.post(
        f"{BASE_URL}/v1/swap",
        json={"inputs": inputs_payload, "outputs": outputs_payload},
        timeout=None,
    )
    response1 = httpx.post(
        f"{BASE_URL}/v1/swap",
        json={"inputs": inputs_payload, "outputs": outputs_payload},
        timeout=None,
    )
    assert response.status_code == 200, f"{response.status_code = }"
    assert response1.status_code == 200, f"{response1.status_code = }"
    assert response.text == response1.text

@pytest.mark.asyncio
@pytest.mark.skipif(
    not settings.mint_redis_cache_enabled,
    reason="settings.mint_redis_cache_enabled is False",
)
async def test_api_melt_cached_responses(wallet: Wallet):
    quote = await wallet.request_mint(64)
    melt_quote = await wallet.melt_quote(invoice_32sat)

    await pay_if_regtest(quote.bolt11)
    minted = await wallet.mint(64, quote.id)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10010, 10010)
    outputs, rs = wallet._construct_outputs([32], secrets, rs)

    inputs_payload = [i.dict() for i in minted]
    outputs_payload = [o.dict() for o in outputs]
    response = httpx.post(
        f"{BASE_URL}/v1/melt/bolt11",
        json={"quote": melt_quote.quote, "inputs": inputs_payload, "outputs": outputs_payload},
        timeout=None,
    )
    response1 = httpx.post(
        f"{BASE_URL}/v1/melt/bolt11",
        json={"quote": melt_quote.quote, "inputs": inputs_payload, "outputs": outputs_payload},
        timeout=None,
    )
    assert response.status_code == 200, f"{response.status_code = }"
    assert response1.status_code == 200, f"{response1.status_code = }"
    assert response.text == response1.text