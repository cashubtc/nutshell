import httpx
import pytest
import pytest_asyncio

from cashu.core.nuts import nut20
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.helpers import pay_if_regtest

BASE_URL = "http://localhost:3337"


@pytest_asyncio.fixture(scope="function")
async def wallet(ledger: Ledger):
    wallet1 = await Wallet.with_db(
        url=BASE_URL,
        db="test_data/wallet_mint_api_batch",
        name="wallet_mint_api_batch",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_mint_quote_check(ledger: Ledger, wallet: Wallet):
    mint_quote1 = await wallet.request_mint(64)
    mint_quote2 = await wallet.request_mint(32)

    response = httpx.post(
        f"{BASE_URL}/v1/mint/quote/bolt11/check",
        json={"quotes": [mint_quote1.quote, mint_quote2.quote]},
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    result = response.json()
    assert len(result) == 2
    assert result[0]["quote"] == mint_quote1.quote
    assert result[0]["amount"] == 64
    assert result[0]["state"] == "PAID"
    assert result[1]["quote"] == mint_quote2.quote
    assert result[1]["amount"] == 32
    assert result[1]["state"] == "PAID"


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_mint_batch_success(ledger: Ledger, wallet: Wallet):
    mint_quote1 = await wallet.request_mint(64)
    mint_quote2 = await wallet.request_mint(32)

    await pay_if_regtest(mint_quote1.request)
    await pay_if_regtest(mint_quote2.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    # Output total 96, first quote is 64, second is 32
    outputs, rs = wallet._construct_outputs([64, 32], secrets, rs)
    
    assert mint_quote1.privkey
    assert mint_quote2.privkey
    
    # Signatures covering all outputs
    sig1 = nut20.sign_mint_quote(mint_quote1.quote, outputs, mint_quote1.privkey)
    sig2 = nut20.sign_mint_quote(mint_quote2.quote, outputs, mint_quote2.privkey)

    outputs_payload = [o.model_dump() for o in outputs]

    response = httpx.post(
        f"{BASE_URL}/v1/mint/bolt11/batch",
        json={
            "quotes": [mint_quote1.quote, mint_quote2.quote],
            "quote_amounts": [64, 32],
            "outputs": outputs_payload,
            "signatures": [sig1, sig2],
        },
        timeout=None,
    )
    
    assert response.status_code == 200, f"{response.url} {response.status_code} {response.text}"
    result = response.json()
    assert len(result["signatures"]) == 2
    assert result["signatures"][0]["amount"] == 64
    assert result["signatures"][1]["amount"] == 32


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_mint_batch_duplicate_quotes(ledger: Ledger, wallet: Wallet):
    mint_quote1 = await wallet.request_mint(64)

    response = httpx.post(
        f"{BASE_URL}/v1/mint/bolt11/batch",
        json={
            "quotes": [mint_quote1.quote, mint_quote1.quote],
            "quote_amounts": [64, 64],
            "outputs": [],
            "signatures": [None, None],
        },
    )
    
    assert response.status_code == 400
    assert "quotes must be unique" in response.text


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_mint_batch_wrong_amount(ledger: Ledger, wallet: Wallet):
    mint_quote1 = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote1.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)

    outputs_payload = [o.model_dump() for o in outputs]
    sig1 = nut20.sign_mint_quote(mint_quote1.quote, outputs, mint_quote1.privkey)

    response = httpx.post(
        f"{BASE_URL}/v1/mint/bolt11/batch",
        json={
            "quotes": [mint_quote1.quote],
            "quote_amounts": [32], # Intentionally wrong quote amount
            "outputs": outputs_payload,
            "signatures": [sig1],
        },
    )
    
    assert response.status_code == 400
    assert "does not match quote" in response.text
