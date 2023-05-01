import asyncio

import pytest
import pytest_asyncio
from httpx import AsyncClient

from cashu.core.settings import settings
from tests.conftest import ledger


@pytest_asyncio.fixture(scope="function")
async def client():
    client = AsyncClient(base_url=f"http://{settings.host}:{settings.port}")
    yield client
    await client.aclose()


@pytest.mark.asyncio
async def test_info(client, ledger):
    response = await client.get("/info")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert response.json()["pubkey"] == ledger.pubkey.serialize().hex()


@pytest.mark.asyncio
async def test_api_keys(client, ledger):
    response = await client.get("/keys")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert response.json() == {
        str(k): v.serialize().hex() for k, v in ledger.keyset.public_keys.items()
    }


@pytest.mark.asyncio
async def test_api_keysets(client, ledger):
    response = await client.get("/keysets")
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert response.json()["keysets"] == list(ledger.keysets.keysets.keys())


@pytest.mark.asyncio
async def test_api_keyset_keys(client, ledger):
    response = await client.get(
        f"/keys/{'1cCNIAZ2X/w1'.replace('/', '_').replace('+', '-')}"
    )
    assert response.status_code == 200, f"{response.url} {response.status_code}"
    assert response.json() == {
        str(k): v.serialize().hex() for k, v in ledger.keyset.public_keys.items()
    }
