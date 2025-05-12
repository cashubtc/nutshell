import json

import pytest
import pytest_asyncio
import respx
from httpx import Request, Response

from cashu.core.base import BlindedSignature
from cashu.core.crypto.b_dhke import hash_to_curve
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import pay_if_regtest


@pytest_asyncio.fixture(scope="function")
async def wallet1(mint):
    wallet1 = await Wallet1.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1",
        name="wallet1",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest.mark.asyncio
async def test_swap_outputs_are_sorted(wallet1: Wallet):
    await wallet1.load_mint()
    mint_quote = await wallet1.request_mint(16)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(16, quote_id=mint_quote.quote, split=[16])
    assert wallet1.balance == 16

    test_url = f"{wallet1.url}/v1/swap"
    key = hash_to_curve("test".encode("utf-8"))
    mock_blind_signature = BlindedSignature(
        id=wallet1.keyset_id,
        amount=8,
        C_=key.serialize().hex(),
    )
    mock_response_data = {"signatures": [mock_blind_signature.dict()]}
    with respx.mock() as mock:
        route = mock.post(test_url).mock(
            return_value=Response(200, json=mock_response_data)
        )
        await wallet1.select_to_send(wallet1.proofs, 5)

        assert route.called
        assert route.call_count == 1
        request: Request = route.calls[0].request
        assert request.method == "POST"
        assert request.url == test_url
        request_data = json.loads(request.content.decode("utf-8"))
        output_amounts = [o["amount"] for o in request_data["outputs"]]
        # assert that output amounts are sorted
        assert output_amounts == sorted(output_amounts)
