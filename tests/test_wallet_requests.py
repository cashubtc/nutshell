import json
from typing import List, Union

import pytest
import pytest_asyncio
import respx
from httpx import Request, Response

from cashu.core.base import BlindedSignature, Proof
from cashu.core.crypto.b_dhke import hash_to_curve
from cashu.core.errors import CashuError
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from cashu.wallet.wallet import Wallet as Wallet2
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import pay_if_regtest


async def assert_err(f, msg: Union[str, CashuError]):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        error_message: str = str(exc.args[0])
        if isinstance(msg, CashuError):
            if msg.detail not in error_message:
                raise Exception(
                    f"CashuError. Expected error: {msg.detail}, got: {error_message}"
                )
            return
        if msg not in error_message:
            raise Exception(f"Expected error: {msg}, got: {error_message}")
        return
    raise Exception(f"Expected error: {msg}, got no error")


async def assert_err_multiple(f, msgs: List[str]):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        for msg in msgs:
            if msg in str(exc.args[0]):
                return
        raise Exception(f"Expected error: {msgs}, got: {exc.args[0]}")
    raise Exception(f"Expected error: {msgs}, got no error")


def assert_amt(proofs: List[Proof], expected: int):
    """Assert amounts the proofs contain."""
    assert sum([p.amount for p in proofs]) == expected


async def reset_wallet_db(wallet: Wallet):
    await wallet.db.execute("DELETE FROM proofs")
    await wallet.db.execute("DELETE FROM proofs_used")
    await wallet.db.execute("DELETE FROM keysets")
    await wallet.load_mint()


@pytest_asyncio.fixture(scope="function")
async def wallet1(mint):
    wallet1 = await Wallet1.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1",
        name="wallet1",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest_asyncio.fixture(scope="function")
async def wallet2():
    wallet2 = await Wallet2.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet2",
        name="wallet2",
    )
    await wallet2.load_mint()
    yield wallet2


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
