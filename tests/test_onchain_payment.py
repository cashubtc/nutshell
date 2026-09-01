from unittest.mock import AsyncMock, MagicMock

import pytest

from cashu.core.base import Amount, MeltQuote, MintQuote, Unit
from cashu.core.models import PostMintQuoteResponse
from cashu.lightning.base import PaymentResult
from cashu.payment.onchain import (
    BdkOnchainBackend,
    OnchainMeltQuoteRequest,
    OnchainMintQuoteRequest,
    onchain_payment_method,
)

TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon about"
)


@pytest.fixture
def backend(tmp_path, monkeypatch) -> BdkOnchainBackend:
    monkeypatch.setattr("cashu.payment.onchain.bdk.Blockchain", MagicMock)
    return BdkOnchainBackend(
        Unit.sat,
        {
            "mnemonic": TEST_MNEMONIC,
            "database_path": str(tmp_path / "bdk.sqlite"),
        },
    )


def test_onchain_mint_quote_requires_pubkey_and_has_no_amount():
    request = OnchainMintQuoteRequest.model_validate(
        {"unit": "sat", "pubkey": "02" + "01" * 32}
    )

    assert request.amount == 0
    assert "amount" not in request.model_dump()
    with pytest.raises(ValueError):
        OnchainMintQuoteRequest.model_validate({"unit": "sat"})


def test_onchain_melt_quote_requires_amount():
    request = OnchainMeltQuoteRequest(
        unit="sat", request="bcrt1qdestination", amount=123
    )

    assert request.amount == 123


def test_nut30_mint_quote_response_has_no_fixed_amount():
    quote = MintQuote(
        quote="quote",
        method="onchain",
        request="bcrt1qaddress",
        checking_id="bcrt1qaddress",
        unit="sat",
        amount=0,
        state="UNPAID",
        pubkey="02" + "01" * 32,
    )

    response = PostMintQuoteResponse.from_mint_quote(quote).model_dump(
        exclude_none=True
    )

    assert "amount" not in response


@pytest.mark.asyncio
async def test_bdk_receive_status_counts_confirmed_sats(backend, monkeypatch):
    monkeypatch.setattr(backend, "received", AsyncMock(return_value=12345))

    status = await onchain_payment_method.get_incoming_payment_status(
        backend,
        MintQuote(
            quote="quote",
            method="onchain",
            request="bcrt1qtest",
            checking_id="bcrt1qtest",
            unit="sat",
            amount=0,
            state="UNPAID",
            pubkey="02" + "01" * 32,
        ),
    )

    assert status.result == PaymentResult.SETTLED
    assert status.amount_paid == Amount(Unit.sat, 12345)


@pytest.mark.asyncio
async def test_bdk_fee_quote_exposes_nut30_option(backend):
    class FeeRate:
        def as_sat_per_vb(self):
            return 1.0

    class Blockchain:
        def estimate_fee(self, target):
            return FeeRate()

    backend._blockchain = Blockchain()
    address = await backend.new_address()

    reserve, options = await backend.fee_quote(address, 1000)

    assert reserve == 752
    assert options == [{"fee_index": 0, "fee_reserve": 752, "estimated_blocks": 1}]


@pytest.mark.asyncio
async def test_onchain_send_returns_txid_as_payment_proof(backend, monkeypatch):
    monkeypatch.setattr(
        backend,
        "send",
        AsyncMock(return_value=("ab" * 32, 120, "ab" * 32 + ":1")),
    )
    quote = MeltQuote(
        quote="quote",
        method="onchain",
        request="bcrt1qdestination",
        checking_id="bcrt1qdestination",
        unit="sat",
        amount=1000,
        fee_reserve=200,
        state="UNPAID",
    )

    response = await onchain_payment_method.execute_outgoing_payment(
        backend, quote, Amount(Unit.sat, 200)
    )

    assert response.result == PaymentResult.PENDING
    assert response.checking_id == "ab" * 32
    assert response.preimage == "ab" * 32 + ":1"
