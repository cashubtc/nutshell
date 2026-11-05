import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from cashu.core.base import (
    Amount,
    BlindedMessage,
    MeltQuote,
    MintQuote,
    MintQuoteState,
    Proof,
    ProofSpentState,
    Unit,
)
from cashu.core.crypto.b_dhke import hash_to_curve, step1_alice
from cashu.core.crypto.secp import PrivateKey
from cashu.core.errors import TransactionError
from cashu.core.models import PostMintBatchRequest, PostMintQuoteResponse
from cashu.core.nuts.nut20 import sign_mint_quote
from cashu.core.settings import settings
from cashu.core.split import amount_split
from cashu.lightning.base import PaymentResult, PaymentStatus, PaymentStatusResult
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

    assert request.amount is None
    assert "amount" not in request.model_dump()
    with pytest.raises(ValueError):
        OnchainMintQuoteRequest.model_validate({"unit": "sat"})


def test_onchain_melt_quote_requires_amount():
    request = OnchainMeltQuoteRequest(
        unit="sat", request="bcrt1qdestination", amount=123
    )

    assert request.amount == 123


def test_grpc_onchain_configuration_can_replace_unused_bdk_plugin(tmp_path):
    script = """
from loguru import logger
from cashu.core.base import Unit
from cashu.core.settings import settings

logger.remove()
settings.mint_private_key = "TEST_PRIVATE_KEY"
settings.mint_mnemonic = None
settings.mint_seed_decryption_key = ""
settings.mint_backend_bolt11_sat = "FakeWallet"
settings.mint_backend_bolt11_msat = None
settings.mint_backend_bolt11_usd = None
settings.mint_backend_bolt11_eur = None
settings.mint_payment_method_plugins = []
settings.mint_database = "./mint"
settings.mint_auth_database = "./auth"
settings.mint_payment_backends = [{
    "type": "GrpcPaymentProcessor", "method": "onchain", "unit": "sat",
    "endpoint": "127.0.0.1:50051", "allow_insecure": True,
}]
from cashu.mint.startup import backends
from cashu.payment import payment_method_registry
from cashu.payment.grpc_processor import GrpcPaymentProcessor

backend = backends["onchain"][Unit.sat]
assert isinstance(backend, GrpcPaymentProcessor)
assert payment_method_registry.get("onchain") is backend
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


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

    assert status.result == PaymentStatusResult.SETTLED
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


@pytest.fixture
def onchain(ledger, backend, monkeypatch):
    monkeypatch.setitem(ledger.backends, "onchain", {Unit.sat: backend})
    monkeypatch.setattr(backend, "received", AsyncMock(return_value=0))
    return backend


async def issue(ledger, quote, key, amount, batch=False):
    outputs = [
        BlindedMessage(
            amount=value,
            id=ledger.keyset.id,
            B_=step1_alice(f"{quote.quote}-{amount}-{index}")[0].format().hex(),
        )
        for index, value in enumerate(amount_split(amount))
    ]
    signature = sign_mint_quote(quote.quote, outputs, key.to_hex())
    if batch:
        return await ledger.mint_batch(
            PostMintBatchRequest(
                quotes=[quote.quote],
                quote_amounts=[amount],
                outputs=outputs,
                signatures=[signature],
            ),
            method_str="onchain",
        )
    return await ledger.mint(
        outputs=outputs,
        quote_id=quote.quote,
        signature=signature,
        method_str="onchain",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("batch", [False, True])
async def test_reusable_deposit_quote_issues_only_received_balance(
    ledger, onchain, monkeypatch, batch
):
    monkeypatch.setattr(settings, "mint_quote_ttl", 1)
    key = PrivateKey()
    quote = await ledger.mint_quote(
        OnchainMintQuoteRequest(unit="sat", pubkey=key.public_key.format().hex()),
        method_str="onchain",
    )
    assert quote.amount == 0
    assert quote.expiry is None
    assert PostMintQuoteResponse.from_mint_quote(quote).amount is None

    onchain.received.return_value = 64
    await ledger.get_mint_quote(quote.quote, force_backend_check=True)
    promises = await issue(ledger, quote, key, 16, batch)
    assert sum(p.amount for p in promises) == 16
    partial = await ledger.get_mint_quote(quote.quote, force_backend_check=True)
    assert (partial.amount_paid, partial.amount_issued, partial.state) == (
        64,
        16,
        MintQuoteState.paid,
    )
    await issue(ledger, quote, key, 48, batch)
    assert (await ledger.get_mint_quote(quote.quote, force_backend_check=True)).issued

    onchain.received.return_value = 80
    reopened = await ledger.get_mint_quote(quote.quote, force_backend_check=True)
    assert (reopened.amount_paid, reopened.amount_issued, reopened.state) == (
        80,
        64,
        MintQuoteState.paid,
    )
    await issue(ledger, quote, key, 16, batch)
    final = await ledger.get_mint_quote(quote.quote, force_backend_check=True)
    assert (final.amount_paid, final.amount_issued, final.state) == (
        80,
        80,
        MintQuoteState.issued,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("batch", [False, True])
async def test_onchain_minimum_applies_to_issuance(ledger, onchain, batch):
    key = PrivateKey()
    quote = await ledger.mint_quote(
        OnchainMintQuoteRequest(unit="sat", pubkey=key.public_key.format().hex()),
        method_str="onchain",
    )
    onchain.received.return_value = 8
    onchain.min_amount = 4
    await ledger.get_mint_quote(quote.quote, force_backend_check=True)
    with pytest.raises(TransactionError, match="below minimum"):
        await issue(ledger, quote, key, 2, batch)
    stored = await ledger.crud.get_mint_quote(quote_id=quote.quote, db=ledger.db)
    assert stored.paid
    assert stored.amount_issued == 0


@pytest.mark.asyncio
async def test_internal_payment_credits_a_reusable_address_after_issuance(
    ledger, onchain
):
    key = PrivateKey()
    quote = await ledger.mint_quote(
        OnchainMintQuoteRequest(unit="sat", pubkey=key.public_key.format().hex()),
        method_str="onchain",
    )
    onchain.received.return_value = 16
    await ledger.get_mint_quote(quote.quote, force_backend_check=True)
    await issue(ledger, quote, key, 16)
    response = await ledger.melt_quote(
        OnchainMeltQuoteRequest(unit="sat", request=quote.request, amount=8),
        method_str="onchain",
    )
    assert response.amount == 8
    assert response.fee_reserve == 0
    melt = await ledger.crud.get_melt_quote(quote_id=response.quote, db=ledger.db)
    pending = await ledger.db_write._set_melt_quote_pending(melt)
    await ledger.melt_mint_settle_internally(pending, [])
    refreshed = await ledger.get_mint_quote(quote.quote, force_backend_check=True)
    assert (
        refreshed.amount_paid,
        refreshed.amount_paid_internal,
        refreshed.amount_issued,
    ) == (24, 8, 16)
    await issue(ledger, quote, key, 8)
    assert (await ledger.get_mint_quote(quote.quote, force_backend_check=True)).issued


@pytest.mark.asyncio
async def test_onchain_melt_persists_fee_selection_and_finalizes_after_confirmation(
    ledger, onchain, monkeypatch
):
    destination = await onchain.new_address()
    monkeypatch.setattr(
        onchain,
        "fee_quote",
        AsyncMock(
            return_value=(
                8,
                [
                    {"fee_index": 0, "fee_reserve": 8, "estimated_blocks": 1},
                    {"fee_index": 1, "fee_reserve": 4, "estimated_blocks": 6},
                ],
            )
        ),
    )
    txid, outpoint = "ab" * 32, "ab" * 32 + ":1"
    monkeypatch.setattr(onchain, "send", AsyncMock(return_value=(txid, 3, outpoint)))
    status = AsyncMock(return_value=PaymentStatus(result=PaymentStatusResult.NOT_FOUND))
    monkeypatch.setattr(onchain, "transaction_status", status)
    response = await ledger.melt_quote(
        OnchainMeltQuoteRequest(unit="sat", request=destination, amount=16),
        method_str="onchain",
    )
    secret = "onchain-melt-input"
    proof = Proof(
        amount=32,
        id=ledger.keyset.id,
        secret=secret,
        C=(hash_to_curve(secret.encode()) * ledger.keyset.private_keys[32])
        .format()
        .hex(),
    )
    await ledger.crud.bump_keyset_balance(db=ledger.db, keyset=ledger.keyset, amount=32)
    pending = await ledger.melt(
        proofs=[proof], quote=response.quote, method_str="onchain", fee_index=1
    )
    assert pending.state == "PENDING"
    assert pending.model_extra["outpoint"] == outpoint
    stored = await ledger.crud.get_melt_quote(quote_id=response.quote, db=ledger.db)
    assert stored.checking_id == txid
    assert stored.method_data["selected_fee_index"] == 1
    assert stored.fee_reserve == 4

    assert (await ledger.get_melt_quote(response.quote)).pending
    assert (await ledger.db_read.get_proofs_states([proof.Y]))[
        0
    ].state == ProofSpentState.pending
    status.return_value = PaymentStatus.model_validate(
        {
            "result": PaymentStatusResult.SETTLED,
            "fee": Amount(Unit.sat, 3),
            "preimage": outpoint,
            "outpoint": outpoint,
        }
    )
    settled = await ledger.get_melt_quote(response.quote)
    assert settled.paid
    assert settled.fee_paid == 3
    assert settled.method_data["outpoint"] == outpoint
    assert (await ledger.db_read.get_proofs_states([proof.Y]))[
        0
    ].state == ProofSpentState.spent
