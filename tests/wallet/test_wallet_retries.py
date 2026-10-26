import json
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio

from cashu.core.base import (
    MeltQuote,
    MeltQuoteState,
    ProofSpentState,
    ProofState,
    Unit,
    WalletKeyset,
)
from cashu.core.crypto.secp import PrivateKey
from cashu.core.models import (
    PostCheckStateResponse,
    PostMeltQuoteResponse,
    PostSwapRequest,
)
from cashu.core.p2pk import P2PKSecret
from cashu.core.secret import Tags
from cashu.wallet.crud import (
    get_bolt11_melt_quote,
    get_proofs,
    store_bolt11_melt_quote,
    store_keyset,
)
from cashu.wallet.errors import MintError
from cashu.wallet.requests import get_pending_request
from cashu.wallet.v1_api import LedgerAPI
from cashu.wallet.wallet import Wallet


async def fund(wallet, ledger, amount):
    secrets, rs, paths = await wallet.generate_n_secrets(1)
    outputs, rs = wallet._construct_outputs([amount], secrets, rs)
    await ledger._store_blinded_messages(outputs)
    promises = await ledger._sign_blinded_messages(outputs)
    return await wallet._construct_proofs(promises, secrets, rs, paths)


@pytest_asyncio.fixture
async def retry_wallet(ledger, tmp_path):
    wallet = await Wallet.with_db(url="http://mint.test", db=str(tmp_path))
    keyset = next(k for k in ledger.keysets.values() if k.unit == Unit.sat and k.active)
    wallet_keyset = WalletKeyset(
        id=keyset.id,
        unit=keyset.unit.name,
        mint_url=wallet.url,
        public_keys=keyset.public_keys,
        active=True,
    )
    await store_keyset(wallet_keyset, db=wallet.db)
    wallet.keysets = {keyset.id: wallet_keyset}
    wallet.keyset_id = keyset.id
    await fund(wallet, ledger, 64)
    yield wallet
    await wallet.db.engine.dispose()


async def restart(wallet):
    restarted = await Wallet.with_db(url=wallet.url, db=wallet.db.db_location)
    await restarted.activate_keyset(wallet.keyset_id)
    await restarted.load_proofs()
    return restarted


@pytest.mark.asyncio
@pytest.mark.parametrize("locked", [False, True])
@pytest.mark.parametrize("cache_expired", [False, True])
async def test_swap_replays_outputs_after_response_loss_and_restart(
    retry_wallet, ledger, monkeypatch, locked, cache_expired
):
    wallet = retry_wallet
    inputs = list(wallet.proofs)
    lock = (
        P2PKSecret(
            kind="P2PK", data=PrivateKey().public_key.format().hex(), tags=Tags()
        )
        if locked
        else None
    )
    calls = []
    cache = {}
    allow_restore = False

    async def swap(self, proofs, outputs):
        payload = PostSwapRequest(inputs=proofs, outputs=outputs).model_dump_json(
            include={
                "inputs": {
                    i: {"id", "amount", "secret", "C", "witness"}
                    for i in range(len(proofs))
                },
                "outputs": ...,
            }
        )
        calls.append(payload)
        if payload not in cache:
            cache[payload] = await ledger.swap(proofs=proofs, outputs=outputs)
        if len(calls) == 1:
            raise httpx.ReadError("response lost after mint committed")
        return cache[payload]

    async def restore(self, outputs):
        return await ledger.restore(outputs) if allow_restore else ([], [])

    monkeypatch.setattr(LedgerAPI, "split", swap)
    monkeypatch.setattr(LedgerAPI, "restore_promises", restore)
    with pytest.raises(httpx.ReadError):
        await wallet.split(inputs, 16, secret_lock=lock)
    assert all(p.reserved for p in await get_proofs(db=wallet.db))

    restarted = await restart(wallet)
    # Another operation advances the counter and changes the wallet's coin mix.
    await fund(restarted, ledger, 8)
    allow_restore = True
    if cache_expired:
        cache.clear()
    keep, send = await restarted.split(inputs, 16, secret_lock=lock)

    assert calls[0] == calls[1]
    assert sum(p.amount for p in keep) == 48
    assert sum(p.amount for p in send) == 16
    assert restarted.balance == 72
    assert len(await restarted.db.fetchall("SELECT * FROM pending_requests")) == 0
    assert not any(p.reserved for p in await get_proofs(db=restarted.db))
    await ledger._verify_inputs(keep + send)
    await restarted.db.engine.dispose()


@pytest.mark.asyncio
async def test_swap_refuses_changed_retry_parameters(retry_wallet, monkeypatch):
    monkeypatch.setattr(
        LedgerAPI, "split", AsyncMock(side_effect=httpx.ReadError("lost"))
    )
    monkeypatch.setattr(LedgerAPI, "restore_promises", AsyncMock(return_value=([], [])))
    inputs = list(retry_wallet.proofs)
    with pytest.raises(httpx.ReadError):
        await retry_wallet.split(inputs, 16)
    with pytest.raises(ValueError, match="original parameters"):
        await retry_wallet.split(inputs, 32)
    assert LedgerAPI.split.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("pending_response", [False, True])
@pytest.mark.parametrize("poll", [False, True])
async def test_melt_recovers_change_after_restart(
    retry_wallet, ledger, monkeypatch, pending_response, poll
):
    wallet = retry_wallet
    inputs = list(wallet.proofs)
    quote = MeltQuote(
        quote="change-quote",
        method="bolt11",
        request="invoice",
        checking_id="payment",
        unit="sat",
        amount=60,
        fee_reserve=4,
        state=MeltQuoteState.unpaid,
        mint=wallet.url,
    )
    await store_bolt11_melt_quote(db=wallet.db, quote=quote)
    calls = []
    paid = None

    async def melt(self, quote_id, proofs, outputs, prefer_async=None):
        nonlocal paid
        calls.append(json.dumps([o.model_dump() for o in outputs], sort_keys=True))
        if paid is None:
            signed = [
                o.model_copy(update={"amount": amount})
                for o, amount in zip(outputs, [2, 1])
            ]
            await ledger._store_blinded_messages(signed)
            change = await ledger._sign_blinded_messages(signed)
            paid = PostMeltQuoteResponse.from_melt_quote(
                quote.model_copy(
                    update={
                        "state": MeltQuoteState.paid,
                        "change": change,
                        "payment_preimage": "preimage",
                    }
                )
            )
            if pending_response:
                return paid.model_copy(update={"state": "PENDING", "change": None})
            raise httpx.ReadError("paid response lost")
        return paid

    monkeypatch.setattr(LedgerAPI, "melt", melt)
    monkeypatch.setattr(
        LedgerAPI,
        "get_melt_quote",
        AsyncMock(side_effect=httpx.ConnectError("offline")),
    )
    if pending_response:
        await wallet.melt(inputs, "invoice", 4, quote.quote)
    else:
        with pytest.raises(Exception, match="paid response lost"):
            await wallet.melt(inputs, "invoice", 4, quote.quote)
    assert await get_pending_request(wallet.db, wallet.url, f"melt:{quote.quote}")
    assert all(p.reserved for p in await get_proofs(db=wallet.db))

    restarted = await restart(wallet)
    await fund(restarted, ledger, 8)
    monkeypatch.setattr(LedgerAPI, "get_melt_quote", AsyncMock(return_value=paid))
    if poll:
        await restarted.get_melt_quote(quote.quote)
    else:
        await restarted.melt(inputs, "invoice", 4, quote.quote)
        assert calls[0] == calls[1]
    assert restarted.balance == 11  # unrelated 8 sat + recovered 3 sat
    stored = await get_bolt11_melt_quote(db=restarted.db, quote=quote.quote)
    assert stored.paid and stored.payment_preimage == "preimage"
    assert stored.fee_paid == 1
    assert [c.amount for c in stored.change] == [2, 1]
    await restarted.get_melt_quote(quote.quote)
    assert restarted.balance == 11
    spent = await get_proofs(db=restarted.db, table="proofs_used")
    assert len(spent) == 1
    assert spent[0].melt_id == quote.quote
    assert (
        await get_pending_request(restarted.db, restarted.url, f"melt:{quote.quote}")
        is None
    )
    await ledger._verify_inputs(restarted.proofs)
    await restarted.db.engine.dispose()


@pytest.mark.asyncio
async def test_swap_completion_rolls_back_and_can_resume(
    retry_wallet, ledger, monkeypatch
):
    import cashu.wallet.wallet as wallet_module

    wallet = retry_wallet
    inputs = list(wallet.proofs)
    calls = 0

    async def swap(self, proofs, outputs):
        nonlocal calls
        calls += 1
        return await ledger.swap(proofs=proofs, outputs=outputs)

    delete = wallet_module.delete_pending_request
    crash = True

    async def interrupted_delete(*args, **kwargs):
        nonlocal crash
        if crash:
            crash = False
            raise RuntimeError("interrupted local commit")
        return await delete(*args, **kwargs)

    monkeypatch.setattr(LedgerAPI, "split", swap)
    monkeypatch.setattr(wallet_module, "delete_pending_request", interrupted_delete)
    with pytest.raises(RuntimeError, match="interrupted local commit"):
        await wallet.split(inputs, 16)
    assert len(await get_proofs(db=wallet.db)) == 1
    assert await get_proofs(db=wallet.db, table="proofs_used") == []
    assert wallet.balance == 64

    restarted = await restart(wallet)
    keep, send = await restarted.split(inputs, 16)
    assert calls == 1  # the saved response survives the interrupted transaction
    assert sum(p.amount for p in keep + send) == 64
    assert len(await get_proofs(db=restarted.db, table="proofs_used")) == 1
    assert not await restarted.db.fetchall("SELECT * FROM pending_requests")
    await restarted.db.engine.dispose()


@pytest.mark.asyncio
async def test_unpaid_quote_does_not_release_an_uncertain_melt(
    retry_wallet, monkeypatch
):
    wallet = retry_wallet
    quote = MeltQuote(
        quote="queued-payment",
        method="bolt11",
        request="invoice",
        checking_id="payment",
        unit="sat",
        amount=60,
        fee_reserve=4,
        state=MeltQuoteState.unpaid,
        mint=wallet.url,
    )
    await store_bolt11_melt_quote(db=wallet.db, quote=quote)
    monkeypatch.setattr(
        LedgerAPI, "melt", AsyncMock(side_effect=httpx.ReadError("queued request"))
    )
    monkeypatch.setattr(
        LedgerAPI,
        "get_melt_quote",
        AsyncMock(return_value=PostMeltQuoteResponse.from_melt_quote(quote)),
    )
    with pytest.raises(Exception, match="queued request"):
        await wallet.melt(list(wallet.proofs), "invoice", 4, quote.quote)
    await wallet.get_melt_quote(quote.quote)
    assert all(p.reserved for p in await get_proofs(db=wallet.db))
    assert await get_pending_request(wallet.db, wallet.url, f"melt:{quote.quote}")


@pytest.mark.asyncio
async def test_explicit_swap_rejection_allows_a_fresh_attempt(
    retry_wallet, ledger, monkeypatch
):
    wallet = retry_wallet
    inputs = list(wallet.proofs)
    monkeypatch.setattr(
        LedgerAPI,
        "check_proof_state",
        AsyncMock(
            return_value=PostCheckStateResponse(
                states=[
                    ProofState(Y=p.Y, state=ProofSpentState.unspent) for p in inputs
                ]
            )
        ),
    )
    monkeypatch.setattr(
        LedgerAPI, "split", AsyncMock(side_effect=MintError("bad witness"))
    )
    monkeypatch.setattr(LedgerAPI, "restore_promises", AsyncMock(return_value=([], [])))
    with pytest.raises(MintError, match="bad witness"):
        await wallet.split(inputs, 16)
    assert wallet.available_balance == 64
    assert not await wallet.db.fetchall("SELECT * FROM pending_requests")

    async def swap(self, proofs, outputs):
        return await ledger.swap(proofs=proofs, outputs=outputs)

    monkeypatch.setattr(LedgerAPI, "split", swap)
    keep, send = await wallet.split(inputs, 32)
    assert sum(p.amount for p in keep + send) == 64
    assert all(any(p is live for live in wallet.proofs) for p in keep + send)


@pytest.mark.asyncio
async def test_swap_rejection_after_timeout_keeps_uncertain_inputs(
    retry_wallet, monkeypatch
):
    wallet = retry_wallet
    inputs = list(wallet.proofs)
    monkeypatch.setattr(
        LedgerAPI,
        "split",
        AsyncMock(
            side_effect=[
                httpx.ReadError("lost"),
                MintError("pending"),
            ]
        ),
    )
    monkeypatch.setattr(LedgerAPI, "restore_promises", AsyncMock(return_value=([], [])))
    with pytest.raises(httpx.ReadError):
        await wallet.split(inputs, 16)
    with pytest.raises(MintError):
        await wallet.split(inputs, 16)
    assert wallet.available_balance == 0
    assert len(await wallet.db.fetchall("SELECT * FROM pending_requests")) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("state", [ProofSpentState.pending, ProofSpentState.spent])
async def test_error_response_does_not_release_committed_inputs(
    retry_wallet, monkeypatch, state
):
    wallet = retry_wallet
    inputs = list(wallet.proofs)
    monkeypatch.setattr(
        LedgerAPI, "split", AsyncMock(side_effect=MintError("backend error"))
    )
    monkeypatch.setattr(LedgerAPI, "restore_promises", AsyncMock(return_value=([], [])))
    monkeypatch.setattr(
        LedgerAPI,
        "check_proof_state",
        AsyncMock(
            return_value=PostCheckStateResponse(
                states=[ProofState(Y=p.Y, state=state) for p in inputs]
            )
        ),
    )
    with pytest.raises(MintError):
        await wallet.split(inputs, 16)
    assert wallet.available_balance == 0
    assert len(await wallet.db.fetchall("SELECT * FROM pending_requests")) == 1
