"""Regression test for the melt "stale FAILED" proof-release race.

Vulnerability (mint loss of funds), fixed by the in-flight guard in the ledger:

`get_melt_quote` runs on the public GET /v1/melt/quote/bolt11/{id} endpoint. For
any PENDING quote it used to ask the backend for the payment status and, on
FAILED, immediately release the proofs via `_finalize_melt_failed` -- with no
knowledge that `_execute_melt_payment` was still running for the same quote.
Because LND tracks payments by payment hash only, a FAILED left over from an
earlier attempt (or reported between MPP sub-attempts) is served while a fresh
payment for the same hash is still in flight. A poller landing in that window
freed the proofs, the attacker re-spent them, the in-flight payment then
settled, and the mint had both paid the invoice AND handed back the ecash.

The fix: `_prepare_melt` records the quote id in `ledger.melt_quotes_in_flight`
for the lifetime of the payment, and status pollers (`get_melt_quote`, the
startup reconciliation) skip backend resolution for quotes in that set. The
executor stays the sole authority over the outcome while it is running.

This test drives the race deterministically with FakeWallet:
  * pay_invoice is slow (delay) and settles  -> the payment is "in flight"
  * get_payment_status returns FAILED         -> the stale status a poller reads
and asserts the proofs are NOT released and cannot be double spent.
"""

import asyncio

import pytest
import pytest_asyncio

from cashu.core.base import MeltQuoteState, Method, Unit
from cashu.core.models import PostMeltQuoteRequest
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import is_regtest

# 62 sat regtest invoice, reused from tests/mint/test_mint_melt.py
INVOICE_62_SAT = "lnbcrt620n1pn0r3vepp5zljn7g09fsyeahl4rnhuy0xax2puhua5r3gspt7ttlfrley6valqdqqcqzzsxqyz5vqsp577h763sel3q06tfnfe75kvwn5pxn344sd5vnays65f9wfgx4fpzq9qxpqysgqg3re9afz9rwwalytec04pdhf9mvh3e2k4r877tw7dr4g0fvzf9sny5nlfggdy6nduy2dytn06w50ls34qfldgsj37x0ymxam0a687mspp0ytr8"


@pytest_asyncio.fixture(scope="function")
async def wallet(ledger: Ledger):
    w = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_stale_failed_race",
        name="wallet_stale_failed_race",
    )
    await w.load_mint()
    yield w


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="deterministic test uses FakeWallet knobs")
async def test_stale_failed_does_not_release_proofs_during_inflight_payment(
    ledger: Ledger, wallet: Wallet, monkeypatch: pytest.MonkeyPatch
):
    # --- fund the attacker wallet with 64 sat -------------------------------
    mint_quote = await wallet.request_mint(64)
    await ledger.get_mint_quote(mint_quote.quote)  # fakewallet: marks it paid
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64
    proofs = wallet.proofs
    proof_Ys = [p.Y for p in proofs]

    # --- create a melt quote for a 62 sat invoice --------------------------
    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=INVOICE_62_SAT)
        )
    ).quote

    backend = ledger.backends[Method.bolt11][Unit.sat]
    balance_before = backend.balance[Unit.sat].amount

    # --- force the race deterministically ----------------------------------
    # pay_invoice: slow + settles => the outgoing payment is "in flight"
    monkeypatch.setattr(settings, "fakewallet_delay_outgoing_payment", 3)
    monkeypatch.setattr(settings, "fakewallet_pay_invoice_state", "SETTLED")
    # get_payment_status: FAILED => the stale status a concurrent poller reads
    monkeypatch.setattr(settings, "fakewallet_payment_state", "FAILED")

    # --- start the honest melt; proofs + quote go PENDING, then pay_invoice
    #     blocks for 3s (the in-flight window) --------------------------------
    melt_task = asyncio.create_task(ledger.melt(proofs=proofs, quote=quote_id))

    # wait until the quote is committed PENDING (i.e. pay_invoice is sleeping)
    for _ in range(100):
        q = await ledger.crud.get_melt_quote(quote_id=quote_id, db=ledger.db)
        if q and q.pending:
            break
        await asyncio.sleep(0.02)
    else:
        melt_task.cancel()
        pytest.fail("melt quote never reached PENDING")

    # the in-flight guard must be armed while the payment executes
    assert quote_id in ledger.melt_quotes_in_flight

    states = await ledger.db_read.get_proofs_states(proof_Ys)
    assert all(s.pending for s in states), "proofs should be pending mid-payment"

    # --- ATTACK: poll the public GET endpoint during the in-flight window --
    attacker_view = await ledger.get_melt_quote(quote_id)
    assert attacker_view.pending, (
        "FIXED: the stale FAILED must be ignored while the payment is in flight;"
        " the quote must stay PENDING"
    )

    states = await ledger.db_read.get_proofs_states(proof_Ys)
    assert all(s.pending for s in states), "proofs must NOT be released to the attacker"

    # --- the attacker tries to re-spend the (still pending) proofs ---------
    secrets, rs, _ = await wallet.generate_n_secrets(len(proofs))
    outputs, rs = wallet._construct_outputs([p.amount for p in proofs], secrets, rs)
    with pytest.raises(Exception):
        await ledger.swap(proofs=proofs, outputs=outputs)

    # --- the honest payment settles normally ------------------------------
    result = await melt_task
    assert result.state == MeltQuoteState.paid.value

    # guard released, proofs consumed exactly once, invoice paid exactly once
    assert quote_id not in ledger.melt_quotes_in_flight
    states = await ledger.db_read.get_proofs_states(proof_Ys)
    assert all(s.spent for s in states), "proofs are spent by the melt, once"
    balance_after = backend.balance[Unit.sat].amount
    assert balance_after == balance_before - 62

    print(
        "\n=== FIX HOLDS ==="
        f"\n  attacker poll saw : {attacker_view.state} (proofs kept locked)"
        f"\n  double-spend swap : rejected"
        f"\n  melt outcome      : {result.state}, backend paid {balance_before - balance_after} sat"
        "\n================="
    )
