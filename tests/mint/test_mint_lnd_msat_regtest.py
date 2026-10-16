"""Exact msat minting against the LND REST and gRPC regtest CI backends."""

from unittest.mock import AsyncMock
from uuid import uuid4

import bolt11
import pytest
import pytest_asyncio

from cashu.core.base import Amount, Method, MintQuote, MintQuoteState, Unit
from cashu.core.errors import LightningError, QuoteAlreadyIssuedError, QuoteNotPaidError
from cashu.core.models import PostMintQuoteRequest
from cashu.core.settings import settings
from cashu.lightning.base import InvoiceResponse
from cashu.lightning.lnd_grpc.lnd_grpc import LndRPCWallet
from cashu.lightning.lndrest import LndRestWallet
from cashu.mint.ledger import Ledger
from tests.helpers import (
    docker_lightning_cli,
    docker_lightning_mint_cli,
    pay_real_invoice,
    run_cmd_json,
)
from tests.mint.invoice_amount_helpers import issue, make_outputs, unblind_promises

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        settings.mint_backend_bolt11_sat not in {"LndRestWallet", "LndRPCWallet"},
        reason="requires an LND regtest backend",
    ),
]

MSAT_AMOUNTS = [1, 999, 1000, 1001, 1999, 65_537, 1_000_001]


@pytest.fixture(scope="module")
def sub_sat_channel():
    """Allow 1 msat on the existing direct regtest channel, then restore policy."""
    sender = run_cmd_json([*docker_lightning_cli, "getinfo"])["identity_pubkey"]
    receiver = run_cmd_json([*docker_lightning_mint_cli, "getinfo"])["identity_pubkey"]
    channels = run_cmd_json([*docker_lightning_cli, "listchannels"])["channels"]
    channel = next(
        c for c in channels if c["active"] and c["remote_pubkey"] == receiver
    )
    channel_id = channel.get("scid", channel["chan_id"])
    edge = run_cmd_json([*docker_lightning_cli, "getchaninfo", channel_id])
    policy = edge["node1_policy" if edge["node1_pub"] == sender else "node2_policy"]

    def update_minimum(minimum):
        result = run_cmd_json(
            [
                *docker_lightning_cli,
                "updatechanpolicy",
                f"--chan_point={channel['channel_point']}",
                f"--base_fee_msat={policy['fee_base_msat']}",
                f"--fee_rate_ppm={policy['fee_rate_milli_msat']}",
                f"--time_lock_delta={policy['time_lock_delta']}",
                f"--min_htlc_msat={minimum}",
            ]
        )
        assert not result["failed_updates"], result

    update_minimum(1)
    try:
        yield
    finally:
        update_minimum(policy["min_htlc"])


@pytest_asyncio.fixture
async def msat_ledger(ledger: Ledger, monkeypatch, sub_sat_channel):
    backend = type(ledger.backends[Method.bolt11][Unit.sat])(unit=Unit.msat)
    monkeypatch.setattr(
        ledger,
        "backends",
        {Method.bolt11: {**ledger.backends[Method.bolt11], Unit.msat: backend}},
    )
    monkeypatch.setattr(settings, "mint_quote_backend_check_rate_limit", 0)
    await ledger.activate_keyset(derivation_path="m/0'/1'/0'")
    try:
        yield ledger
    finally:
        client = getattr(backend, "client", None)
        if client is not None:
            await client.aclose()


async def pay_and_lookup(request: str) -> dict:
    # Keep subprocess creation on the main thread, as in the other regtests.
    # Forking from a worker thread can deadlock gRPC's fork handlers.
    payment = pay_real_invoice(request)
    assert "SUCCEEDED" in payment, payment
    invoice = run_cmd_json(
        [
            *docker_lightning_mint_cli,
            "lookupinvoice",
            bolt11.decode(request).payment_hash,
        ]
    )
    assert invoice["state"] == "SETTLED"
    return invoice


@pytest.mark.parametrize(
    "unit,amount",
    [(Unit.msat, n) for n in MSAT_AMOUNTS] + [(Unit.sat, 1), (Unit.sat, 123)],
)
async def test_lnd_invoice_collects_exact_amount(msat_ledger: Ledger, unit, amount):
    backend = msat_ledger.backends[Method.bolt11][unit]
    assert isinstance(backend, (LndRestWallet, LndRPCWallet))
    response = await backend.create_invoice(
        Amount(unit, amount), memo="exact invoice amount", expiry=120
    )
    assert response.ok
    assert response.payment_request and response.checking_id
    invoice = bolt11.decode(response.payment_request)
    expected_msat = amount * 1000 if unit == Unit.sat else amount
    assert invoice.amount_msat == expected_msat
    assert invoice.description == "exact invoice amount"
    assert invoice.expiry == 120
    assert invoice.payment_hash == response.checking_id
    assert (await backend.get_invoice_status(response.checking_id)).pending

    settled = await pay_and_lookup(response.payment_request)

    assert int(settled["value_msat"]) == expected_msat
    assert int(settled["amt_paid_msat"]) == expected_msat
    assert (await backend.get_invoice_status(response.checking_id)).settled


@pytest.mark.parametrize("amount", MSAT_AMOUNTS)
async def test_lnd_msat_mint_lifecycle_and_backing(msat_ledger: Ledger, amount):
    quote = await msat_ledger.mint_quote(
        PostMintQuoteRequest(unit="msat", amount=amount)
    )
    assert quote.unpaid
    assert quote.amount == amount
    assert bolt11.decode(quote.request).amount_msat == amount
    outputs, secrets = make_outputs(msat_ledger, amount, Unit.msat)

    with pytest.raises(QuoteNotPaidError):
        await issue(msat_ledger, [quote], outputs, batch=False)
    assert (await msat_ledger.get_mint_quote(quote.quote)).unpaid
    assert await msat_ledger.restore(outputs) == ([], [])

    settled = await pay_and_lookup(quote.request)
    assert (await msat_ledger.get_mint_quote(quote.quote)).paid
    promises = await issue(msat_ledger, [quote], outputs, batch=False)
    proofs = unblind_promises(msat_ledger, promises, secrets)
    await msat_ledger._verify_inputs(proofs)

    assert sum(p.amount for p in proofs) == int(settled["amt_paid_msat"]) == amount
    balance, _ = await msat_ledger.get_unit_balance_and_fees(
        Unit.msat, db=msat_ledger.db
    )
    assert balance == Amount(Unit.msat, amount)
    stored = await msat_ledger.get_mint_quote(quote.quote)
    assert stored.issued
    assert stored.amount_issued == amount
    assert stored.issued_time is not None

    fresh_outputs, _ = make_outputs(msat_ledger, amount, Unit.msat)
    with pytest.raises(QuoteAlreadyIssuedError):
        await issue(msat_ledger, [quote], fresh_outputs, batch=False)
    assert await msat_ledger.restore(fresh_outputs) == ([], [])


async def test_lnd_msat_batch_conserves_sum_of_invoice_payments(msat_ledger: Ledger):
    quotes = [
        await msat_ledger.mint_quote(PostMintQuoteRequest(unit="msat", amount=n))
        for n in (1, 999, 1001, 1999)
    ]
    outputs, secrets = make_outputs(msat_ledger, 4000, Unit.msat)
    collected = 0
    for quote in quotes[:-1]:
        collected += int((await pay_and_lookup(quote.request))["amt_paid_msat"])

    with pytest.raises(QuoteNotPaidError):
        await issue(msat_ledger, quotes, outputs, batch=True)
    assert await msat_ledger.restore(outputs) == ([], [])
    for quote in quotes[:-1]:
        assert (await msat_ledger.get_mint_quote(quote.quote)).paid

    collected += int((await pay_and_lookup(quotes[-1].request))["amt_paid_msat"])
    promises = await issue(msat_ledger, quotes, outputs, batch=True)
    proofs = unblind_promises(msat_ledger, promises, secrets)
    await msat_ledger._verify_inputs(proofs)
    assert sum(p.amount for p in proofs) == collected == 4000
    for quote in quotes:
        stored = await msat_ledger.get_mint_quote(quote.quote)
        assert stored.issued
        assert stored.amount_issued == quote.amount
    balance, _ = await msat_ledger.get_unit_balance_and_fees(
        Unit.msat, db=msat_ledger.db
    )
    assert balance == Amount(Unit.msat, collected)

    fresh_outputs, _ = make_outputs(msat_ledger, collected, Unit.msat)
    with pytest.raises(QuoteAlreadyIssuedError):
        await issue(msat_ledger, quotes, fresh_outputs, batch=True)


@pytest.mark.parametrize("invoice_amount", [0, 1000, 1002])
async def test_lnd_mismatched_invoice_is_not_quoted(
    msat_ledger: Ledger, monkeypatch, invoice_amount
):
    backend = msat_ledger.backends[Method.bolt11][Unit.msat]
    response = await backend.create_invoice(Amount(Unit.msat, invoice_amount))
    assert response.ok
    monkeypatch.setattr(backend, "create_invoice", AsyncMock(return_value=response))
    events = AsyncMock()
    monkeypatch.setattr(msat_ledger.events, "submit", events)

    with pytest.raises(LightningError, match="invoice amount does not match"):
        await msat_ledger.mint_quote(PostMintQuoteRequest(unit="msat", amount=1001))

    assert (
        await msat_ledger.crud.get_mint_quote(
            checking_id=response.checking_id, db=msat_ledger.db
        )
        is None
    )
    events.assert_not_awaited()


@pytest.mark.parametrize("batch", [False, True], ids=["single", "batch"])
@pytest.mark.parametrize("notification", ["poll", "callback"])
async def test_lnd_legacy_underfunded_quote_cannot_issue(
    msat_ledger: Ledger, batch, notification
):
    # Reproduce the old adapter: a 1999 msat quote backed by a 1 sat invoice.
    response: InvoiceResponse = await msat_ledger.backends[Method.bolt11][
        Unit.sat
    ].create_invoice(Amount(Unit.sat, 1))
    assert response.ok and response.payment_request and response.checking_id
    legacy = MintQuote(
        quote=uuid4().hex,
        method="bolt11",
        unit="msat",
        amount=1999,
        request=response.payment_request,
        checking_id=response.checking_id,
        state=MintQuoteState.unpaid,
    )
    await msat_ledger.crud.store_mint_quote(quote=legacy, db=msat_ledger.db)
    assert int((await pay_and_lookup(legacy.request))["amt_paid_msat"]) == 1000
    if notification == "callback":
        await msat_ledger.invoice_callback_dispatcher(legacy.checking_id)
    assert (await msat_ledger.get_mint_quote(legacy.quote)).paid
    quotes = [legacy]
    if batch:
        valid = await msat_ledger.mint_quote(
            PostMintQuoteRequest(unit="msat", amount=1)
        )
        await pay_and_lookup(valid.request)
        quotes.insert(0, valid)
    outputs, _ = make_outputs(msat_ledger, sum(q.amount for q in quotes), Unit.msat)

    with pytest.raises(LightningError, match="invoice amount does not match"):
        await issue(msat_ledger, quotes, outputs, batch)

    for quote in quotes:
        stored = await msat_ledger.get_mint_quote(quote.quote)
        assert stored.paid
        assert stored.amount_issued == 0
    assert await msat_ledger.restore(outputs) == ([], [])
