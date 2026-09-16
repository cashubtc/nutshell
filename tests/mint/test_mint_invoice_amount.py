import time
from unittest.mock import AsyncMock
from uuid import uuid4

import bolt11
import pytest
import pytest_asyncio
from bolt11.exceptions import Bolt11Exception

from cashu.core.base import Method, MintQuote, MintQuoteState, Unit
from cashu.core.errors import LightningError
from cashu.core.models import PostMintQuoteRequest
from cashu.core.settings import settings
from cashu.lightning.base import InvoiceResponse
from cashu.lightning.fake import FakeWallet
from cashu.mint.ledger import Ledger
from tests.mint.invoice_amount_helpers import issue, make_outputs, unblind_promises


@pytest_asyncio.fixture
async def amount_ledger(ledger: Ledger, monkeypatch):
    monkeypatch.setattr(settings, "fakewallet_brr", False)
    monkeypatch.setattr(
        ledger,
        "backends",
        {
            Method.bolt11: {
                u: FakeWallet(u) for u in (Unit.sat, Unit.msat, Unit.usd, Unit.eur)
            }
        },
    )
    for unit in (Unit.msat, Unit.eur):
        await ledger.activate_keyset(derivation_path=f"m/0'/{unit.value}'/0'")
    return ledger


def invoice_response(amount_msat: int | None) -> InvoiceResponse:
    payment_hash = uuid4().hex * 2
    invoice = bolt11.Bolt11(
        currency="bcrt",
        date=int(time.time()),
        amount_msat=(
            bolt11.MilliSatoshi(amount_msat) if amount_msat is not None else None
        ),
        tags=bolt11.Tags(
            [
                bolt11.Tag(bolt11.TagChar.payment_hash, payment_hash),
                bolt11.Tag(bolt11.TagChar.payment_secret, "22" * 32),
                bolt11.Tag(bolt11.TagChar.description, "invoice amount regression"),
            ]
        ),
    )
    return InvoiceResponse(
        ok=True,
        payment_request=bolt11.encode(invoice, "11" * 32),
        checking_id=payment_hash,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("unit,amount", [(Unit.sat, 2), (Unit.msat, 1001)])
@pytest.mark.parametrize("invoice_amount", [None, 0, "lower", "higher", "malformed"])
async def test_mint_rejects_backend_invoice_before_storing_quote(
    amount_ledger: Ledger, monkeypatch, unit, amount, invoice_amount
):
    expected = amount * 1000 if unit == Unit.sat else amount
    returned = {"lower": expected - 1, "higher": expected + 1}.get(invoice_amount, None)
    response = invoice_response(0 if invoice_amount == 0 else returned)
    if invoice_amount == "malformed":
        response.payment_request = "invalid-bolt11"
    backend = amount_ledger.backends[Method.bolt11][unit]
    monkeypatch.setattr(backend, "create_invoice", AsyncMock(return_value=response))
    store = AsyncMock(wraps=amount_ledger.crud.store_mint_quote)
    events = AsyncMock()
    monkeypatch.setattr(amount_ledger.crud, "store_mint_quote", store)
    monkeypatch.setattr(amount_ledger.events, "submit", events)

    error = Bolt11Exception if invoice_amount == "malformed" else LightningError
    with pytest.raises(error):
        await amount_ledger.mint_quote(
            PostMintQuoteRequest(unit=unit.name, amount=amount)
        )

    store.assert_not_awaited()
    events.assert_not_awaited()
    assert (
        await amount_ledger.crud.get_mint_quote(
            checking_id=response.checking_id, db=amount_ledger.db
        )
        is None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unit,amount",
    [
        (Unit.sat, 2),
        (Unit.msat, 1),
        (Unit.msat, 999),
        (Unit.msat, 1001),
        (Unit.usd, 2),
        (Unit.eur, 2),
    ],
)
@pytest.mark.parametrize("batch", [False, True], ids=["single", "batch"])
async def test_mint_accepts_exact_btc_and_converted_fiat_quotes(
    amount_ledger: Ledger, unit, amount, batch
):
    quote = await amount_ledger.mint_quote(
        PostMintQuoteRequest(unit=unit.name, amount=amount)
    )
    decoded = bolt11.decode(quote.request)
    if unit in (Unit.sat, Unit.msat):
        assert decoded.amount_msat == (amount * 1000 if unit == Unit.sat else amount)
    else:
        assert decoded.amount_msat != amount
    quote.state = MintQuoteState.paid
    await amount_ledger.crud.update_mint_quote(quote=quote, db=amount_ledger.db)
    outputs, secrets = make_outputs(amount_ledger, amount, unit)

    promises = await issue(amount_ledger, [quote], outputs, batch)
    await amount_ledger._verify_inputs(
        unblind_promises(amount_ledger, promises, secrets)
    )

    assert sum(p.amount for p in promises) == amount
    assert (await amount_ledger.get_mint_quote(quote.quote)).issued


@pytest.mark.asyncio
@pytest.mark.parametrize("unit,amount", [(Unit.sat, 2), (Unit.msat, 1001)])
@pytest.mark.parametrize("invoice_amount", [None, 0, "lower", "higher"])
@pytest.mark.parametrize("batch", [False, True], ids=["single", "batch"])
async def test_legacy_mismatched_quote_cannot_issue(
    amount_ledger: Ledger, monkeypatch, unit, amount, invoice_amount, batch
):
    expected = amount * 1000 if unit == Unit.sat else amount
    returned = {"lower": expected - 1, "higher": expected + 1}.get(invoice_amount, None)
    response = invoice_response(0 if invoice_amount == 0 else returned)
    assert response.payment_request and response.checking_id
    quote = MintQuote(
        quote=uuid4().hex,
        method=Method.bolt11.name,
        unit=unit.name,
        amount=amount,
        request=response.payment_request,
        checking_id=response.checking_id,
        state=MintQuoteState.paid,
    )
    await amount_ledger.crud.store_mint_quote(quote=quote, db=amount_ledger.db)
    quotes = [quote]
    if batch:
        valid_quote = await amount_ledger.mint_quote(
            PostMintQuoteRequest(unit=unit.name, amount=amount)
        )
        valid_quote.state = MintQuoteState.paid
        await amount_ledger.crud.update_mint_quote(
            quote=valid_quote, db=amount_ledger.db
        )
        quotes.insert(0, valid_quote)
    outputs, _ = make_outputs(amount_ledger, sum(q.amount for q in quotes), unit)
    sign = AsyncMock(wraps=amount_ledger._sign_blinded_messages)
    monkeypatch.setattr(amount_ledger, "_sign_blinded_messages", sign)

    with pytest.raises(LightningError, match="invoice amount does not match"):
        await issue(amount_ledger, quotes, outputs, batch)

    sign.assert_not_awaited()
    for q in quotes:
        stored = await amount_ledger.get_mint_quote(q.quote)
        assert stored.paid
        assert stored.amount_issued == 0
    restored_outputs, promises = await amount_ledger.restore(outputs)
    assert restored_outputs == []
    assert promises == []
