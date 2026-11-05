import asyncio
from copy import copy
from unittest.mock import AsyncMock

import pytest

from cashu.core.base import (
    Amount,
    MeltQuote,
    MeltQuoteState,
    Method,
    MintQuote,
    MintQuoteState,
    Unit,
)
from cashu.core.errors import (
    LightningError,
    NotAllowedError,
    QuotePendingError,
    TransactionError,
)
from cashu.core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from cashu.core.settings import settings
from cashu.lightning.base import PaymentResult, PaymentStatus, PaymentStatusResult
from cashu.payment import payment_method_registry
from cashu.payment.base import PaymentMethodSettings
from cashu.payment.grpc import payment_processor_pb2 as pb
from cashu.payment.grpc_processor import (
    GrpcPaymentProcessor,
    _identifier_from_json,
    _identifier_to_json,
    _result,
)


def identifier(value="payment"):
    return pb.PaymentIdentifier(type=pb.PAYMENT_IDENTIFIER_TYPE_QUOTE_ID, id=value)


def quote(**updates):
    fields = dict(
        quote="outgoing",
        method="testpay",
        unit="sat",
        amount=8,
        fee_reserve=2,
        state=MeltQuoteState.unpaid,
        request="destination",
        checking_id=_identifier_to_json(identifier()),
    )
    return MeltQuote(**{**fields, **updates})


@pytest.mark.parametrize("value", ["false", "true", 0, 1, None])
def test_transport_requires_boolean(value):
    with pytest.raises(ValueError, match="boolean"):
        GrpcPaymentProcessor("testpay", Unit.sat, {"allow_insecure": value})


@pytest.mark.parametrize("value", [0, -1, float("inf"), float("nan")])
def test_processor_requires_finite_deadlines(value):
    with pytest.raises(ValueError, match="deadlines"):
        GrpcPaymentProcessor("testpay", Unit.sat, {"rpc_timeout": value})


def test_bolt11_capabilities_are_single_use():
    with pytest.raises(ValueError, match="repeated"):
        GrpcPaymentProcessor("bolt11", Unit.sat, {"allows_repeated_payments": True})


def test_processor_factory_creates_independent_instances():
    first = GrpcPaymentProcessor("testpay", Unit.sat, {"endpoint": "first"})
    second = first.create_backend(Unit.usd, {"endpoint": "second"})
    assert second is not first
    assert second.unit == Unit.usd and second.config["endpoint"] == "second"


@pytest.mark.parametrize(
    "state, result",
    [
        (pb.QUOTE_STATE_UNPAID, PaymentResult.PENDING),
        (pb.QUOTE_STATE_FAILED, PaymentResult.FAILED),
        (pb.QUOTE_STATE_UNKNOWN, PaymentResult.ERROR),
    ],
)
def test_processor_state_mapping(state, result):
    assert _result(state) == result


def test_legacy_bolt11_identifier_compatibility():
    value = "ab" * 32
    assert _identifier_from_json(value, bolt11=True).hash == value
    with pytest.raises(ValueError, match="original backend"):
        _identifier_from_json(value)
    with pytest.raises(ValueError, match="invalid payment identifier"):
        _identifier_to_json(pb.PaymentIdentifier())


@pytest.mark.asyncio
async def test_processor_converts_units_and_uses_deadlines():
    processor = GrpcPaymentProcessor(
        "testpay", Unit.sat, {"rpc_timeout": 7, "payment_timeout": 11}
    )
    processor.native_unit = Unit.msat
    processor._stub = stub = AsyncMock()
    stub.GetPaymentQuote.return_value = pb.PaymentQuoteResponse(
        request_identifier=identifier(),
        amount=pb.AmountMessage(value=8000, unit="msat"),
        fee=pb.AmountMessage(value=1501, unit="msat"),
        extra_json='{"fee": "ignored", "merchant": "alice"}',
    )
    priced = await processor.quote_outgoing_payment(
        processor,
        PostMeltQuoteRequest(unit="sat", request="destination", amount=8),
        "outgoing",
    )
    request = stub.GetPaymentQuote.call_args.args[0]
    assert request.unit == "msat" and request.amount.value == 8000
    assert priced.amount == Amount(Unit.sat, 8) and priced.fee == Amount(Unit.sat, 2)
    assert priced.model_extra == {"merchant": "alice"}
    assert stub.GetPaymentQuote.call_args.kwargs["timeout"] == 7
    stub.MakePayment.return_value = pb.MakePaymentResponse(
        status=pb.QUOTE_STATE_PAID,
        total_spent=pb.AmountMessage(value=8000, unit="msat"),
        extra_json='{"result": "ignored", "receipt": "receipt"}',
    )
    paid = await processor.execute_outgoing_payment(
        processor, quote(), Amount(Unit.sat, 2)
    )
    assert paid.settled and paid.fee == Amount(Unit.sat, 0)
    sent = stub.MakePayment.call_args.args[0]
    assert sent.unit == "msat" and sent.payment_options.custom.amount.value == 8000
    assert sent.payment_options.custom.max_fee_amount.value == 2000
    assert stub.MakePayment.call_args.kwargs["timeout"] == 11


@pytest.mark.asyncio
async def test_incoming_payments_are_summed_before_rounding():
    processor = GrpcPaymentProcessor("testpay", Unit.sat, {})
    processor._stub = stub = AsyncMock()
    stub.CheckIncomingPayment.return_value = pb.CheckIncomingPaymentResponse(
        payments=[
            pb.WaitIncomingPaymentResponse(
                payment_amount=pb.AmountMessage(value=n, unit="msat")
            )
            for n in (500, 500)
        ]
    )
    incoming = MintQuote(
        quote="incoming",
        method="testpay",
        request="request",
        checking_id=_identifier_to_json(identifier()),
        unit="sat",
        amount=1,
        state=MintQuoteState.unpaid,
    )
    status = await processor.get_incoming_payment_status(processor, incoming)
    assert status.amount_paid == Amount(Unit.sat, 1) and status.settled
    stub.CheckIncomingPayment.return_value.payments[0].payment_amount.unit = "usd"
    with pytest.raises(ValueError, match="cannot convert"):
        await processor.get_incoming_payment_status(processor, incoming)


@pytest.mark.asyncio
async def test_processor_rejects_unidentified_incoming_payments():
    processor = GrpcPaymentProcessor("testpay", Unit.sat, {})
    processor._stub = stub = AsyncMock()
    stub.CreatePayment.return_value = pb.CreatePaymentResponse(request="request")
    with pytest.raises(ValueError, match="invalid payment identifier"):
        await processor.create_incoming_payment(
            processor, PostMintQuoteRequest(amount=8, unit="sat"), "quote"
        )


def test_amountless_bolt12_rejects_fiat():
    processor = GrpcPaymentProcessor("bolt12", Unit.usd, {})
    with pytest.raises(ValueError, match="sat or msat"):
        processor.amountless_payment_amount(
            PostMeltQuoteRequest(unit="usd", request="offer", amount=8)
        )


@pytest.mark.asyncio
async def test_management_updates_preserve_cumulative_accounting(ledger):
    incoming = MintQuote(
        quote="partial",
        method="testpay",
        request="request",
        checking_id="incoming",
        unit="sat",
        amount=32,
        amount_paid=16,
        amount_issued=8,
        state=MintQuoteState.paid,
    )
    await ledger.crud.store_mint_quote(quote=incoming, db=ledger.db)
    await ledger.db_write._update_mint_quote_state(incoming.quote, MintQuoteState.paid)
    with pytest.raises(TransactionError):
        await ledger.db_write._update_mint_quote_state(
            incoming.quote, MintQuoteState.issued
        )
    stored = await ledger.crud.get_mint_quote(quote_id=incoming.quote, db=ledger.db)
    assert (stored.amount_paid, stored.amount_issued, stored.state) == (
        16,
        8,
        MintQuoteState.paid,
    )


@pytest.mark.asyncio
async def test_reusable_outgoing_quotes_have_independent_execution(ledger):
    first = quote(quote="first", method="bolt12", checking_id="first")
    second = quote(quote="second", method="bolt12", checking_id="second")
    await ledger.db_write._store_melt_quote(first, reusable=True)
    await ledger.db_write._set_melt_quote_pending(first, reusable=True)
    await ledger.db_write._store_melt_quote(second, reusable=True)
    pending = await ledger.db_write._set_melt_quote_pending(second, reusable=True)
    assert pending.pending
    with pytest.raises(QuotePendingError):
        await ledger.db_write._store_melt_quote(
            quote(quote="third", method="bolt12", checking_id="second"), reusable=True
        )


@pytest.mark.asyncio
async def test_long_payment_identities_are_unique_without_blocking_other_rows(ledger):
    incoming = MintQuote(
        quote="first",
        method="testpay",
        request="a" * 8192,
        checking_id="a",
        unit="sat",
        amount=8,
        state=MintQuoteState.unpaid,
    )
    await ledger.crud.store_mint_quote(quote=incoming, db=ledger.db)
    if ledger.db.type == "POSTGRES":
        async with ledger.db.connect() as conn:
            await conn.execute(
                "SELECT quote FROM mint_quotes WHERE quote = 'first' FOR UPDATE"
            )
            await asyncio.wait_for(
                ledger.crud.store_mint_quote(
                    quote=incoming.model_copy(
                        update={
                            "quote": "second",
                            "request": "b" * 8192,
                            "checking_id": "b",
                        }
                    ),
                    db=ledger.db,
                ),
                3,
            )
    results = await asyncio.gather(
        *[
            ledger.crud.store_mint_quote(
                quote=incoming.model_copy(update={"quote": str(i)}), db=ledger.db
            )
            for i in range(4)
        ],
        return_exceptions=True,
    )
    assert all(isinstance(result, LightningError) for result in results)


def test_feature_options_and_limits_are_directional(ledger, monkeypatch):
    monkeypatch.setattr(settings, "mint_max_mint_bolt11_sat", 5)
    backend = ledger.backends[Method.bolt11][Unit.sat]
    monkeypatch.setattr(
        ledger, "backends", {Method.bolt11: {Unit.sat: backend, Unit.msat: backend}}
    )
    info = ledger.create_mint_features()
    assert [entry.max_amount for entry in info[4]["methods"]] == [5, 5000]
    assert all(entry.options is None for entry in info[5]["methods"])


@pytest.mark.asyncio
async def test_method_policy_is_enforced_before_invoice_creation(ledger, monkeypatch):
    plugin = copy(payment_method_registry.get("bolt11"))
    plugin.method = "testpay"
    monkeypatch.setitem(payment_method_registry._plugins, "testpay", plugin)
    monkeypatch.setattr(
        ledger,
        "backends",
        {**ledger.backends, "testpay": ledger.backends[Method.bolt11]},
    )
    monkeypatch.setattr(
        plugin,
        "settings_for",
        lambda backend, unit: PaymentMethodSettings(mint_enabled=False),
    )
    create = AsyncMock()
    monkeypatch.setattr(plugin, "create_incoming_payment", create)
    with pytest.raises(NotAllowedError):
        await ledger.mint_quote(PostMintQuoteRequest(unit="sat", amount=8), "testpay")
    create.assert_not_awaited()


@pytest.mark.asyncio
async def test_payment_events_retry_without_restarting_the_stream(ledger, monkeypatch):
    plugin = payment_method_registry.get("bolt11")
    monkeypatch.setattr(settings, "mint_retry_exponential_backoff_base_delay", 0.01)
    delivered = asyncio.Event()
    opened = 0

    async def stream(backend):
        nonlocal opened
        opened += 1
        yield "incoming"
        await asyncio.Event().wait()

    calls = 0

    async def refresh(*args):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("temporary backend failure")
        delivered.set()

    monkeypatch.setattr(plugin, "incoming_payment_stream", stream)
    monkeypatch.setattr(ledger, "invoice_callback_dispatcher", refresh)
    task = asyncio.create_task(
        ledger.invoice_listener(
            Method.bolt11, Unit.sat, ledger.backends[Method.bolt11][Unit.sat]
        )
    )
    try:
        await asyncio.wait_for(delivered.wait(), 2)
        assert opened == 1 and calls == 2
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("batch", [False, True])
async def test_fixed_method_retains_full_receipts_after_quote_expiry(
    ledger, monkeypatch, batch
):
    from cashu.core.base import BlindedMessage
    from cashu.core.crypto.b_dhke import step1_alice
    from cashu.core.models import PostMintBatchRequest

    plugin = copy(payment_method_registry.get("bolt11"))
    plugin.method = "fixedpay"
    monkeypatch.setitem(payment_method_registry._plugins, "fixedpay", plugin)
    monkeypatch.setattr(
        ledger,
        "backends",
        {**ledger.backends, "fixedpay": ledger.backends[Method.bolt11]},
    )
    monkeypatch.setattr(
        plugin,
        "get_incoming_payment_status",
        AsyncMock(
            return_value=PaymentStatus(
                result=PaymentStatusResult.SETTLED, amount_paid=Amount(Unit.sat, 12)
            )
        ),
    )
    incoming = MintQuote(
        quote="fixed",
        method="fixedpay",
        request="request",
        checking_id="incoming",
        unit="sat",
        amount=8,
        state=MintQuoteState.unpaid,
        expiry=1,
    )
    await ledger.crud.store_mint_quote(quote=incoming, db=ledger.db)
    paid = await ledger.get_mint_quote(incoming.quote, force_backend_check=True)
    assert paid.amount_paid == 12
    outputs = [
        BlindedMessage(
            amount=n, id=ledger.keyset.id, B_=step1_alice(str(n))[0].format().hex()
        )
        for n in (8, 4)
    ]
    promises = (
        (
            await ledger.mint_batch(
                PostMintBatchRequest(quotes=[incoming.quote], outputs=outputs)
            )
        )
        if batch
        else await ledger.mint(quote_id=incoming.quote, outputs=outputs)
    )
    assert sum(p.amount for p in promises) == 12
    monkeypatch.setattr(
        plugin,
        "get_incoming_payment_status",
        AsyncMock(
            return_value=PaymentStatus(
                result=PaymentStatusResult.SETTLED, amount_paid=Amount(Unit.sat, 16)
            )
        ),
    )
    later = await ledger.get_mint_quote(incoming.quote, force_backend_check=True)
    assert later.state == MintQuoteState.issued
    assert (later.amount_paid, later.amount_issued) == (16, 12)


@pytest.mark.asyncio
async def test_issuance_balance_ceiling_is_atomic(ledger, monkeypatch):
    from cashu.core.base import BlindedMessage
    from cashu.core.crypto.b_dhke import step1_alice

    plugin = copy(payment_method_registry.get("bolt11"))
    plugin.method = "fixedpay"
    monkeypatch.setitem(payment_method_registry._plugins, "fixedpay", plugin)
    monkeypatch.setattr(
        ledger,
        "backends",
        {**ledger.backends, "fixedpay": ledger.backends[Method.bolt11]},
    )
    monkeypatch.setattr(
        plugin,
        "get_incoming_payment_status",
        AsyncMock(
            return_value=PaymentStatus(
                result=PaymentStatusResult.SETTLED, amount_paid=Amount(Unit.sat, 8)
            )
        ),
    )
    incoming = MintQuote(
        quote="one",
        method="fixedpay",
        request="one",
        checking_id="one",
        unit="sat",
        amount=8,
        amount_paid=8,
        state=MintQuoteState.paid,
    )
    for name in ("one", "two"):
        await ledger.crud.store_mint_quote(
            quote=incoming.model_copy(
                update={"quote": name, "request": name, "checking_id": name}
            ),
            db=ledger.db,
        )
    monkeypatch.setattr(settings, "mint_max_balance", 8)
    results = await asyncio.gather(
        *[
            ledger.mint(
                quote_id=name,
                outputs=[
                    BlindedMessage(
                        amount=8,
                        id=ledger.keyset.id,
                        B_=step1_alice(name)[0].format().hex(),
                    )
                ],
            )
            for name in ("one", "two")
        ],
        return_exceptions=True,
    )
    assert sum(isinstance(result, list) for result in results) == 1
    assert sum(isinstance(result, NotAllowedError) for result in results) == 1
    balance, _ = await ledger.get_unit_balance_and_fees(Unit.sat, db=ledger.db)
    assert balance.amount == 8


@pytest.mark.asyncio
async def test_offline_audit_corrections_are_explicit_and_preserve_funded_records(
    ledger,
):
    from cashu.mint.payment_audit import audit, repair

    incoming = MintQuote(
        quote="audit",
        method="testpay",
        request="old",
        checking_id="old",
        unit="sat",
        amount=8,
        state=MintQuoteState.unpaid,
    )
    await ledger.crud.store_mint_quote(quote=incoming, db=ledger.db)
    assert not (await audit(ledger.db))["duplicates"]
    await repair(ledger.db, incoming.quote, "checking_id", "old", "correct", False)
    assert (
        await ledger.crud.get_mint_quote(quote_id=incoming.quote, db=ledger.db)
    ).checking_id == "old"
    await repair(ledger.db, incoming.quote, "checking_id", "old", "correct", True)
    assert (
        await ledger.crud.get_mint_quote(checking_id="correct", db=ledger.db)
    ).quote == incoming.quote
    incoming.checking_id = "correct"
    incoming.state = MintQuoteState.paid
    await ledger.crud.update_mint_quote(quote=incoming, db=ledger.db)
    with pytest.raises(ValueError, match="reconciliation"):
        await repair(ledger.db, incoming.quote, "checking_id", "correct", "other", True)


@pytest.mark.asyncio
async def test_protocol_errors_remain_typed(ledger):
    from cashu.core.errors import QuoteAlreadyIssuedError

    with pytest.raises(NotAllowedError) as unsupported:
        payment_method_registry.get("unsupported_method")
    assert unsupported.value.code == 10000
    issued = MintQuote(
        quote="issued",
        method="bolt11",
        request="own-request",
        checking_id="incoming",
        unit="sat",
        amount=8,
        amount_paid=8,
        amount_issued=8,
        state=MintQuoteState.issued,
    )
    with pytest.raises(QuoteAlreadyIssuedError) as already_issued:
        ledger.create_internal_melt_quote(
            issued, PostMeltQuoteRequest(unit="sat", request=issued.request)
        )
    assert already_issued.value.code == 20002


@pytest.mark.asyncio
async def test_batch_limits_apply_to_each_quote(ledger, monkeypatch):
    from cashu.core.base import BlindedMessage
    from cashu.core.crypto.b_dhke import step1_alice
    from cashu.core.models import PostMintBatchRequest

    plugin = copy(payment_method_registry.get("bolt11"))
    plugin.method = "fixedpay"
    monkeypatch.setitem(payment_method_registry._plugins, "fixedpay", plugin)
    monkeypatch.setattr(
        ledger,
        "backends",
        {**ledger.backends, "fixedpay": ledger.backends[Method.bolt11]},
    )
    monkeypatch.setattr(
        plugin,
        "settings_for",
        lambda backend, unit: PaymentMethodSettings(max_amount=8),
    )
    monkeypatch.setattr(
        plugin,
        "get_incoming_payment_status",
        AsyncMock(
            return_value=PaymentStatus(
                result=PaymentStatusResult.SETTLED, amount_paid=Amount(Unit.sat, 8)
            )
        ),
    )
    for name in ("one", "two"):
        await ledger.crud.store_mint_quote(
            quote=MintQuote(
                quote=name,
                method="fixedpay",
                request=name,
                checking_id=name,
                unit="sat",
                amount=8,
                amount_paid=8,
                state=MintQuoteState.paid,
            ),
            db=ledger.db,
        )
    output = BlindedMessage(
        amount=16, id=ledger.keyset.id, B_=step1_alice("batch-limits")[0].format().hex()
    )
    promises = await ledger.mint_batch(
        PostMintBatchRequest(quotes=["one", "two"], outputs=[output])
    )
    assert sum(p.amount for p in promises) == 16
