import asyncio
from typing import List, Tuple

import grpc
import pytest
import pytest_asyncio

from cashu.core.base import (
    Amount,
    MeltQuote,
    MeltQuoteState,
    Method,
    MintQuoteState,
    Proof,
    Unit,
)
from cashu.core.db import Database
from cashu.core.errors import (
    InvoiceAlreadyPaidError,
    LightningPaymentFailedError,
    OutputsAlreadySignedError,
    OutputsArePendingError,
    ProofsArePendingError,
    QuoteAlreadyIssuedError,
    QuotePendingError,
    TransactionError,
)
from cashu.core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from cashu.core.nuts import nut20
from cashu.core.settings import settings
from cashu.lightning.base import (
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    PaymentStatusResult,
)
from cashu.lightning.lnd_grpc import lnd_grpc
from cashu.mint.db.lease import maintain_melt_lease
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    expire_melt_lease,
    get_fake_invoice,
    get_real_invoice,
    is_fake,
    is_regtest,
    pay_if_regtest,
    use_v2_keyset,
)

SEED = "TEST_PRIVATE_KEY"
DERIVATION_PATH = "m/0'/0'/0'"
DECRYPTON_KEY = "testdecryptionkey"
ENCRYPTED_SEED = "U2FsdGVkX1_7UU_-nVBMBWDy_9yDu4KeYb7MH8cJTYQGD4RWl82PALH8j-HKzTrI"


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    with pytest.raises(Exception) as exc:
        await f
    assert str(exc.value) == msg


def assert_amt(proofs: List[Proof], expected: int):
    """Assert amounts the proofs contain."""
    assert [p.amount for p in proofs] == expected



async def melt_signed(ledger, signer_wallet, *, proofs, quote, outputs=None, **kwargs):
    """ledger.melt with client-side nutroot witnesses attached (NUT-10)."""
    quote_obj = await ledger.crud.get_melt_quote(quote_id=quote, db=ledger.db)
    if quote_obj is not None:
        signer_wallet._attach_nutroot_witnesses(
            proofs,
            outputs or [],
            melt_quote_id=quote,
            melt_quote_amount=quote_obj.amount,
        )
    return await ledger.melt(proofs=proofs, quote=quote, outputs=outputs, **kwargs)


@pytest_asyncio.fixture(scope="function")
async def wallet(ledger: Ledger):
    wallet1 = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_mint_melt",
        name="wallet_mint_melt",
    )
    await wallet1.load_mint()
    yield wallet1


async def fund_wallet(ledger: Ledger, wallet: Wallet, amount: int = 64):
    mint_quote = await wallet.request_mint(amount)
    await ledger.get_mint_quote(mint_quote.quote)  # fakewallet: marks it paid
    await wallet.mint(amount, quote_id=mint_quote.quote)
    assert wallet.balance == amount


async def create_pending_melts(
    ledger: Ledger, check_id: str = "checking_id", quote_id: str = "quote_id"
) -> Tuple[Proof, MeltQuote]:
    """Create a pending melt quote and synthetic proofs for payment-state tests."""
    quote = MeltQuote(
        quote=quote_id,
        method="bolt11",
        request=get_fake_invoice(100),
        checking_id=check_id,
        unit="sat",
        state=MeltQuoteState.pending,
        amount=100,
        fee_reserve=1,
    )
    await ledger.crud.store_melt_quote(
        quote=quote,
        db=ledger.db,
    )
    # v3 keysets take point secrets, so the placeholder is a compressed point.
    pending_proof = Proof(
        amount=123,
        C="asdasd",
        secret="02" + "ab" * 32,
        id=ledger.keyset.id,
    )
    await ledger.crud.set_proof_pending(
        db=ledger.db,
        proof=pending_proof,
        quote_id=quote_id,
    )
    # expect a pending melt quote
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert melt_quotes
    return pending_proof, quote


@pytest.mark.asyncio
async def test_finalize_melt_paid_is_idempotent_under_concurrency(
    ledger: Ledger, monkeypatch
):
    from cashu.core.crypto.b_dhke import step1_alice

    quote = MeltQuote(
        quote="concurrent-finalize-quote",
        method=Method.bolt11.name,
        request=get_fake_invoice(10),
        checking_id="concurrent-finalize-checking-id",
        unit=Unit.sat.name,
        state=MeltQuoteState.pending,
        amount=10,
        fee_reserve=6,
    )
    await ledger.crud.store_melt_quote(quote=quote, db=ledger.db)

    proof = Proof(
        amount=16,
        C="concurrent-finalize-proof",
        secret="concurrent-finalize-secret",
        id=ledger.keyset.id,
    )
    await ledger.crud.set_proof_pending(
        proof=proof,
        quote_id=quote.quote,
        db=ledger.db,
    )
    # Model previously issued ecash so the persisted accounting balance stays
    # non-negative while the input proof is pending.
    await ledger.crud.bump_keyset_balance(
        db=ledger.db,
        keyset=ledger.keyset,
        amount=100,
    )
    assert await ledger.crud.try_debit_keyset_balance(
        db=ledger.db,
        keyset=ledger.keyset,
        amount=proof.amount,
    )

    for index in range(3):
        B_, _ = step1_alice(f"concurrent-finalize-change-{index}")
        await ledger.crud.store_blinded_message(
            db=ledger.db,
            amount=1,
            b_=B_.format().hex(),
            id=ledger.keyset.id,
            melt_id=quote.quote,
            order_index=index,
        )

    balance_before, _ = await ledger.crud.get_balance(
        db=ledger.db,
        keyset=ledger.keyset,
    )

    payment_started = asyncio.Event()
    release_payment = asyncio.Event()
    backend = ledger.backends[Method.bolt11][Unit.sat]

    async def delayed_settled_payment(quote: MeltQuote, fee_limit_msat: int):
        payment_started.set()
        await release_payment.wait()
        return PaymentResponse(
            result=PaymentResult.SETTLED,
            checking_id=quote.checking_id,
            fee=Amount(Unit.sat, 1),
            preimage="0" * 64,
        )

    async def settled_payment_status(checking_id: str):
        return PaymentStatus(
            result=PaymentStatusResult.SETTLED,
            fee=Amount(Unit.sat, 1),
            preimage="0" * 64,
        )

    monkeypatch.setattr(backend, "pay_invoice", delayed_settled_payment)
    monkeypatch.setattr(backend, "get_payment_status", settled_payment_status)

    quote = await ledger.db_write.claim_melt_quote_lease(quote)
    assert quote is not None

    payment_task = asyncio.create_task(
        ledger._execute_melt_payment(quote, [proof], outputs=None)
    )
    try:
        await asyncio.wait_for(payment_started.wait(), timeout=10)
        lookup_result = await ledger.get_melt_quote(quote.quote)
    finally:
        release_payment.set()
        # Surface payment failures even if the task never signals that it started.
        payment_result = await asyncio.wait_for(payment_task, timeout=10)
    retry_result = await ledger._finalize_melt_paid(
        quote.quote,
        fee_paid=1,
        preimage="0" * 64,
    )
    stale_failure_result = await ledger._finalize_melt_failed(quote.quote)

    assert lookup_result.pending
    assert payment_result.state == MeltQuoteState.paid.value
    assert stale_failure_result.paid
    assert payment_result.change == retry_result.change == stale_failure_result.change
    assert payment_result.change
    assert sum(promise.amount for promise in payment_result.change) == 5

    persisted = await ledger.get_melt_quote(quote.quote)
    assert persisted.paid
    assert persisted.change == payment_result.change

    pending = await ledger.crud.get_pending_proofs_for_quote(
        quote_id=quote.quote,
        db=ledger.db,
    )
    assert pending == []
    states = await ledger.db_read.get_proofs_states([proof.Y])
    assert states[0].spent

    signed = await ledger.crud.get_blinded_messages_melt_id(
        db=ledger.db,
        melt_id=quote.quote,
        signed=True,
    )
    unsigned = await ledger.crud.get_blinded_messages_melt_id(
        db=ledger.db,
        melt_id=quote.quote,
    )
    assert len(signed) == len(payment_result.change)
    assert unsigned == []

    balance_after, _ = await ledger.crud.get_balance(
        db=ledger.db,
        keyset=ledger.keyset,
    )
    assert balance_after.amount - balance_before.amount == 5


@pytest.mark.asyncio
@pytest.mark.skipif(
    not is_fake,
    reason="only fakewallet",
)
async def test_pending_melt_quote_outputs_registration_regression(
    wallet, ledger: Ledger
):
    """When paying a request results in a PENDING melt quote,
    the change outputs should be registered properly
    and further requests with the same outputs should result in an expected error.
    """
    settings.fakewallet_payment_state = PaymentStatusResult.PENDING.name
    settings.fakewallet_pay_invoice_state = PaymentResult.PENDING.name

    mint_quote1 = await wallet.request_mint(100)
    mint_quote2 = await wallet.request_mint(100)
    # await pay_if_regtest(mint_quote1.request)
    # await pay_if_regtest(mint_quote2.request)

    proofs1 = await wallet.mint(amount=100, quote_id=mint_quote1.quote)
    proofs2 = await wallet.mint(amount=100, quote_id=mint_quote2.quote)

    invoice_64_sat = get_fake_invoice(64)
    invoice_62_sat = get_fake_invoice(62)

    # Get two melt quotes
    melt_quote1 = await wallet.melt_quote(invoice_64_sat)
    melt_quote2 = await wallet.melt_quote(invoice_62_sat)

    n_change_outputs = 7
    (
        change_secrets,
        change_rs,
        change_derivation_paths,
    ) = await wallet.generate_n_secrets(n_change_outputs, skip_bump=True)
    change_outputs, change_rs = wallet._construct_outputs(
        n_change_outputs * [1], change_secrets, change_rs
    )
    response1 = await melt_signed(
        ledger, wallet, proofs=proofs1, quote=melt_quote1.quote, outputs=change_outputs
    )
    assert response1.state == "PENDING"

    await assert_err(
        melt_signed(
            ledger,
            wallet,
            proofs=proofs2,
            quote=melt_quote2.quote,
            outputs=change_outputs,
        ),
        OutputsArePendingError.detail,
    )

    # use get_melt_quote to verify that the quote state is updated
    melt_quote1_updated = await ledger.get_melt_quote(melt_quote1.quote)
    assert melt_quote1_updated.state == MeltQuoteState.pending

    melt_quote2_updated = await ledger.get_melt_quote(melt_quote2.quote)
    assert melt_quote2_updated.state == MeltQuoteState.unpaid


@pytest.mark.asyncio
@pytest.mark.skipif(
    not is_fake,
    reason="only fakewallet",
)
async def test_settled_melt_quote_outputs_registration_regression(
    wallet, ledger: Ledger
):
    """Verify that if one melt request fails, we can still use the same outputs in another request"""

    settings.fakewallet_payment_state = PaymentStatusResult.FAILED.name
    settings.fakewallet_pay_invoice_state = PaymentResult.FAILED.name

    mint_quote1 = await wallet.request_mint(100)
    mint_quote2 = await wallet.request_mint(100)
    # await pay_if_regtest(mint_quote1.request)
    # await pay_if_regtest(mint_quote2.request)

    proofs1 = await wallet.mint(amount=100, quote_id=mint_quote1.quote)
    proofs2 = await wallet.mint(amount=100, quote_id=mint_quote2.quote)

    invoice_64_sat = get_fake_invoice(64)
    invoice_62_sat = get_fake_invoice(62)

    # Get two melt quotes
    melt_quote1 = await wallet.melt_quote(invoice_64_sat)
    melt_quote2 = await wallet.melt_quote(invoice_62_sat)

    n_change_outputs = 7
    (
        change_secrets,
        change_rs,
        change_derivation_paths,
    ) = await wallet.generate_n_secrets(n_change_outputs, skip_bump=True)
    # amount 0 is what wallets send for blank outputs; the mint must accept it
    change_outputs, change_rs = wallet._construct_outputs(
        n_change_outputs * [0], change_secrets, change_rs
    )
    await assert_err(
        melt_signed(ledger, wallet, proofs=proofs1, quote=melt_quote1.quote, outputs=change_outputs),
        "Lightning payment failed.",
    )

    settings.fakewallet_payment_state = PaymentStatusResult.SETTLED.name
    settings.fakewallet_pay_invoice_state = PaymentResult.SETTLED.name

    response2 = await melt_signed(
        ledger,
        wallet,
        proofs=proofs2,
        quote=melt_quote2.quote,
        outputs=change_outputs,
    )

    assert response2.state == "PAID"

    # use get_melt_quote to verify that the quote state is updated
    melt_quote2_updated = await ledger.get_melt_quote(melt_quote2.quote)
    assert melt_quote2_updated.state == MeltQuoteState.paid


@pytest.mark.asyncio
@pytest.mark.skipif(
    not is_fake,
    reason="only fakewallet",
)
async def test_melt_quote_reuse_same_outputs(wallet, ledger: Ledger):
    """Verify that if the same outputs are used in two melt requests,
    the second one fails.
    """

    settings.fakewallet_payment_state = PaymentStatusResult.SETTLED.name
    settings.fakewallet_pay_invoice_state = PaymentResult.SETTLED.name

    mint_quote1 = await wallet.request_mint(100)
    mint_quote2 = await wallet.request_mint(100)
    # await pay_if_regtest(mint_quote1.request)
    # await pay_if_regtest(mint_quote2.request)

    proofs1 = await wallet.mint(amount=100, quote_id=mint_quote1.quote)
    proofs2 = await wallet.mint(amount=100, quote_id=mint_quote2.quote)

    invoice_64_sat = get_fake_invoice(64)
    invoice_62_sat = get_fake_invoice(62)

    # Get two melt quotes
    melt_quote1 = await wallet.melt_quote(invoice_64_sat)
    melt_quote2 = await wallet.melt_quote(invoice_62_sat)

    n_change_outputs = 7
    (
        change_secrets,
        change_rs,
        change_derivation_paths,
    ) = await wallet.generate_n_secrets(n_change_outputs, skip_bump=True)
    change_outputs, change_rs = wallet._construct_outputs(
        n_change_outputs * [1], change_secrets, change_rs
    )
    await melt_signed(
        ledger, wallet, proofs=proofs1, quote=melt_quote1.quote, outputs=change_outputs
    )

    await assert_err(
        melt_signed(
            ledger,
            wallet,
            proofs=proofs2,
            quote=melt_quote2.quote,
            outputs=change_outputs,
        ),
        OutputsAlreadySignedError.detail,
    )


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_fakewallet_pending_quote_get_melt_quote_success(ledger: Ledger):
    """Startup routine test. Expects that a pending proofs are removed form the pending db
    after the startup routine determines that the associated melt quote was paid."""
    pending_proof, quote = await create_pending_melts(ledger)
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending
    settings.fakewallet_payment_state = PaymentStatusResult.SETTLED.name

    # get_melt_quote should check the payment status and update the db
    quote2 = await ledger.get_melt_quote(quote_id=quote.quote)
    assert quote2.state == MeltQuoteState.paid

    # expect that no pending tokens are in db anymore
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert not melt_quotes

    # expect that proofs are spent
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].spent


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_fakewallet_pending_quote_get_melt_quote_pending(ledger: Ledger):
    """Startup routine test. Expects that a pending proofs are removed form the pending db
    after the startup routine determines that the associated melt quote was paid."""
    pending_proof, quote = await create_pending_melts(ledger)
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending
    settings.fakewallet_payment_state = PaymentStatusResult.PENDING.name

    # get_melt_quote should check the payment status and update the db
    quote2 = await ledger.get_melt_quote(quote_id=quote.quote)
    assert quote2.state == MeltQuoteState.pending

    # expect that pending tokens are still in db
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert melt_quotes

    # expect that proofs are pending
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_fakewallet_pending_quote_get_melt_quote_failed(ledger: Ledger):
    """Startup routine test. Expects that a pending proofs are removed form the pending db
    after the startup routine determines that the associated melt quote was paid."""
    pending_proof, quote = await create_pending_melts(ledger)
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending
    settings.fakewallet_payment_state = PaymentStatusResult.FAILED.name

    # get_melt_quote should check the payment status and update the db
    quote2 = await ledger.get_melt_quote(quote_id=quote.quote)
    assert quote2.state == MeltQuoteState.unpaid

    # expect that pending tokens are still in db
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert not melt_quotes

    # expect that proofs are pending
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].unspent


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_fakewallet_pending_quote_get_melt_quote_error(ledger: Ledger):
    """An inconclusive payment status must keep the quote and proofs pending."""
    pending_proof, quote = await create_pending_melts(ledger)
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending
    settings.fakewallet_payment_state = PaymentStatusResult.ERROR.name

    quote2 = await ledger.get_melt_quote(quote_id=quote.quote)
    assert quote2.state == MeltQuoteState.pending

    # Check the pending-state contract for an error response.
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert melt_quotes

    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_fakewallet_pending_quote_get_melt_quote_not_found(ledger: Ledger):
    pending_proof, quote = await create_pending_melts(ledger)
    settings.fakewallet_payment_state = PaymentStatusResult.NOT_FOUND.name

    quote2 = await ledger.get_melt_quote(quote_id=quote.quote)
    assert quote2.state == MeltQuoteState.pending

    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_fakewallet_pending_quote_get_melt_quote_exception(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch
):
    pending_proof, quote = await create_pending_melts(ledger)
    monkeypatch.setattr(settings, "fakewallet_payment_state_exception", True)

    quote2 = await ledger.get_melt_quote(quote_id=quote.quote)
    assert quote2.state == MeltQuoteState.pending

    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending
    assert not ledger.disable_melt


@pytest.mark.asyncio
async def test_execute_melt_failed_payment_uses_settled_status(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch
):
    proof, quote = await create_pending_melts(ledger)
    backend = ledger.backends[Method.bolt11][Unit.sat]

    async def failed_payment(quote: MeltQuote, fee_limit_msat: int):
        return PaymentResponse(
            result=PaymentResult.FAILED,
            checking_id=quote.checking_id,
        )

    async def settled_status(checking_id: str):
        return PaymentStatus(result=PaymentStatusResult.SETTLED)

    monkeypatch.setattr(backend, "pay_invoice", failed_payment)
    monkeypatch.setattr(backend, "get_payment_status", settled_status)

    quote = await ledger.db_write.claim_melt_quote_lease(quote)
    assert quote is not None

    response = await ledger._execute_melt_payment(quote, [proof], outputs=None)
    assert response.state == MeltQuoteState.paid.value
    current = await ledger.crud.get_melt_quote(quote_id=quote.quote, db=ledger.db)
    assert current is not None and not current.locked
    assert current.melt_lock_expires_at == 0

    states = await ledger.db_read.get_proofs_states([proof.Y])
    assert states[0].spent


@pytest.mark.asyncio
@pytest.mark.parametrize("stale_failed", [False, True])
async def test_execute_melt_payment_and_status_exceptions_keep_pending(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch, stale_failed: bool
):
    proof, quote = await create_pending_melts(ledger)
    backend = ledger.backends[Method.bolt11][Unit.sat]

    async def payment_exception(quote: MeltQuote, fee_limit_msat: int):
        raise RuntimeError("payment error")

    async def status_exception(checking_id: str):
        if stale_failed:
            return PaymentStatus(result=PaymentStatusResult.FAILED)
        raise RuntimeError("status error")

    monkeypatch.setattr(backend, "pay_invoice", payment_exception)
    monkeypatch.setattr(backend, "get_payment_status", status_exception)

    quote = await ledger.db_write.claim_melt_quote_lease(quote)
    assert quote is not None

    response = await ledger._execute_melt_payment(quote, [proof], outputs=None)
    assert response.state == MeltQuoteState.pending.value
    current = await ledger.crud.get_melt_quote(quote_id=quote.quote, db=ledger.db)
    assert current is not None and not current.locked
    assert current.melt_lock_expires_at == 0

    states = await ledger.db_read.get_proofs_states([proof.Y])
    assert states[0].pending
    assert not ledger.disable_melt


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_melt_lightning_pay_invoice_settled(ledger: Ledger, wallet: Wallet):
    mint_quote = await wallet.request_mint(64)
    await ledger.get_mint_quote(mint_quote.quote)  # fakewallet: set the quote to paid
    await wallet.mint(64, quote_id=mint_quote.quote)
    invoice_62_sat = get_fake_invoice(62)
    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=invoice_62_sat)
        )
    ).quote
    # quote = await ledger.get_melt_quote(quote_id)
    settings.fakewallet_payment_state = PaymentStatusResult.SETTLED.name
    settings.fakewallet_pay_invoice_state = PaymentResult.SETTLED.name
    melt_response = await melt_signed(ledger, wallet, proofs=wallet.proofs, quote=quote_id)
    assert melt_response.state == MeltQuoteState.paid.value


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_melt_lightning_pay_invoice_failed_failed(ledger: Ledger, wallet: Wallet):
    # Inherited test: it melts without nutroot witnesses, so it belongs on the v2 keyset.
    await use_v2_keyset(wallet)
    mint_quote = await wallet.request_mint(64)
    await ledger.get_mint_quote(mint_quote.quote)  # fakewallet: set the quote to paid
    await wallet.mint(64, quote_id=mint_quote.quote)
    invoice_62_sat = get_fake_invoice(62)
    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=invoice_62_sat)
        )
    ).quote
    # quote = await ledger.get_melt_quote(quote_id)
    settings.fakewallet_payment_state = PaymentStatusResult.FAILED.name
    settings.fakewallet_pay_invoice_state = PaymentResult.FAILED.name
    try:
        await ledger.melt(proofs=wallet.proofs, quote=quote_id)
        raise AssertionError("Expected LightningPaymentFailedError")
    except LightningPaymentFailedError:
        pass

@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_melt_lightning_error_status_keeps_proofs_pending(
    ledger: Ledger, wallet: Wallet
):
    mint_quote = await wallet.request_mint(64)
    await ledger.get_mint_quote(mint_quote.quote)
    await wallet.mint(64, quote_id=mint_quote.quote)
    invoice = get_fake_invoice(62)
    quote_id = (
        await ledger.melt_quote(PostMeltQuoteRequest(unit="sat", request=invoice))
    ).quote

    settings.fakewallet_payment_state = PaymentStatusResult.ERROR.name
    settings.fakewallet_pay_invoice_state = PaymentResult.ERROR.name
    response = await melt_signed(ledger, wallet, proofs=wallet.proofs, quote=quote_id)

    assert response.state == MeltQuoteState.pending.value
    states = await ledger.db_read.get_proofs_states([p.Y for p in wallet.proofs])
    assert all(state.pending for state in states)
    assert not ledger.disable_melt


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_melt_lightning_pay_invoice_failed_settled(
    ledger: Ledger, wallet: Wallet
):
    mint_quote = await wallet.request_mint(64)
    await ledger.get_mint_quote(mint_quote.quote)  # fakewallet: set the quote to paid
    await wallet.mint(64, quote_id=mint_quote.quote)
    invoice_62_sat = get_fake_invoice(62)
    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=invoice_62_sat)
        )
    ).quote
    settings.fakewallet_pay_invoice_state = PaymentResult.FAILED.name
    settings.fakewallet_payment_state = PaymentStatusResult.SETTLED.name

    melt_response = await melt_signed(ledger, wallet, proofs=wallet.proofs, quote=quote_id)
    assert melt_response.state == MeltQuoteState.paid.value
    states = await ledger.db_read.get_proofs_states([p.Y for p in wallet.proofs])
    assert all([s.spent for s in states])


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_melt_lightning_pay_invoice_failed_pending(
    ledger: Ledger, wallet: Wallet
):
    mint_quote = await wallet.request_mint(64)
    await ledger.get_mint_quote(mint_quote.quote)  # fakewallet: set the quote to paid
    await wallet.mint(64, quote_id=mint_quote.quote)
    invoice_62_sat = get_fake_invoice(62)
    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=invoice_62_sat)
        )
    ).quote
    settings.fakewallet_pay_invoice_state = PaymentResult.FAILED.name
    settings.fakewallet_payment_state = PaymentStatusResult.PENDING.name

    melt_response = await melt_signed(ledger, wallet, proofs=wallet.proofs, quote=quote_id)
    assert melt_response.state == MeltQuoteState.pending.value
    # expect that proofs are pending
    states = await ledger.db_read.get_proofs_states([p.Y for p in wallet.proofs])
    assert all([s.pending for s in states])


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_melt_lightning_payment_exceptions_keep_pending(
    ledger: Ledger, wallet: Wallet, monkeypatch: pytest.MonkeyPatch
):
    mint_quote = await wallet.request_mint(64)
    await ledger.get_mint_quote(mint_quote.quote)  # fakewallet: set the quote to paid
    await wallet.mint(64, quote_id=mint_quote.quote)
    invoice_62_sat = get_fake_invoice(62)
    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=invoice_62_sat)
        )
    ).quote
    monkeypatch.setattr(settings, "fakewallet_payment_state_exception", True)
    monkeypatch.setattr(settings, "fakewallet_pay_invoice_state_exception", True)

    resp = await melt_signed(ledger, wallet, proofs=wallet.proofs, quote=quote_id)
    assert resp.state == MeltQuoteState.pending.value
    states = await ledger.db_read.get_proofs_states([p.Y for p in wallet.proofs])
    assert all(state.pending for state in states)
    assert not ledger.disable_melt


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_mint_melt_different_units(ledger: Ledger, wallet: Wallet):
    """Mint and melt different units."""
    # load the wallet
    mint_quote = await wallet.request_mint(64)
    await wallet.mint(64, quote_id=mint_quote.quote)

    wallet_usd = await Wallet.with_db(
        url=wallet.url,
        db="test_data/wallet_usd",
        name="wallet_usd",
        unit="usd",
    )
    await wallet_usd.load_mint()
    mint_quote_usd = await wallet_usd.request_mint(64)
    await wallet_usd.mint(64, quote_id=mint_quote_usd.quote)

    amount = 32

    # mint quote in sat, locked: a v3 mint quote is a transaction input and inputs sign
    quote_privkey, quote_pubkey = nut20.generate_keypair()
    sat_mint_quote = await ledger.mint_quote(
        quote_request=PostMintQuoteRequest(
            amount=amount, unit="sat", pubkey=quote_pubkey
        )
    )
    sat_invoice = sat_mint_quote.request
    assert sat_mint_quote.state != MintQuoteState.paid

    # melt quote in usd
    usd_melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="usd", request=sat_invoice)
    )
    assert usd_melt_quote.state != MeltQuoteState.paid

    # pay melt quote with usd
    await melt_signed(ledger, wallet_usd, proofs=wallet_usd.proofs, quote=usd_melt_quote.quote)

    output_amounts = [32]

    secrets, rs, derivation_paths = await wallet.generate_n_secrets(len(output_amounts))
    outputs, rs = wallet._construct_outputs(output_amounts, secrets, rs)

    # mint in sat
    mint_resp = await ledger.mint(
        outputs=outputs,
        quote_id=sat_mint_quote.quote,
        signature=nut20.sign_mint_quote_v3(
            sat_mint_quote.quote, sat_mint_quote.amount, outputs, quote_privkey
        ),
    )

    assert len(mint_resp) == len(outputs)


# Tests for unique pending melt quote checking_id constraint
@pytest.mark.asyncio
async def test_set_melt_quote_pending_without_checking_id(ledger: Ledger):
    """Test that setting a melt quote as pending without a checking_id raises an error."""
    quote = MeltQuote(
        quote="quote_id_no_checking",
        method="bolt11",
        request="lnbc123",
        checking_id="temp_id",
        unit="sat",
        amount=100,
        fee_reserve=1,
        state=MeltQuoteState.unpaid,
    )
    await ledger.crud.store_melt_quote(quote=quote, db=ledger.db)

    # Set checking_id to empty to simulate the error condition
    quote.checking_id = ""

    try:
        await ledger.db_write._set_melt_quote_pending(quote=quote)
        raise AssertionError("Expected TransactionError")
    except TransactionError as e:
        assert "Melt quote doesn't have checking ID" in str(e)


@pytest.mark.asyncio
async def test_set_melt_quote_pending_prevents_duplicate_checking_id(ledger: Ledger):
    """Test that setting a melt quote as pending fails if another quote with same checking_id is already pending."""
    checking_id = "test_checking_id_duplicate"

    quote1 = MeltQuote(
        quote="quote_id_dup_first",
        method="bolt11",
        request="lnbc123",
        checking_id=checking_id,
        unit="sat",
        amount=100,
        fee_reserve=1,
        state=MeltQuoteState.unpaid,
    )
    quote2 = MeltQuote(
        quote="quote_id_dup_second",
        method="bolt11",
        request="lnbc456",
        checking_id=checking_id,
        unit="sat",
        amount=200,
        fee_reserve=2,
        state=MeltQuoteState.unpaid,
    )

    await ledger.crud.store_melt_quote(quote=quote1, db=ledger.db)
    await ledger.crud.store_melt_quote(quote=quote2, db=ledger.db)

    # Set the first quote as pending
    await ledger.db_write._set_melt_quote_pending(quote=quote1)

    # Verify the first quote is pending
    quote1_db = await ledger.crud.get_melt_quote(
        quote_id="quote_id_dup_first", db=ledger.db
    )
    assert quote1_db.state == MeltQuoteState.pending

    # Attempt to set the second quote as pending should fail
    try:
        await ledger.db_write._set_melt_quote_pending(quote=quote2)
        raise AssertionError("Expected QuotePendingError")
    except QuotePendingError as e:
        assert "Melt quote already paid or pending." in str(e)
        assert e.code == 20005

    # Verify the second quote is still unpaid
    quote2_db = await ledger.crud.get_melt_quote(
        quote_id="quote_id_dup_second", db=ledger.db
    )
    assert quote2_db.state == MeltQuoteState.unpaid


@pytest.mark.asyncio
async def test_melt_quote_lookup_after_backend_id_update(
    ledger: Ledger,
):
    """Check quote lookup after a backend checking-ID update."""
    request = "same-invoice-request"
    initial_checking_id = "invoice-payment-hash"
    quote1 = MeltQuote(
        quote="checking-id-update-quote-1",
        method="bolt11",
        request=request,
        checking_id=initial_checking_id,
        unit="sat",
        amount=100,
        fee_reserve=1,
        state=MeltQuoteState.unpaid,
    )
    quote2 = quote1.model_copy(
        update={"quote": "checking-id-update-quote-2", "amount": 50}
    )
    await ledger.crud.store_melt_quote(quote=quote1, db=ledger.db)
    await ledger.crud.store_melt_quote(quote=quote2, db=ledger.db)

    pending = await ledger.db_write._set_melt_quote_pending(quote1)
    updated = await ledger._update_melt_checking_id(
        quote1.quote,
        "backend-payment-attempt-id",
        expected_attempt=pending.attempt,
        lock_token=pending.melt_lock,
    )
    assert updated.checking_id == "backend-payment-attempt-id"

    with pytest.raises(QuotePendingError) as exc_info:
        await ledger.db_write._set_melt_quote_pending(quote2)
    assert exc_info.value.code == 20005

    quote3 = quote1.model_copy(
        update={
            "quote": "checking-id-update-quote-3",
            "checking_id": "new-backend-quote-id",
        }
    )
    with pytest.raises(QuotePendingError) as exc_info:
        await ledger.db_write._store_melt_quote(quote3)
    assert exc_info.value.code == 20005


@pytest.mark.asyncio
async def test_set_melt_quote_pending_allows_different_checking_id(ledger: Ledger):
    """Test that setting melt quotes as pending succeeds when they have different checking_ids."""
    checking_id_1 = "test_checking_id_allow_1"
    checking_id_2 = "test_checking_id_allow_2"

    quote1 = MeltQuote(
        quote="quote_id_allow_1",
        method="bolt11",
        request="lnbc123",
        checking_id=checking_id_1,
        unit="sat",
        amount=100,
        fee_reserve=1,
        state=MeltQuoteState.unpaid,
    )
    quote2 = MeltQuote(
        quote="quote_id_allow_2",
        method="bolt11",
        request="lnbc456",
        checking_id=checking_id_2,
        unit="sat",
        amount=200,
        fee_reserve=2,
        state=MeltQuoteState.unpaid,
    )

    await ledger.crud.store_melt_quote(quote=quote1, db=ledger.db)
    await ledger.crud.store_melt_quote(quote=quote2, db=ledger.db)

    # Set both quotes as pending - should succeed
    await ledger.db_write._set_melt_quote_pending(quote=quote1)
    await ledger.db_write._set_melt_quote_pending(quote=quote2)

    # Verify both quotes are pending
    quote1_db = await ledger.crud.get_melt_quote(
        quote_id="quote_id_allow_1", db=ledger.db
    )
    quote2_db = await ledger.crud.get_melt_quote(
        quote_id="quote_id_allow_2", db=ledger.db
    )
    assert quote1_db.state == MeltQuoteState.pending
    assert quote2_db.state == MeltQuoteState.pending


@pytest.mark.asyncio
async def test_set_melt_quote_pending_after_unset(ledger: Ledger):
    """Test that a quote can be set as pending again after being unset."""
    checking_id = "test_checking_id_unset_test"

    quote1 = MeltQuote(
        quote="quote_id_unset_first",
        method="bolt11",
        request="lnbc123",
        checking_id=checking_id,
        unit="sat",
        amount=100,
        fee_reserve=1,
        state=MeltQuoteState.unpaid,
    )
    quote2 = MeltQuote(
        quote="quote_id_unset_second",
        method="bolt11",
        request="lnbc456",
        checking_id=checking_id,
        unit="sat",
        amount=200,
        fee_reserve=2,
        state=MeltQuoteState.unpaid,
    )

    await ledger.crud.store_melt_quote(quote=quote1, db=ledger.db)
    await ledger.crud.store_melt_quote(quote=quote2, db=ledger.db)

    # Set the first quote as pending
    quote1_pending = await ledger.db_write._set_melt_quote_pending(quote=quote1)
    assert quote1_pending.state == MeltQuoteState.pending

    # Unset the first quote (mark as paid)
    await ledger.db_write._unset_melt_quote_pending(
        quote=quote1_pending, state=MeltQuoteState.paid
    )

    # Verify the first quote is no longer pending
    quote1_db = await ledger.crud.get_melt_quote(
        quote_id="quote_id_unset_first", db=ledger.db
    )
    assert quote1_db.state == MeltQuoteState.paid

    # Now the second quote should still
    await assert_err(
        ledger.db_write._set_melt_quote_pending(quote=quote2),
        "Melt quote already paid or pending.",
    )

    # Verify the second quote is unpaid
    quote2_db = await ledger.crud.get_melt_quote(
        quote_id="quote_id_unset_second", db=ledger.db
    )
    assert quote2_db.state == MeltQuoteState.unpaid


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_mint_pay_with_duplicate_checking_id(wallet):
    mint_quote1 = await wallet.request_mint(1024)
    mint_quote2 = await wallet.request_mint(1024)
    await pay_if_regtest(mint_quote1.request)
    await pay_if_regtest(mint_quote2.request)

    proofs1 = await wallet.mint(amount=1024, quote_id=mint_quote1.quote)
    proofs2 = await wallet.mint(amount=1024, quote_id=mint_quote2.quote)

    invoice = get_real_invoice(64)["payment_request"]

    # Get two melt quotes for the same invoice
    melt_quote1 = await wallet.melt_quote(invoice)
    melt_quote2 = await wallet.melt_quote(invoice)

    response1 = await wallet.melt(
        proofs=proofs1,
        invoice=invoice,
        fee_reserve_sat=melt_quote1.fee_reserve,
        quote_id=melt_quote1.quote,
    )
    assert response1.state == "PAID"

    await assert_err(
        wallet.melt(
            proofs=proofs2,
            invoice=invoice,
            fee_reserve_sat=melt_quote2.fee_reserve,
            quote_id=melt_quote2.quote,
        ),
        "could not pay invoice: Mint Error: Melt quote already paid or pending. (Code: 20006)",
    )


@pytest.mark.asyncio
async def test_melt_race_condition_fixed(wallet: Wallet, ledger: Ledger):
    import asyncio

    # Setup: Get proofs and a melt quote
    # Mint set 1 (128 sat)
    mq1 = await wallet.request_mint(128)
    await pay_if_regtest(mq1.request)
    proofs1 = await wallet.mint(128, quote_id=mq1.quote)

    # Mint set 2 (128 sat)
    mq2 = await wallet.request_mint(128)
    await pay_if_regtest(mq2.request)
    proofs2 = await wallet.mint(128, quote_id=mq2.quote)

    # Invoice for 64 sats (+2 fee = 66 sats needed)
    invoice = (
        get_real_invoice(64)["payment_request"]
        if is_regtest
        else get_fake_invoice(64)
    )
    melt_quote1 = await wallet.melt_quote(invoice)
    melt_quote2 = await wallet.melt_quote(invoice)

    assert melt_quote1.quote != melt_quote2.quote

    responses = await asyncio.gather(
        melt_signed(ledger, wallet, proofs=proofs1, quote=melt_quote1.quote),
        melt_signed(ledger, wallet, proofs=proofs2, quote=melt_quote2.quote),
        return_exceptions=True,
    )

    failures = [r for r in responses if isinstance(r, Exception)]
    successes = [r for r in responses if not isinstance(r, Exception)]

    assert len(successes) == 1
    assert len(failures) == 1
    assert "Melt quote already paid or pending." in str(failures[0])

    failed_proofs = proofs2 if responses[1] is failures[0] else proofs1

    states = await ledger.db_read.get_proofs_states([p.Y for p in failed_proofs])

    # We expect them to NOT be pending if the bug is fixed
    assert not any(
        s.pending for s in states
    ), "Proofs from failed melt request stuck in pending!"


@pytest.mark.asyncio
async def test_melt_with_wrong_unit_proofs(ledger: Ledger, wallet: Wallet):
    """
    Test that a melt quote cannot be paid with proofs of a different unit.
    """
    wallet_usd = await Wallet.with_db(
        url=wallet.url,
        db="test_data/wallet_usd_different_unit",
        name="wallet_usd_different_unit",
        unit="usd",
    )
    await wallet_usd.load_mint()

    mint_quote_usd = await wallet_usd.request_mint(100)
    await pay_if_regtest(mint_quote_usd.request)
    usd_proofs = await wallet_usd.mint(100, quote_id=mint_quote_usd.quote)
    assert wallet_usd.unit.name == "usd"

    sat_mint_quote = await ledger.mint_quote(
        quote_request=PostMintQuoteRequest(amount=100, unit="sat")
    )
    sat_invoice = sat_mint_quote.request

    sat_melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=sat_invoice)
    )

    assert sat_melt_quote.amount == 100
    assert sat_melt_quote.unit == "sat"

    await assert_err(
        melt_signed(ledger, wallet_usd, proofs=usd_proofs, quote=sat_melt_quote.quote, outputs=[]),
        "proof unit usd does not match quote unit sat",
    )


@pytest.mark.asyncio
async def test_internal_melt_failure_unsets_pending(ledger: Ledger, wallet: Wallet):
    """
    Test that when an internal melt quote settlement fails, the pending state of the proofs
    and the melt quote is correctly unset.
    """
    # Get some proofs to use
    mint_quote_req = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote_req.request)
    proofs = await wallet.mint(64, quote_id=mint_quote_req.quote)

    # Create internal mint quote
    sat_mint_quote = await ledger.mint_quote(
        quote_request=PostMintQuoteRequest(amount=64, unit="sat")
    )

    # Create internal melt quote for the same invoice
    sat_melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=sat_mint_quote.request)
    )

    # Make the mint quote "paid" to cause melt_mint_settle_internally to fail
    sat_mint_quote.state = MintQuoteState.paid
    await ledger.crud.update_mint_quote(quote=sat_mint_quote, db=ledger.db)

    # Try to melt - it should fail because mint quote is already paid
    await assert_err(
        melt_signed(ledger, wallet, proofs=proofs, quote=sat_melt_quote.quote, outputs=[]),
        "mint quote already paid",
    )

    # Check that proofs are not pending
    states = await ledger.db_read.get_proofs_states([p.Y for p in proofs])
    assert not any(s.pending for s in states), "Proofs stuck in pending!"

    # Check that quote is not pending and is unpaid
    melt_quote = await ledger.crud.get_melt_quote(
        quote_id=sat_melt_quote.quote, db=ledger.db
    )
    assert melt_quote is not None
    assert melt_quote.state == MeltQuoteState.unpaid, "Quote state should be unpaid"
    assert not melt_quote.pending, "Quote should not be pending"


@pytest.mark.asyncio
async def test_internal_melt_concurrently_issued_quote(ledger: Ledger, monkeypatch):
    monkeypatch.setattr(settings, "fakewallet_brr", False)
    internal_mint_quote = await ledger.mint_quote(
        quote_request=PostMintQuoteRequest(amount=64, unit="sat")
    )
    internal_melt_quote_response = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=internal_mint_quote.request)
    )
    internal_melt_quote = await ledger.crud.get_melt_quote(
        quote_id=internal_melt_quote_response.quote,
        db=ledger.db,
    )
    assert internal_melt_quote is not None
    internal_melt_quote.state = MeltQuoteState.pending
    await ledger.crud.update_melt_quote(quote=internal_melt_quote, db=ledger.db)

    proof = Proof(
        amount=64,
        C="concurrent-internal-settlement-proof",
        secret="concurrent-internal-settlement-secret",
        id=ledger.keyset.id,
    )
    await ledger.crud.bump_keyset_balance(
        db=ledger.db,
        keyset=ledger.keyset,
        amount=proof.amount,
    )
    await ledger.crud.set_proof_pending(
        proof=proof,
        quote_id=internal_melt_quote.quote,
        db=ledger.db,
    )
    assert await ledger.crud.try_debit_keyset_balance(
        db=ledger.db,
        keyset=ledger.keyset,
        amount=proof.amount,
    )

    original_get_mint_quote = ledger.crud.get_mint_quote
    issued_during_settlement = False

    async def get_mint_quote_with_concurrent_issuance(*args, **kwargs):
        nonlocal issued_during_settlement
        quote = await original_get_mint_quote(*args, **kwargs)
        if (
            not issued_during_settlement
            and kwargs.get("request") == internal_mint_quote.request
            and kwargs.get("conn") is None
        ):
            assert quote is not None
            issued_quote = quote.model_copy(deep=True)
            issued_quote.state = MintQuoteState.paid
            issued_quote.state = MintQuoteState.pending
            issued_quote.state = MintQuoteState.issued
            issued_quote.paid_time = 1_700_000_000
            issued_quote.issued_time = 1_700_000_001
            issued_quote.updated_at = 1_700_000_001
            await ledger.crud.update_mint_quote(quote=issued_quote, db=ledger.db)
            issued_during_settlement = True
        return quote

    monkeypatch.setattr(
        ledger.crud,
        "get_mint_quote",
        get_mint_quote_with_concurrent_issuance,
    )

    with pytest.raises(QuoteAlreadyIssuedError) as exc_info:
        internal_melt_quote = await ledger.db_write.claim_melt_quote_lease(
            internal_melt_quote
        )
        assert internal_melt_quote is not None
        await ledger._execute_melt_payment(
            internal_melt_quote,
            [proof],
            outputs=[],
        )
    assert exc_info.value.code == 20002

    assert issued_during_settlement
    persisted_mint_quote = await original_get_mint_quote(
        quote_id=internal_mint_quote.quote,
        db=ledger.db,
    )
    assert persisted_mint_quote is not None
    assert persisted_mint_quote.issued
    assert persisted_mint_quote.issued_time == 1_700_000_001
    assert persisted_mint_quote.amount_issued == 64

    persisted_melt_quote = await ledger.crud.get_melt_quote(
        quote_id=internal_melt_quote.quote,
        db=ledger.db,
    )
    assert persisted_melt_quote is not None
    assert persisted_melt_quote.unpaid
    states = await ledger.db_read.get_proofs_states([proof.Y])
    assert all(state.unspent for state in states)


@pytest.mark.asyncio
@pytest.mark.skipif(
    not is_fake,
    reason="only fakewallet",
)
@pytest.mark.parametrize(
    "fee_paid_sat_offset",
    [
        pytest.param(0, id="overpaid_fee_zero"),
        pytest.param(1, id="overpaid_fee_negative"),
    ],
)
async def test_melt_early_return_leaves_no_orphan_blank_outputs(
    wallet, ledger: Ledger, monkeypatch, fee_paid_sat_offset: int
):
    # Inherited test: it melts without nutroot witnesses, so it belongs on the v2 keyset.
    await use_v2_keyset(wallet)
    """When `_generate_change_promises` takes its early-return branch
    (overpaid_fee <= 0), the wallet's blank NUT-08 outputs — already
    inserted into `promises` with c_ IS NULL before the LN payment —
    must not be left behind as orphans. Later operations that re-derive
    the same B_ (e.g. NUT-13 seed restore) collide with them and surface
    as `OutputsArePendingError`.

    Both parametrize cases hit the same early-return branch:
      - offset == 0  → overpaid_fee == 0  (fee exactly matched reserve)
      - offset > 0   → overpaid_fee < 0   (backend took more than the
        reserve due to a service fee on top of the routing fee)
    """
    settings.fakewallet_payment_state = PaymentStatusResult.SETTLED.name
    settings.fakewallet_pay_invoice_state = ""

    invoice_64_sat = get_fake_invoice(64)

    mint_quote = await wallet.request_mint(100)
    proofs = await wallet.mint(amount=100, quote_id=mint_quote.quote)

    melt_quote = await wallet.melt_quote(invoice_64_sat)

    total_provided = sum(p.amount for p in proofs)
    input_fees = ledger.get_fees_for_proofs(proofs)
    fee_reserve_provided = total_provided - melt_quote.amount - input_fees
    fee_paid_sat = fee_reserve_provided + fee_paid_sat_offset

    backend = ledger.backends[Method.bolt11][Unit.sat]

    async def patched_pay_invoice(quote: MeltQuote, fee_limit_msat: int):
        return PaymentResponse(
            result=PaymentResult.SETTLED,
            checking_id=quote.checking_id or "fake_checking_id",
            fee=Amount(unit=Unit.sat, amount=fee_paid_sat),
            preimage="0" * 64,
        )

    monkeypatch.setattr(backend, "pay_invoice", patched_pay_invoice)

    n_change_outputs = 4
    change_secrets, change_rs, _ = await wallet.generate_n_secrets(
        n_change_outputs, skip_bump=True
    )
    change_outputs, _ = wallet._construct_outputs(
        n_change_outputs * [1], change_secrets, change_rs
    )

    response = await ledger.melt(
        proofs=proofs, quote=melt_quote.quote, outputs=change_outputs
    )

    assert response.state == MeltQuoteState.paid.value
    assert not response.change

    orphans = await ledger.crud.get_blinded_messages_melt_id(
        db=ledger.db, melt_id=melt_quote.quote
    )
    assert orphans == [], (
        f"Expected no orphan blank outputs for melt {melt_quote.quote}, "
        f"got {len(orphans)} with B_s {[o.B_ for o in orphans]}"
    )


@pytest.mark.asyncio
async def test_prepare_melt_rejects_already_paid_quote(ledger: Ledger):
    """_prepare_melt runs before the locked guard, so it must report the paid
    state with its own code rather than a generic transaction error."""
    quote = MeltQuote(
        quote="quote_id_already_paid",
        method="bolt11",
        request="lnbcfake",
        checking_id="checking_id_already_paid",
        unit="sat",
        state=MeltQuoteState.paid,
        amount=100,
        fee_reserve=1,
    )
    await ledger.crud.store_melt_quote(quote=quote, db=ledger.db)

    with pytest.raises(InvoiceAlreadyPaidError) as exc_info:
        await ledger._prepare_melt(proofs=[], quote=quote.quote)
    assert exc_info.value.code == 20006


@pytest.mark.asyncio
async def test_finalize_melt_attempt_selection(ledger: Ledger):
    """Check finalization with distinct execution-attempt identifiers."""
    proof_a, quote = await create_pending_melts(ledger)

    failed_quote = await ledger._finalize_melt_failed(
        quote.quote, expected_attempt=quote.attempt
    )
    assert failed_quote.unpaid
    states = await ledger.db_read.get_proofs_states([proof_a.Y])
    assert states[0].unspent

    quote_db = await ledger.crud.get_melt_quote(quote_id=quote.quote, db=ledger.db)
    assert quote_db is not None
    remelted_quote = await ledger.db_write.verify_and_set_melt_quote_pending(
        quote=quote_db, proofs=[proof_a], keysets=ledger.keysets
    )
    assert remelted_quote.attempt != quote.attempt
    states = await ledger.db_read.get_proofs_states([proof_a.Y])
    assert states[0].pending

    stale_result = await ledger._finalize_melt_failed(
        quote.quote, expected_attempt=quote.attempt
    )
    assert stale_result.pending
    assert stale_result.attempt == remelted_quote.attempt

    states = await ledger.db_read.get_proofs_states([proof_a.Y])
    assert states[0].pending


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_melt_status_resolution_across_attempts(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch
):
    """Check quote-status resolution across execution attempts."""
    proof_a, quote = await create_pending_melts(ledger)
    proof_b = Proof(
        amount=123, C="remelt_c2", secret="remelt_secret2", id=ledger.keyset.id
    )
    backend = ledger.backends[Method.bolt11][Unit.sat]

    async def failed_status_with_concurrent_remelt(checking_id: str):
        current = await ledger.crud.get_melt_quote(quote_id=quote.quote, db=ledger.db)
        assert current is not None
        await ledger._finalize_melt_failed(
            quote.quote, expected_attempt=quote.attempt, lock_token=current.melt_lock
        )
        quote_db = await ledger.crud.get_melt_quote(quote_id=quote.quote, db=ledger.db)
        assert quote_db is not None
        remelted_quote = await ledger.db_write.verify_and_set_melt_quote_pending(
            quote=quote_db, proofs=[proof_b], keysets=ledger.keysets
        )
        assert remelted_quote.attempt != quote.attempt
        # Complete the synthetic attempt's preparation for status resolution.
        await ledger._update_melt_checking_id(
            remelted_quote.quote,
            remelted_quote.checking_id,
            expected_attempt=remelted_quote.attempt,
            lock_token=remelted_quote.melt_lock,
            payment_uncertain=False,
        )
        await ledger.db_write.unlock_melt_quote(
            remelted_quote.quote, remelted_quote.melt_lock
        )
        return PaymentStatus(result=PaymentStatusResult.FAILED)

    monkeypatch.setattr(
        backend, "get_payment_status", failed_status_with_concurrent_remelt
    )

    result = await ledger.get_melt_quote(quote.quote)

    assert result.state == MeltQuoteState.pending
    states = await ledger.db_read.get_proofs_states([proof_a.Y, proof_b.Y])
    assert states[0].unspent
    assert states[1].pending

    async def failed_status(checking_id: str):
        return PaymentStatus(result=PaymentStatusResult.FAILED)

    monkeypatch.setattr(backend, "get_payment_status", failed_status)
    result = await ledger.get_melt_quote(quote.quote)
    assert result.state == MeltQuoteState.unpaid
    states = await ledger.db_read.get_proofs_states([proof_b.Y])
    assert states[0].unspent


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="deterministic test uses FakeWallet knobs")
async def test_melt_quote_during_payment(
    ledger: Ledger, wallet: Wallet, monkeypatch: pytest.MonkeyPatch
):
    """Check quote, lease, and proof states throughout an active payment."""
    await fund_wallet(ledger, wallet, 64)
    proofs = wallet.proofs
    proof_Ys = [p.Y for p in proofs]

    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=get_fake_invoice(62))
        )
    ).quote

    backend = ledger.backends[Method.bolt11][Unit.sat]
    balance_before = backend.balance[Unit.sat].amount

    # Use a controlled payment delay and backend status.
    monkeypatch.setattr(settings, "fakewallet_delay_outgoing_payment", 3)
    monkeypatch.setattr(settings, "fakewallet_pay_invoice_state", "SETTLED")
    monkeypatch.setattr(settings, "fakewallet_payment_state", "FAILED")

    melt_task = asyncio.create_task(ledger.melt(proofs=proofs, quote=quote_id))

    # Wait for payment preparation to finish.
    for _ in range(100):
        q = await ledger.crud.get_melt_quote(quote_id=quote_id, db=ledger.db)
        if q and q.pending:
            break
        await asyncio.sleep(0.02)
    else:
        melt_task.cancel()
        pytest.fail("melt quote never reached PENDING")

    # Check the active lease and pending proofs.
    assert q.locked, "melt lock must be armed while the payment executes"

    states = await ledger.db_read.get_proofs_states(proof_Ys)
    assert all(s.pending for s in states), "proofs should be pending mid-payment"

    # Read the quote during payment execution.
    polled_quote = await ledger.get_melt_quote(quote_id)
    assert polled_quote.pending, "active quote remains pending"
    assert polled_quote.locked

    states = await ledger.db_read.get_proofs_states(proof_Ys)
    assert all(s.pending for s in states), "proofs remain pending"

    # Check reservation behavior for pending proofs.
    secrets, rs, _ = await wallet.generate_n_secrets(len(proofs))
    outputs, rs = wallet._construct_outputs([p.amount for p in proofs], secrets, rs)
    with pytest.raises(Exception):
        await ledger.swap(proofs=proofs, outputs=outputs)

    # Finalization follows the active lease owner.
    q2 = await ledger._finalize_melt_failed(quote_id)
    assert q2.pending, "finalizing a locked quote without the token must be refused"
    q3 = await ledger._finalize_melt_paid(quote_id)
    assert q3.pending, "finalizing a locked quote without the token must be refused"

    # Complete the payment.
    result = await melt_task
    assert result.state == MeltQuoteState.paid.value

    # lock released, proofs consumed exactly once, invoice paid exactly once
    q4 = await ledger.crud.get_melt_quote(quote_id=quote_id, db=ledger.db)
    assert q4 is not None and not q4.locked, "lock must be cleared on finalize"
    states = await ledger.db_read.get_proofs_states(proof_Ys)
    assert all(s.spent for s in states), "proofs are spent by the melt, once"
    balance_after = backend.balance[Unit.sat].amount
    assert balance_after == balance_before - 62


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="deterministic test uses FakeWallet knobs")
async def test_melt_pending_response_reconciliation(
    ledger: Ledger, wallet: Wallet, monkeypatch: pytest.MonkeyPatch
):
    """Check status reconciliation after a pending payment response."""
    await fund_wallet(ledger, wallet, 64)
    proofs = wallet.proofs

    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=get_fake_invoice(62))
        )
    ).quote

    # pay_invoice returns PENDING (payment in doubt), but the payment later
    # settles at the backend
    monkeypatch.setattr(settings, "fakewallet_delay_outgoing_payment", None)
    monkeypatch.setattr(settings, "fakewallet_pay_invoice_state", "PENDING")
    monkeypatch.setattr(settings, "fakewallet_payment_state", "SETTLED")

    result = await ledger.melt(proofs=proofs, quote=quote_id)
    assert result.state == MeltQuoteState.pending.value

    # the executor released the lock even though it did not finalize
    q = await ledger.crud.get_melt_quote(quote_id=quote_id, db=ledger.db)
    assert q is not None and q.pending and not q.locked

    # now a poller may resolve the (settled) payment and finalize the quote
    resolved = await ledger.get_melt_quote(quote_id)
    assert resolved.paid


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="deterministic test uses FakeWallet knobs")
async def test_lock_cleared_on_every_state_transition(ledger: Ledger, wallet: Wallet):
    """The lock is only meaningful while PENDING: every helper that moves a
    quote out of PENDING must clear it."""
    await fund_wallet(ledger, wallet, 64)
    proofs = wallet.proofs
    assert len(proofs) >= 3

    async def locked_quote(quote_id: str, proof) -> MeltQuote:
        quote = MeltQuote(
            quote=quote_id,
            method="bolt11",
            request=f"req-{quote_id}",
            checking_id=f"cid-{quote_id}",
            unit="sat",
            state=MeltQuoteState.unpaid,
            amount=100,
            fee_reserve=1,
        )
        await ledger.crud.store_melt_quote(quote=quote, db=ledger.db)
        quote_db = await ledger.crud.get_melt_quote(quote_id=quote_id, db=ledger.db)
        assert quote_db is not None
        locked = await ledger.db_write.verify_and_set_melt_quote_pending(
            quote=quote_db, proofs=[proof], keysets=ledger.keysets
        )
        assert locked.locked
        return locked

    # _unset_melt_quote_pending (via unset_melt_quote_pending_and_proofs)
    q1 = await locked_quote("lock-unset-pending", proofs[0])
    await ledger.db_write.unset_melt_quote_pending_and_proofs(
        q1, [proofs[0]], ledger.keysets, MeltQuoteState.unpaid
    )
    r1 = await ledger.crud.get_melt_quote(quote_id=q1.quote, db=ledger.db)
    assert r1 is not None and r1.unpaid and not r1.locked

    # _update_melt_quote_state (management RPC path) refuses locked quotes;
    # an operator must release the lock explicitly first
    q2 = await locked_quote("lock-mgmt-rpc", proofs[1])
    with pytest.raises(TransactionError):
        await ledger.db_write._update_melt_quote_state(q2.quote, MeltQuoteState.unpaid)
    released = await ledger.db_write.force_unlock_melt_quote(q2.quote)
    assert released
    await ledger.db_write._update_melt_quote_state(q2.quote, MeltQuoteState.unpaid)
    r2 = await ledger.crud.get_melt_quote(quote_id=q2.quote, db=ledger.db)
    assert r2 is not None and r2.unpaid and not r2.locked

    # set_melt_quote_paid_and_invalidate_proofs
    q3 = await locked_quote("lock-set-paid", proofs[2])
    await ledger.db_write.set_melt_quote_paid_and_invalidate_proofs(
        q3, [proofs[2]], ledger.keysets, keyset_fees={}
    )
    r3 = await ledger.crud.get_melt_quote(quote_id=q3.quote, db=ledger.db)
    assert r3 is not None and r3.paid and not r3.locked


@pytest.mark.asyncio
async def test_melt_lease_renewal_and_cleanup(ledger: Ledger, monkeypatch):
    _, quote = await create_pending_melts(ledger)
    monkeypatch.setattr(settings, "mint_melt_lease_seconds", 1)
    quote = await ledger.db_write.claim_melt_quote_lease(quote)
    assert quote is not None
    renewed = asyncio.Event()
    calls = 0
    original_renew = ledger.db_write.renew_melt_quote_lease

    async def observe_renew(current):
        nonlocal calls
        result = await original_renew(current)
        calls += 1
        if calls > 1:
            renewed.set()
        return result

    monkeypatch.setattr(ledger.db_write, "renew_melt_quote_lease", observe_renew)
    async with maintain_melt_lease(ledger.db_write, quote):
        await asyncio.wait_for(renewed.wait(), 2)
        current = await ledger.crud.get_melt_quote(quote_id=quote.quote, db=ledger.db)
        assert current is not None
        assert current.melt_lock_expires_at > quote.melt_lock_expires_at
        assert current.melt_lock == quote.melt_lock
    # The renewal task was awaited on exit, including when its owner is cancelled.
    assert not any(
        "maintain_melt_lease.<locals>.renew" in task.get_coro().__qualname__
        for task in asyncio.all_tasks()
    )


@pytest.mark.asyncio
async def test_melt_lease_budget_stops_renewal_during_slow_cleanup(
    ledger: Ledger, monkeypatch
):
    _, quote = await create_pending_melts(ledger)
    quote = await ledger.db_write.claim_melt_quote_lease(quote)
    assert quote is not None
    monkeypatch.setattr(settings, "mint_melt_lease_seconds", 1)
    monkeypatch.setattr(settings, "mint_melt_execution_timeout_seconds", 0.1)
    calls = 0
    original_renew = ledger.db_write.renew_melt_quote_lease

    async def observe_renew(current):
        nonlocal calls
        calls += 1
        return await original_renew(current)

    monkeypatch.setattr(ledger.db_write, "renew_melt_quote_lease", observe_renew)
    async with maintain_melt_lease(ledger.db_write, quote):
        # Model a backend that takes longer than the execution timeout to cancel.
        await asyncio.sleep(0.3)
        assert calls == 1  # Initial acquisition only; no later heartbeat.


@pytest.mark.asyncio
async def test_expired_melt_lease_has_one_recovery_owner(ledger: Ledger):
    proof, quote = await create_pending_melts(ledger)
    owner = await ledger.db_write.claim_melt_quote_lease(quote)
    assert owner is not None
    await expire_melt_lease(ledger, quote.quote)
    assert not await ledger.db_write.renew_melt_quote_lease(owner)
    claims = await asyncio.gather(
        ledger.db_write.claim_melt_quote_lease(owner),
        ledger.db_write.claim_melt_quote_lease(owner),
    )
    winners = [claim for claim in claims if claim is not None]
    assert len(winners) == 1
    winner = winners[0]
    assert winner.attempt == owner.attempt
    assert winner.melt_lock != owner.melt_lock
    assert not await ledger.db_write.renew_melt_quote_lease(owner)
    await ledger.db_write.unlock_melt_quote(owner.quote, owner.melt_lock)
    current = await ledger.crud.get_melt_quote(quote_id=quote.quote, db=ledger.db)
    assert current is not None and current.melt_lock == winner.melt_lock
    assert (await ledger.db_read.get_proofs_states([proof.Y]))[0].pending


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="uses a controlled payment backend")
async def test_melt_lease_recovery_and_finalization(
    ledger: Ledger, wallet: Wallet, monkeypatch
):
    await fund_wallet(ledger, wallet)
    proofs = wallet.proofs
    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=get_fake_invoice(62))
        )
    ).quote
    started, finish = asyncio.Event(), asyncio.Event()
    backend = ledger.backends[Method.bolt11][Unit.sat]

    async def delayed_payment(quote, fee_limit_msat):
        started.set()
        await finish.wait()
        return PaymentResponse(result=PaymentResult.SETTLED)

    monkeypatch.setattr(backend, "pay_invoice", delayed_payment)
    monkeypatch.setattr(settings, "fakewallet_payment_state", "FAILED")
    task = asyncio.create_task(ledger.melt(proofs=proofs, quote=quote_id))
    try:
        await asyncio.wait_for(started.wait(), 2)
        owner = await ledger.crud.get_melt_quote(quote_id=quote_id, db=ledger.db)
        assert owner is not None and owner.payment_uncertain
        await expire_melt_lease(ledger, quote_id)
        assert (await ledger.get_melt_quote(quote_id)).pending
        assert all(
            s.pending
            for s in await ledger.db_read.get_proofs_states([p.Y for p in proofs])
        )
        # Finalization follows the current lease owner.
        assert (
            await ledger._finalize_melt_paid(
                quote_id, expected_attempt=owner.attempt, lock_token=owner.melt_lock
            )
        ).pending
        assert (
            await ledger._finalize_melt_failed(
                quote_id, expected_attempt=owner.attempt, lock_token=owner.melt_lock
            )
        ).pending
        with pytest.raises(TransactionError, match="lease lost"):
            await ledger._update_melt_checking_id(
                quote_id,
                "late-id",
                expected_attempt=owner.attempt,
                lock_token=owner.melt_lock,
            )
        finish.set()
        with pytest.raises(TransactionError, match="lease lost"):
            await asyncio.wait_for(task, 2)
        monkeypatch.setattr(settings, "fakewallet_payment_state", "SETTLED")
        assert (await ledger.get_melt_quote(quote_id)).paid
        assert all(
            s.spent
            for s in await ledger.db_read.get_proofs_states([p.Y for p in proofs])
        )
        assert (await ledger.get_melt_quote(quote_id)).paid
    finally:
        finish.set()
        if not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


@pytest.mark.asyncio
async def test_melt_execution_timeout_state(ledger: Ledger, monkeypatch):
    proof, quote = await create_pending_melts(ledger)
    quote = await ledger.db_write.claim_melt_quote_lease(quote)
    assert quote is not None
    quote.payment_uncertain = True
    await ledger.crud.update_melt_quote(quote=quote, db=ledger.db)
    cancelled = asyncio.Event()

    async def hung_payment(quote, fee_limit_msat):
        try:
            await asyncio.Future()
        finally:
            cancelled.set()

    backend = ledger.backends[Method.bolt11][Unit.sat]
    monkeypatch.setattr(backend, "pay_invoice", hung_payment)
    monkeypatch.setattr(settings, "mint_melt_execution_timeout_seconds", 0.1)
    monkeypatch.setattr(settings, "fakewallet_payment_state", "FAILED")
    result = await ledger._execute_melt_payment(quote, [proof], outputs=None)
    assert result.state == MeltQuoteState.pending.value and cancelled.is_set()
    current = await ledger.crud.get_melt_quote(quote_id=quote.quote, db=ledger.db)
    assert current is not None and not current.locked
    assert current.melt_lock_expires_at == 0
    assert (await ledger.get_melt_quote(quote.quote)).pending
    assert (await ledger.db_read.get_proofs_states([proof.Y]))[0].pending
    assert not any(
        "maintain_melt_lease.<locals>.renew" in task.get_coro().__qualname__
        for task in asyncio.all_tasks()
    )


@pytest.mark.asyncio
async def test_melt_lease_loss_cancels_executor(ledger: Ledger, monkeypatch):
    proof, quote = await create_pending_melts(ledger)
    quote = await ledger.db_write.claim_melt_quote_lease(quote)
    assert quote is not None
    monkeypatch.setattr(settings, "mint_melt_lease_seconds", 1)
    original_renew = ledger.db_write.renew_melt_quote_lease
    calls = 0
    cancelled = asyncio.Event()

    async def lose_lease(current):
        nonlocal calls
        calls += 1
        return await original_renew(current) if calls == 1 else False

    async def hung_payment(quote, fee_limit_msat):
        try:
            await asyncio.Future()
        finally:
            cancelled.set()

    monkeypatch.setattr(ledger.db_write, "renew_melt_quote_lease", lose_lease)
    monkeypatch.setattr(
        ledger.backends[Method.bolt11][Unit.sat], "pay_invoice", hung_payment
    )
    with pytest.raises(TransactionError, match="lease lost"):
        await asyncio.wait_for(ledger._execute_melt_payment(quote, [proof], None), 2)
    assert cancelled.is_set()
    current = await ledger.crud.get_melt_quote(quote_id=quote.quote, db=ledger.db)
    assert current is not None and not current.locked
    assert current.melt_lock_expires_at == 0
    assert (await ledger.db_read.get_proofs_states([proof.Y]))[0].pending


@pytest.mark.asyncio
@pytest.mark.parametrize("cancelled", [False, True])
async def test_melt_executor_exit_releases_lease(
    ledger: Ledger, monkeypatch, cancelled: bool
):
    proof, quote = await create_pending_melts(ledger)
    quote = await ledger.db_write.claim_melt_quote_lease(quote)
    assert quote is not None
    started = asyncio.Event()

    async def payment(current, fee_limit_msat):
        started.set()
        if cancelled:
            await asyncio.Future()
        return PaymentResponse(result=PaymentResult.PENDING)

    async def persistence_error(*args, **kwargs):
        raise RuntimeError("could not persist payment result")

    monkeypatch.setattr(ledger.backends[Method.bolt11][Unit.sat], "pay_invoice", payment)
    monkeypatch.setattr(ledger, "_update_melt_checking_id", persistence_error)
    task = asyncio.create_task(ledger._execute_melt_payment(quote, [proof], None))
    await asyncio.wait_for(started.wait(), 2)
    if cancelled:
        task.cancel()
    with pytest.raises(asyncio.CancelledError if cancelled else RuntimeError):
        await task
    current = await ledger.crud.get_melt_quote(quote_id=quote.quote, db=ledger.db)
    assert current is not None and current.pending and not current.locked
    assert current.melt_lock_expires_at == 0
    assert (await ledger.db_read.get_proofs_states([proof.Y]))[0].pending


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="uses a controlled payment backend")
@pytest.mark.parametrize(
    "stage, failure",
    [
        ("outputs", "exception"),
        ("outputs", "cancelled"),
        ("outputs", "timeout"),
        ("outputs", "expired"),
        ("outputs", "interrupted"),
        ("pending", "interrupted"),
    ],
)
async def test_prepare_melt_failure_rolls_back(
    ledger: Ledger, wallet: Wallet, monkeypatch, stage: str, failure: str
):
    class PreparationInterrupted(BaseException):
        pass

    await fund_wallet(ledger, wallet)
    balance_before = await ledger.crud.get_balance(db=ledger.db, keyset=ledger.keyset)
    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=get_fake_invoice(62))
        )
    ).quote
    secrets, rs, _ = await wallet.generate_n_secrets(1)
    outputs, _ = wallet._construct_outputs([1], secrets, rs)
    started = asyncio.Event()
    target = ledger if stage == "outputs" else ledger.db_write
    operation = (
        "_store_blinded_messages"
        if stage == "outputs"
        else "verify_and_set_melt_quote_pending"
    )
    original_operation = getattr(target, operation)
    monkeypatch.setattr(settings, "mint_melt_lease_seconds", 1)
    if failure == "timeout":
        monkeypatch.setattr(settings, "mint_melt_execution_timeout_seconds", 0.1)

    async def interrupt_preparation(*args, **kwargs):
        await original_operation(*args, **kwargs)
        started.set()
        if failure in ("cancelled", "timeout"):
            await asyncio.Future()
        if failure == "expired":
            await asyncio.sleep(1.5)
        if failure == "interrupted":
            raise PreparationInterrupted()
        raise RuntimeError("could not prepare melt")

    async def unexpected_send(*args, **kwargs):
        pytest.fail("Failed preparation must not send a Lightning payment")

    monkeypatch.setattr(target, operation, interrupt_preparation)
    monkeypatch.setattr(
        ledger.backends[Method.bolt11][Unit.sat], "pay_invoice", unexpected_send
    )
    task = asyncio.create_task(
        ledger.melt(proofs=wallet.proofs, quote=quote_id, outputs=outputs)
    )
    await asyncio.wait_for(started.wait(), 2)
    if failure == "cancelled":
        task.cancel()
    expected_error = {
        "cancelled": asyncio.CancelledError,
        "timeout": asyncio.TimeoutError,
        "interrupted": PreparationInterrupted,
    }.get(failure, RuntimeError)
    with pytest.raises(expected_error):
        await task
    current = await ledger.crud.get_melt_quote(quote_id=quote_id, db=ledger.db)
    assert current is not None and current.unpaid and not current.locked
    assert current.melt_lock_expires_at == 0
    assert not current.payment_uncertain
    assert all(
        state.unspent
        for state in await ledger.db_read.get_proofs_states([p.Y for p in wallet.proofs])
    )
    assert await ledger.crud.get_blinded_messages_melt_id(
        db=ledger.db, melt_id=quote_id
    ) == []
    assert (
        await ledger.crud.get_balance(db=ledger.db, keyset=ledger.keyset)
        == balance_before
    )


@pytest.mark.asyncio
async def test_accepted_pending_melt_can_recover_failure(ledger: Ledger, monkeypatch):
    proof, quote = await create_pending_melts(ledger)
    quote = await ledger.db_write.claim_melt_quote_lease(quote)
    assert quote is not None
    quote.payment_uncertain = True
    await ledger.crud.update_melt_quote(quote=quote, db=ledger.db)

    async def accepted_payment(quote, fee_limit_msat):
        return PaymentResponse(result=PaymentResult.PENDING)

    async def failed_status(checking_id):
        return PaymentStatus(result=PaymentStatusResult.FAILED)

    backend = ledger.backends[Method.bolt11][Unit.sat]
    monkeypatch.setattr(backend, "pay_invoice", accepted_payment)
    monkeypatch.setattr(backend, "get_payment_status", failed_status)
    assert (await ledger._execute_melt_payment(quote, [proof], None)).state == "PENDING"
    current = await ledger.crud.get_melt_quote(quote_id=quote.quote, db=ledger.db)
    assert current is not None and not current.payment_uncertain and not current.locked
    assert (await ledger.get_melt_quote(quote.quote)).unpaid
    assert (await ledger.db_read.get_proofs_states([proof.Y]))[0].unspent


@pytest.mark.asyncio
async def test_melt_recovery_bounds_stalled_status_lookup(ledger: Ledger, monkeypatch):
    proof, quote = await create_pending_melts(ledger)
    monkeypatch.setattr(settings, "mint_melt_lease_seconds", 1)

    async def hung_status(checking_id):
        await asyncio.Future()

    monkeypatch.setattr(
        ledger.backends[Method.bolt11][Unit.sat], "get_payment_status", hung_status
    )
    assert (await asyncio.wait_for(ledger.get_melt_quote(quote.quote), 2)).pending
    current = await ledger.crud.get_melt_quote(quote_id=quote.quote, db=ledger.db)
    assert current is not None and not current.locked
    assert (await ledger.db_read.get_proofs_states([proof.Y]))[0].pending


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="uses FakeWallet invoices")
@pytest.mark.parametrize("settled_internally", [False, True])
@pytest.mark.parametrize("overpaid", [False, True])
async def test_expired_internal_melt_recovers_without_lightning_send(
    ledger: Ledger, wallet: Wallet, monkeypatch, settled_internally: bool, overpaid: bool
):
    await fund_wallet(ledger, wallet)
    _, proofs = await wallet.swap_to_send(wallet.proofs, 64 if overpaid else 16)
    secrets, rs, _ = await wallet.generate_n_secrets(2)
    outputs, _ = wallet._construct_outputs([1, 1], secrets, rs)
    mint_quote = await ledger.mint_quote(PostMintQuoteRequest(unit="sat", amount=16))
    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=mint_quote.request)
        )
    ).quote
    owner = await ledger._prepare_melt(
        proofs=proofs, quote=quote_id, outputs=outputs if overpaid else None
    )
    if settled_internally:
        # Model a crash between the internal transfer and consuming its proofs.
        await ledger.melt_mint_settle_internally(owner, proofs)
    await expire_melt_lease(ledger, quote_id)

    async def unexpected_send(quote, fee_limit_msat):
        pytest.fail("Recovering an internal melt must not send a Lightning payment")

    monkeypatch.setattr(
        ledger.backends[Method.bolt11][Unit.sat], "pay_invoice", unexpected_send
    )
    recovered = await ledger.get_melt_quote(quote_id)
    assert recovered.paid
    assert sum(p.amount for p in recovered.change or []) == (48 if overpaid else 0)
    assert all(
        s.spent for s in await ledger.db_read.get_proofs_states([p.Y for p in proofs])
    )
    current_mint = await ledger.crud.get_mint_quote(
        quote_id=mint_quote.quote, db=ledger.db
    )
    assert current_mint is not None and current_mint.paid
    repeated = await ledger.get_melt_quote(quote_id)
    assert repeated.paid and repeated.change == recovered.change


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="deterministic test uses FakeWallet knobs")
@pytest.mark.parametrize("raise_exception", [False, True], ids=["ERROR", "exception"])
async def test_melt_payment_response_reconciliation(
    ledger: Ledger,
    wallet: Wallet,
    monkeypatch: pytest.MonkeyPatch,
    raise_exception: bool,
):
    """Check reconciliation after an interrupted payment response."""
    await fund_wallet(ledger, wallet)
    proofs = wallet.proofs
    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=get_fake_invoice(62))
        )
    ).quote
    backend = ledger.backends[Method.bolt11][Unit.sat]
    original_pay = backend.pay_invoice
    continue_payment = asyncio.Event()
    remote_payment = None
    monkeypatch.setattr(settings, "fakewallet_pay_invoice_state", "SETTLED")
    monkeypatch.setattr(settings, "fakewallet_payment_state", "FAILED")

    async def pay_remotely(quote, fee_limit):
        await continue_payment.wait()
        return await original_pay(quote, fee_limit)

    async def lose_payment_response(quote, fee_limit):
        nonlocal remote_payment
        remote_payment = asyncio.create_task(pay_remotely(quote, fee_limit))
        if raise_exception:
            raise ConnectionError("Response lost after payment request delivery")
        return PaymentResponse(result=PaymentResult.ERROR)

    monkeypatch.setattr(backend, "pay_invoice", lose_payment_response)
    try:
        response = await ledger.melt(proofs=proofs, quote=quote_id)
        assert response.state == MeltQuoteState.pending.value
        # Check repeated reads before settlement is confirmed.
        for _ in range(2):
            quote = await ledger.get_melt_quote(quote_id)
            assert quote.pending and quote.payment_uncertain
        stored = await ledger.crud.get_melt_quote(quote_id=quote_id, db=ledger.db)
        assert stored is not None and not stored.locked
        assert stored.melt_lock_expires_at == 0
        states = await ledger.db_read.get_proofs_states([p.Y for p in proofs])
        assert all(state.pending for state in states)
        secrets, rs, _ = await wallet.generate_n_secrets(len(proofs))
        outputs, _ = wallet._construct_outputs([p.amount for p in proofs], secrets, rs)
        with pytest.raises(ProofsArePendingError):
            await ledger.swap(proofs=proofs, outputs=outputs)

        # Confirmed settlement permits automatic recovery of the reserved proofs.
        continue_payment.set()
        assert remote_payment is not None
        assert (await remote_payment).settled
        monkeypatch.setattr(settings, "fakewallet_payment_state", "SETTLED")
        assert (await ledger.get_melt_quote(quote_id)).paid
        states = await ledger.db_read.get_proofs_states([p.Y for p in proofs])
        assert all(state.spent for state in states)
    finally:
        if remote_payment is not None:
            remote_payment.cancel()
            await asyncio.gather(remote_payment, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="deterministic test uses mocked LND RPCs")
async def test_lnd_mpp_payment_response_reconciliation(
    ledger: Ledger, wallet: Wallet, monkeypatch: pytest.MonkeyPatch
):
    """Check reconciliation with an interrupted LND MPP response."""
    await fund_wallet(ledger, wallet)
    proofs = wallet.proofs
    continue_payment = asyncio.Event()
    remote_payment = None
    payment_results = []

    class MockChannel:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    class MockStub:
        def __init__(self, channel):
            pass

        async def QueryRoutes(self, request):
            return lnd_grpc.lnrpc.QueryRoutesResponse(
                routes=[lnd_grpc.lnrpc.Route(hops=[lnd_grpc.lnrpc.Hop()])]
            )

        async def SendToRouteV2(self, request):
            nonlocal remote_payment
            remote_payment = asyncio.create_task(continue_payment.wait())
            raise grpc.aio.AioRpcError(
                code=grpc.StatusCode.UNAVAILABLE,
                initial_metadata=None,
                trailing_metadata=None,
                details="Response lost after payment request delivery",
            )

        async def TrackPaymentV2(self, request):
            # Return the controlled status for this payment phase.
            settled = remote_payment is not None and remote_payment.done()
            yield lnd_grpc.lnrpc.Payment(
                status=(
                    lnd_grpc.lnrpc.Payment.SUCCEEDED
                    if settled
                    else lnd_grpc.lnrpc.Payment.FAILED
                ),
                payment_preimage="1" * 64 if settled else "0" * 64,
            )

    monkeypatch.setattr(
        lnd_grpc.grpc.aio, "secure_channel", lambda *args: MockChannel()
    )
    monkeypatch.setattr(lnd_grpc.lightningstub, "LightningStub", MockStub)
    monkeypatch.setattr(lnd_grpc.routerstub, "RouterStub", MockStub)
    backend = object.__new__(lnd_grpc.LndRPCWallet)
    backend.unit = Unit.sat
    backend.supports_mpp = True
    backend.endpoint = "localhost:10009"
    backend.combined_creds = None
    original_pay = backend.pay_invoice

    async def observe_payment(quote, fee_limit):
        result = await original_pay(quote, fee_limit)
        payment_results.append(result)
        return result

    monkeypatch.setattr(backend, "pay_invoice", observe_payment)
    monkeypatch.setitem(ledger.backends[Method.bolt11], Unit.sat, backend)
    quote = await ledger.melt_quote(
        PostMeltQuoteRequest(
            unit="sat", request=get_fake_invoice(62), options={"mpp": {"amount": 31000}}
        )
    )
    stored = await ledger.crud.get_melt_quote(quote_id=quote.quote, db=ledger.db)
    assert stored is not None
    assert (await backend.get_payment_status(stored.checking_id)).failed
    try:
        response = await ledger.melt(proofs=proofs, quote=quote.quote)
        assert payment_results[0].result == PaymentResult.ERROR
        assert payment_results[0].error_message is not None
        assert "Response lost" in payment_results[0].error_message
        assert response.state == MeltQuoteState.pending.value
        assert remote_payment is not None and not remote_payment.done()
        for _ in range(2):
            polled = await ledger.get_melt_quote(quote.quote)
            assert polled.pending and polled.payment_uncertain
        stored = await ledger.crud.get_melt_quote(quote_id=quote.quote, db=ledger.db)
        assert stored is not None and not stored.locked
        assert stored.melt_lock_expires_at == 0
        states = await ledger.db_read.get_proofs_states([p.Y for p in proofs])
        assert all(state.pending for state in states)
        secrets, rs, _ = await wallet.generate_n_secrets(len(proofs))
        outputs, _ = wallet._construct_outputs([p.amount for p in proofs], secrets, rs)
        with pytest.raises(ProofsArePendingError):
            await ledger.swap(proofs=proofs, outputs=outputs)

        continue_payment.set()
        await remote_payment
        assert (await ledger.get_melt_quote(quote.quote)).paid
        states = await ledger.db_read.get_proofs_states([p.Y for p in proofs])
        assert all(state.spent for state in states)
    finally:
        if remote_payment is not None:
            remote_payment.cancel()
            await asyncio.gather(remote_payment, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="deterministic test uses FakeWallet knobs")
async def test_melt_lease_across_ledger_startup(
    ledger: Ledger, wallet: Wallet, monkeypatch: pytest.MonkeyPatch
):
    """Check execution ownership across ledger startup."""
    await fund_wallet(ledger, wallet)
    proofs = wallet.proofs
    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=get_fake_invoice(62))
        )
    ).quote
    backend = ledger.backends[Method.bolt11][Unit.sat]
    original_pay = backend.pay_invoice
    payment_started = asyncio.Event()
    continue_payment = asyncio.Event()
    monkeypatch.setattr(settings, "fakewallet_pay_invoice_state", "SETTLED")
    monkeypatch.setattr(settings, "fakewallet_payment_state", "FAILED")

    async def pay_slowly(quote, fee_limit):
        payment_started.set()
        await continue_payment.wait()
        return await original_pay(quote, fee_limit)

    monkeypatch.setattr(backend, "pay_invoice", pay_slowly)
    second = Ledger(
        db=Database("mint", ledger.db.db_location),
        seed=ledger.seed,
        derivation_path=ledger.derivation_path,
        backends=ledger.backends,
        crud=ledger.crud,
    )
    payment = asyncio.create_task(ledger.melt(proofs=proofs, quote=quote_id))
    try:
        await asyncio.wait_for(payment_started.wait(), 5)
        await second.startup_ledger()
        await second._check_pending_proofs_and_melt_quotes()
        quote = await second.get_melt_quote(quote_id)
        assert quote.pending and quote.locked
        states = await second.db_read.get_proofs_states([p.Y for p in proofs])
        assert all(state.pending for state in states)
        secrets, rs, _ = await wallet.generate_n_secrets(len(proofs))
        outputs, _ = wallet._construct_outputs([p.amount for p in proofs], secrets, rs)
        with pytest.raises(ProofsArePendingError):
            await second.swap(proofs=proofs, outputs=outputs)

        continue_payment.set()
        assert (await payment).state == MeltQuoteState.paid.value
        quote = await second.get_melt_quote(quote_id)
        assert quote.paid and not quote.locked
        states = await second.db_read.get_proofs_states([p.Y for p in proofs])
        assert all(state.spent for state in states)
    finally:
        payment.cancel()
        await asyncio.gather(payment, return_exceptions=True)
        await second.shutdown_ledger()
