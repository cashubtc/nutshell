import asyncio
from typing import List, Tuple

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
from cashu.core.errors import (
    LightningPaymentFailedError,
    OutputsAlreadySignedError,
    OutputsArePendingError,
    TransactionError,
)
from cashu.core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from cashu.core.settings import settings
from cashu.lightning.base import (
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    PaymentStatusResult,
)
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    get_real_invoice,
    is_fake,
    is_regtest,
    pay_if_regtest,
)

SEED = "TEST_PRIVATE_KEY"
DERIVATION_PATH = "m/0'/0'/0'"
DECRYPTON_KEY = "testdecryptionkey"
ENCRYPTED_SEED = "U2FsdGVkX1_7UU_-nVBMBWDy_9yDu4KeYb7MH8cJTYQGD4RWl82PALH8j-HKzTrI"


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        assert exc.args[0] == msg, Exception(
            f"Expected error: {msg}, got: {exc.args[0]}"
        )


def assert_amt(proofs: List[Proof], expected: int):
    """Assert amounts the proofs contain."""
    assert [p.amount for p in proofs] == expected


@pytest_asyncio.fixture(scope="function")
async def wallet(ledger: Ledger):
    wallet1 = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_mint_melt",
        name="wallet_mint_melt",
    )
    await wallet1.load_mint()
    yield wallet1


async def create_pending_melts(
    ledger: Ledger, check_id: str = "checking_id", quote_id: str = "quote_id"
) -> Tuple[Proof, MeltQuote]:
    """Helper function for startup tests for fakewallet. Creates fake pending melt
    quote and fake proofs that are in the pending table that look like they're being
    used to pay the pending melt quote."""
    quote = MeltQuote(
        quote=quote_id,
        method="bolt11",
        request="asdasd",
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
    pending_proof = Proof(amount=123, C="asdasd", secret="asdasd", id=ledger.keyset.id)
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
        request="concurrent-finalize-request",
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
    await ledger.crud.bump_keyset_balance(
        db=ledger.db,
        keyset=ledger.keyset,
        amount=-proof.amount,
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

    payment_task = asyncio.create_task(
        ledger._execute_melt_payment(quote, [proof], outputs=None)
    )
    await payment_started.wait()
    try:
        lookup_result = await ledger.get_melt_quote(quote.quote)
    finally:
        release_payment.set()
    payment_result = await payment_task
    retry_result = await ledger._finalize_melt_paid(
        quote.quote,
        fee_paid=1,
        preimage="0" * 64,
    )
    stale_failure_result = await ledger._finalize_melt_failed(quote.quote)

    assert lookup_result.paid
    assert payment_result.state == MeltQuoteState.paid.value
    assert stale_failure_result.paid
    assert (
        lookup_result.change
        == payment_result.change
        == retry_result.change
        == stale_failure_result.change
    )
    assert lookup_result.change
    assert sum(promise.amount for promise in lookup_result.change) == 5

    persisted = await ledger.get_melt_quote(quote.quote)
    assert persisted.paid
    assert persisted.change == lookup_result.change

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
    assert len(signed) == len(lookup_result.change)
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

    invoice_64_sat = "lnbcrt640n1pn0r3tfpp5e30xac756gvd26cn3tgsh8ug6ct555zrvl7vsnma5cwp4g7auq5qdqqcqzzsxqyz5vqsp5xfhtzg0y3mekv6nsdnj43c346smh036t4f8gcfa2zwpxzwcryqvs9qxpqysgqw5juev8y3zxpdu0mvdrced5c6a852f9x7uh57g6fgjgcg5muqzd5474d7xgh770frazel67eejfwelnyr507q46hxqehala880rhlqspw07ta0"
    invoice_62_sat = "lnbcrt620n1pn0r3vepp5zljn7g09fsyeahl4rnhuy0xax2puhua5r3gspt7ttlfrley6valqdqqcqzzsxqyz5vqsp577h763sel3q06tfnfe75kvwn5pxn344sd5vnays65f9wfgx4fpzq9qxpqysgqg3re9afz9rwwalytec04pdhf9mvh3e2k4r877tw7dr4g0fvzf9sny5nlfggdy6nduy2dytn06w50ls34qfldgsj37x0ymxam0a687mspp0ytr8"

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
    response1 = await ledger.melt(
        proofs=proofs1, quote=melt_quote1.quote, outputs=change_outputs
    )
    assert response1.state == "PENDING"

    await assert_err(
        ledger.melt(
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

    invoice_64_sat = "lnbcrt640n1pn0r3tfpp5e30xac756gvd26cn3tgsh8ug6ct555zrvl7vsnma5cwp4g7auq5qdqqcqzzsxqyz5vqsp5xfhtzg0y3mekv6nsdnj43c346smh036t4f8gcfa2zwpxzwcryqvs9qxpqysgqw5juev8y3zxpdu0mvdrced5c6a852f9x7uh57g6fgjgcg5muqzd5474d7xgh770frazel67eejfwelnyr507q46hxqehala880rhlqspw07ta0"
    invoice_62_sat = "lnbcrt620n1pn0r3vepp5zljn7g09fsyeahl4rnhuy0xax2puhua5r3gspt7ttlfrley6valqdqqcqzzsxqyz5vqsp577h763sel3q06tfnfe75kvwn5pxn344sd5vnays65f9wfgx4fpzq9qxpqysgqg3re9afz9rwwalytec04pdhf9mvh3e2k4r877tw7dr4g0fvzf9sny5nlfggdy6nduy2dytn06w50ls34qfldgsj37x0ymxam0a687mspp0ytr8"

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
        ledger.melt(proofs=proofs1, quote=melt_quote1.quote, outputs=change_outputs),
        "Lightning payment failed.",
    )

    settings.fakewallet_payment_state = PaymentStatusResult.SETTLED.name
    settings.fakewallet_pay_invoice_state = PaymentResult.SETTLED.name

    response2 = await ledger.melt(
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

    invoice_64_sat = "lnbcrt640n1pn0r3tfpp5e30xac756gvd26cn3tgsh8ug6ct555zrvl7vsnma5cwp4g7auq5qdqqcqzzsxqyz5vqsp5xfhtzg0y3mekv6nsdnj43c346smh036t4f8gcfa2zwpxzwcryqvs9qxpqysgqw5juev8y3zxpdu0mvdrced5c6a852f9x7uh57g6fgjgcg5muqzd5474d7xgh770frazel67eejfwelnyr507q46hxqehala880rhlqspw07ta0"
    invoice_62_sat = "lnbcrt620n1pn0r3vepp5zljn7g09fsyeahl4rnhuy0xax2puhua5r3gspt7ttlfrley6valqdqqcqzzsxqyz5vqsp577h763sel3q06tfnfe75kvwn5pxn344sd5vnays65f9wfgx4fpzq9qxpqysgqg3re9afz9rwwalytec04pdhf9mvh3e2k4r877tw7dr4g0fvzf9sny5nlfggdy6nduy2dytn06w50ls34qfldgsj37x0ymxam0a687mspp0ytr8"

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
    await ledger.melt(proofs=proofs1, quote=melt_quote1.quote, outputs=change_outputs)

    await assert_err(
        ledger.melt(
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

    # An error does not prove that the payment failed, so the proofs cannot be released.
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

    response = await ledger._execute_melt_payment(quote, [proof], outputs=None)
    assert response.state == MeltQuoteState.paid.value

    states = await ledger.db_read.get_proofs_states([proof.Y])
    assert states[0].spent


@pytest.mark.asyncio
async def test_execute_melt_payment_and_status_exceptions_keep_pending(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch
):
    proof, quote = await create_pending_melts(ledger)
    backend = ledger.backends[Method.bolt11][Unit.sat]

    async def payment_exception(quote: MeltQuote, fee_limit_msat: int):
        raise RuntimeError("payment error")

    async def status_exception(checking_id: str):
        raise RuntimeError("status error")

    monkeypatch.setattr(backend, "pay_invoice", payment_exception)
    monkeypatch.setattr(backend, "get_payment_status", status_exception)

    response = await ledger._execute_melt_payment(quote, [proof], outputs=None)
    assert response.state == MeltQuoteState.pending.value

    states = await ledger.db_read.get_proofs_states([proof.Y])
    assert states[0].pending
    assert not ledger.disable_melt


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_melt_lightning_pay_invoice_settled(ledger: Ledger, wallet: Wallet):
    mint_quote = await wallet.request_mint(64)
    await ledger.get_mint_quote(mint_quote.quote)  # fakewallet: set the quote to paid
    await wallet.mint(64, quote_id=mint_quote.quote)
    # invoice_64_sat = "lnbcrt640n1pn0r3tfpp5e30xac756gvd26cn3tgsh8ug6ct555zrvl7vsnma5cwp4g7auq5qdqqcqzzsxqyz5vqsp5xfhtzg0y3mekv6nsdnj43c346smh036t4f8gcfa2zwpxzwcryqvs9qxpqysgqw5juev8y3zxpdu0mvdrced5c6a852f9x7uh57g6fgjgcg5muqzd5474d7xgh770frazel67eejfwelnyr507q46hxqehala880rhlqspw07ta0"
    invoice_62_sat = "lnbcrt620n1pn0r3vepp5zljn7g09fsyeahl4rnhuy0xax2puhua5r3gspt7ttlfrley6valqdqqcqzzsxqyz5vqsp577h763sel3q06tfnfe75kvwn5pxn344sd5vnays65f9wfgx4fpzq9qxpqysgqg3re9afz9rwwalytec04pdhf9mvh3e2k4r877tw7dr4g0fvzf9sny5nlfggdy6nduy2dytn06w50ls34qfldgsj37x0ymxam0a687mspp0ytr8"
    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=invoice_62_sat)
        )
    ).quote
    # quote = await ledger.get_melt_quote(quote_id)
    settings.fakewallet_payment_state = PaymentStatusResult.SETTLED.name
    settings.fakewallet_pay_invoice_state = PaymentResult.SETTLED.name
    melt_response = await ledger.melt(proofs=wallet.proofs, quote=quote_id)
    assert melt_response.state == MeltQuoteState.paid.value


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_melt_lightning_pay_invoice_failed_failed(ledger: Ledger, wallet: Wallet):
    mint_quote = await wallet.request_mint(64)
    await ledger.get_mint_quote(mint_quote.quote)  # fakewallet: set the quote to paid
    await wallet.mint(64, quote_id=mint_quote.quote)
    # invoice_64_sat = "lnbcrt640n1pn0r3tfpp5e30xac756gvd26cn3tgsh8ug6ct555zrvl7vsnma5cwp4g7auq5qdqqcqzzsxqyz5vqsp5xfhtzg0y3mekv6nsdnj43c346smh036t4f8gcfa2zwpxzwcryqvs9qxpqysgqw5juev8y3zxpdu0mvdrced5c6a852f9x7uh57g6fgjgcg5muqzd5474d7xgh770frazel67eejfwelnyr507q46hxqehala880rhlqspw07ta0"
    invoice_62_sat = "lnbcrt620n1pn0r3vepp5zljn7g09fsyeahl4rnhuy0xax2puhua5r3gspt7ttlfrley6valqdqqcqzzsxqyz5vqsp577h763sel3q06tfnfe75kvwn5pxn344sd5vnays65f9wfgx4fpzq9qxpqysgqg3re9afz9rwwalytec04pdhf9mvh3e2k4r877tw7dr4g0fvzf9sny5nlfggdy6nduy2dytn06w50ls34qfldgsj37x0ymxam0a687mspp0ytr8"
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
    invoice = "lnbcrt620n1pn0r3vepp5zljn7g09fsyeahl4rnhuy0xax2puhua5r3gspt7ttlfrley6valqdqqcqzzsxqyz5vqsp577h763sel3q06tfnfe75kvwn5pxn344sd5vnays65f9wfgx4fpzq9qxpqysgqg3re9afz9rwwalytec04pdhf9mvh3e2k4r877tw7dr4g0fvzf9sny5nlfggdy6nduy2dytn06w50ls34qfldgsj37x0ymxam0a687mspp0ytr8"
    quote_id = (
        await ledger.melt_quote(PostMeltQuoteRequest(unit="sat", request=invoice))
    ).quote

    settings.fakewallet_payment_state = PaymentStatusResult.ERROR.name
    settings.fakewallet_pay_invoice_state = PaymentResult.ERROR.name
    response = await ledger.melt(proofs=wallet.proofs, quote=quote_id)

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
    invoice_62_sat = "lnbcrt620n1pn0r3vepp5zljn7g09fsyeahl4rnhuy0xax2puhua5r3gspt7ttlfrley6valqdqqcqzzsxqyz5vqsp577h763sel3q06tfnfe75kvwn5pxn344sd5vnays65f9wfgx4fpzq9qxpqysgqg3re9afz9rwwalytec04pdhf9mvh3e2k4r877tw7dr4g0fvzf9sny5nlfggdy6nduy2dytn06w50ls34qfldgsj37x0ymxam0a687mspp0ytr8"
    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=invoice_62_sat)
        )
    ).quote
    settings.fakewallet_pay_invoice_state = PaymentResult.FAILED.name
    settings.fakewallet_payment_state = PaymentStatusResult.SETTLED.name

    melt_response = await ledger.melt(proofs=wallet.proofs, quote=quote_id)
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
    invoice_62_sat = "lnbcrt620n1pn0r3vepp5zljn7g09fsyeahl4rnhuy0xax2puhua5r3gspt7ttlfrley6valqdqqcqzzsxqyz5vqsp577h763sel3q06tfnfe75kvwn5pxn344sd5vnays65f9wfgx4fpzq9qxpqysgqg3re9afz9rwwalytec04pdhf9mvh3e2k4r877tw7dr4g0fvzf9sny5nlfggdy6nduy2dytn06w50ls34qfldgsj37x0ymxam0a687mspp0ytr8"
    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=invoice_62_sat)
        )
    ).quote
    settings.fakewallet_pay_invoice_state = PaymentResult.FAILED.name
    settings.fakewallet_payment_state = PaymentStatusResult.PENDING.name

    melt_response = await ledger.melt(proofs=wallet.proofs, quote=quote_id)
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
    invoice_62_sat = "lnbcrt620n1pn0r3vepp5zljn7g09fsyeahl4rnhuy0xax2puhua5r3gspt7ttlfrley6valqdqqcqzzsxqyz5vqsp577h763sel3q06tfnfe75kvwn5pxn344sd5vnays65f9wfgx4fpzq9qxpqysgqg3re9afz9rwwalytec04pdhf9mvh3e2k4r877tw7dr4g0fvzf9sny5nlfggdy6nduy2dytn06w50ls34qfldgsj37x0ymxam0a687mspp0ytr8"
    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=invoice_62_sat)
        )
    ).quote
    monkeypatch.setattr(settings, "fakewallet_payment_state_exception", True)
    monkeypatch.setattr(settings, "fakewallet_pay_invoice_state_exception", True)

    resp = await ledger.melt(proofs=wallet.proofs, quote=quote_id)
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

    # mint quote in sat
    sat_mint_quote = await ledger.mint_quote(
        quote_request=PostMintQuoteRequest(amount=amount, unit="sat")
    )
    sat_invoice = sat_mint_quote.request
    assert sat_mint_quote.state != MintQuoteState.paid

    # melt quote in usd
    usd_melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="usd", request=sat_invoice)
    )
    assert usd_melt_quote.state != MeltQuoteState.paid

    # pay melt quote with usd
    await ledger.melt(proofs=wallet_usd.proofs, quote=usd_melt_quote.quote)

    output_amounts = [32]

    secrets, rs, derivation_paths = await wallet.generate_n_secrets(len(output_amounts))
    outputs, rs = wallet._construct_outputs(output_amounts, secrets, rs)

    # mint in sat
    mint_resp = await ledger.mint(outputs=outputs, quote_id=sat_mint_quote.quote)

    assert len(mint_resp) == len(outputs)


# Tests for unique pending melt quote checking_id constraint
@pytest.mark.asyncio
async def test_set_melt_quote_pending_without_checking_id(ledger: Ledger):
    """Test that setting a melt quote as pending without a checking_id raises an error."""
    from cashu.core.errors import TransactionError

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
    from cashu.core.errors import TransactionError

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
        raise AssertionError("Expected TransactionError")
    except TransactionError as e:
        assert "Melt quote already paid or pending." in str(e)

    # Verify the second quote is still unpaid
    quote2_db = await ledger.crud.get_melt_quote(
        quote_id="quote_id_dup_second", db=ledger.db
    )
    assert quote2_db.state == MeltQuoteState.unpaid


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

    assert_err(
        wallet.melt(
            proofs=proofs2,
            invoice=invoice,
            fee_reserve_sat=melt_quote2.fee_reserve,
            quote_id=melt_quote2.quote,
        ),
        "Melt quote already paid or pending.",
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
        else "lnbcrt640n1pn0r3tfpp5e30xac756gvd26cn3tgsh8ug6ct555zrvl7vsnma5cwp4g7auq5qdqqcqzzsxqyz5vqsp5xfhtzg0y3mekv6nsdnj43c346smh036t4f8gcfa2zwpxzwcryqvs9qxpqysgqw5juev8y3zxpdu0mvdrced5c6a852f9x7uh57g6fgjgcg5muqzd5474d7xgh770frazel67eejfwelnyr507q46hxqehala880rhlqspw07ta0"
    )
    melt_quote1 = await wallet.melt_quote(invoice)
    melt_quote2 = await wallet.melt_quote(invoice)

    assert melt_quote1.quote != melt_quote2.quote

    responses = await asyncio.gather(
        ledger.melt(proofs=proofs1, quote=melt_quote1.quote),
        ledger.melt(proofs=proofs2, quote=melt_quote2.quote),
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
    assert not any(s.pending for s in states), (
        "Proofs from failed melt request stuck in pending!"
    )


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
        ledger.melt(proofs=usd_proofs, quote=sat_melt_quote.quote, outputs=[]),
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
        ledger.melt(proofs=proofs, quote=sat_melt_quote.quote, outputs=[]),
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
    await ledger.crud.bump_keyset_balance(
        db=ledger.db,
        keyset=ledger.keyset,
        amount=-proof.amount,
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

    with pytest.raises(TransactionError, match="mint quote already issued"):
        await ledger._execute_melt_payment(
            internal_melt_quote,
            [proof],
            outputs=[],
        )

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

    invoice_64_sat = "lnbcrt640n1pn0r3tfpp5e30xac756gvd26cn3tgsh8ug6ct555zrvl7vsnma5cwp4g7auq5qdqqcqzzsxqyz5vqsp5xfhtzg0y3mekv6nsdnj43c346smh036t4f8gcfa2zwpxzwcryqvs9qxpqysgqw5juev8y3zxpdu0mvdrced5c6a852f9x7uh57g6fgjgcg5muqzd5474d7xgh770frazel67eejfwelnyr507q46hxqehala880rhlqspw07ta0"

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
