from typing import List, Tuple

import pytest
import pytest_asyncio

from cashu.core.base import MeltQuote, MeltQuoteState, Proof
from cashu.core.errors import LightningPaymentFailedError, OutputsAlreadySignedError
from cashu.core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from cashu.core.settings import settings
from cashu.lightning.base import PaymentResult
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    get_real_invoice,
    is_deprecated_api_only,
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
        db="test_data/wallet_mint_api_deprecated",
        name="wallet_mint_api_deprecated",
    )
    await wallet1.load_mint()
    yield wallet1


async def create_pending_melts(
    ledger: Ledger, check_id: str = "checking_id"
) -> Tuple[Proof, MeltQuote]:
    """Helper function for startup tests for fakewallet. Creates fake pending melt
    quote and fake proofs that are in the pending table that look like they're being
    used to pay the pending melt quote."""
    quote_id = "quote_id"
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
@pytest.mark.skipif(
    not is_fake or is_deprecated_api_only,
    reason="only fakewallet and non-deprecated api",
)
async def test_pending_melt_outputs_already_signed_regression_(wallet, ledger: Ledger):
    settings.fakewallet_payment_state = PaymentResult.PENDING.name
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
        OutputsAlreadySignedError.detail,
    )


@pytest.mark.asyncio
@pytest.mark.skipif(
    not is_fake or is_deprecated_api_only,
    reason="only fakewallet and non-deprecated api",
)
async def test_settled_melt_outputs_already_signed_regression(wallet, ledger: Ledger):
    settings.fakewallet_payment_state = PaymentResult.SETTLED.name
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
    response1 = await ledger.melt(
        proofs=proofs1, quote=melt_quote1.quote, outputs=change_outputs
    )
    assert response1.state == "PAID"

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
    settings.fakewallet_payment_state = PaymentResult.SETTLED.name

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
    settings.fakewallet_payment_state = PaymentResult.PENDING.name

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
    settings.fakewallet_payment_state = PaymentResult.FAILED.name

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
async def test_fakewallet_pending_quote_get_melt_quote_unknown(ledger: Ledger):
    """Startup routine test. Expects that a pending proofs are removed form the pending db
    after the startup routine determines that the associated melt quote was paid."""
    pending_proof, quote = await create_pending_melts(ledger)
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending
    settings.fakewallet_payment_state = PaymentResult.UNKNOWN.name

    # get_melt_quote(..., rollback_unknown=True) should check the payment status and update the db
    quote2 = await ledger.get_melt_quote(quote_id=quote.quote, rollback_unknown=True)
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
    settings.fakewallet_payment_state = PaymentResult.SETTLED.name
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
    settings.fakewallet_payment_state = PaymentResult.FAILED.name
    settings.fakewallet_pay_invoice_state = PaymentResult.FAILED.name
    try:
        await ledger.melt(proofs=wallet.proofs, quote=quote_id)
        raise AssertionError("Expected LightningPaymentFailedError")
    except LightningPaymentFailedError:
        pass

    settings.fakewallet_payment_state = PaymentResult.UNKNOWN.name
    settings.fakewallet_pay_invoice_state = PaymentResult.FAILED.name
    try:
        await ledger.melt(proofs=wallet.proofs, quote=quote_id)
        raise AssertionError("Expected LightningPaymentFailedError")
    except LightningPaymentFailedError:
        pass

    settings.fakewallet_payment_state = PaymentResult.FAILED.name
    settings.fakewallet_pay_invoice_state = PaymentResult.UNKNOWN.name
    try:
        await ledger.melt(proofs=wallet.proofs, quote=quote_id)
        raise AssertionError("Expected LightningPaymentFailedError")
    except LightningPaymentFailedError:
        pass

    settings.fakewallet_payment_state = PaymentResult.UNKNOWN.name
    settings.fakewallet_pay_invoice_state = PaymentResult.UNKNOWN.name
    try:
        await ledger.melt(proofs=wallet.proofs, quote=quote_id)
        raise AssertionError("Expected LightningPaymentFailedError")
    except LightningPaymentFailedError:
        pass


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
    settings.fakewallet_payment_state = PaymentResult.SETTLED.name

    melt_response = await ledger.melt(proofs=wallet.proofs, quote=quote_id)
    assert melt_response.state == MeltQuoteState.pending.value
    # expect that proofs are pending
    states = await ledger.db_read.get_proofs_states([p.Y for p in wallet.proofs])
    assert all([s.pending for s in states])


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
    settings.fakewallet_payment_state = PaymentResult.PENDING.name

    melt_response = await ledger.melt(proofs=wallet.proofs, quote=quote_id)
    assert melt_response.state == MeltQuoteState.pending.value
    # expect that proofs are pending
    states = await ledger.db_read.get_proofs_states([p.Y for p in wallet.proofs])
    assert all([s.pending for s in states])


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_melt_lightning_pay_invoice_exception_exception(
    ledger: Ledger, wallet: Wallet
):
    """Simulates the case where pay_invoice and get_payment_status raise an exception (due to network issues for example)."""
    settings.mint_disable_melt_on_error = True
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
    settings.fakewallet_payment_state_exception = True
    settings.fakewallet_pay_invoice_state_exception = True

    # we expect a pending melt quote because something has gone wrong (for example has lost connection to backend)
    resp = await ledger.melt(proofs=wallet.proofs, quote=quote_id)
    assert resp.state == MeltQuoteState.pending.value

    # the mint should be locked now and not allow any other melts until it is restarted
    quote_id = (
        await ledger.melt_quote(
            PostMeltQuoteRequest(unit="sat", request=invoice_62_sat)
        )
    ).quote
    await assert_err(
        ledger.melt(proofs=wallet.proofs, quote=quote_id),
        "Melt is disabled. Please contact the operator.",
    )


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_mint_melt_different_units(ledger: Ledger, wallet: Wallet):
    """Mint and melt different units."""
    # load the wallet
    mint_quote = await wallet.request_mint(64)
    await wallet.mint(64, quote_id=mint_quote.quote)

    amount = 32

    # mint quote in sat
    sat_mint_quote = await ledger.mint_quote(
        quote_request=PostMintQuoteRequest(amount=amount, unit="sat")
    )
    sat_invoice = sat_mint_quote.request
    assert sat_mint_quote.paid is False

    # melt quote in usd
    usd_melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="usd", request=sat_invoice)
    )
    assert usd_melt_quote.paid is False

    # pay melt quote with usd
    await ledger.melt(proofs=wallet.proofs, quote=usd_melt_quote.quote)

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
