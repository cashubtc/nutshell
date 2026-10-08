import pytest
import pytest_asyncio

from cashu.core.base import MeltQuote, MeltQuoteState
from cashu.core.settings import settings
from cashu.lightning.base import PaymentResult, PaymentStatusResult
from cashu.lightning.fake import FakeInvoiceDescription, FakeWallet
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import get_fake_invoice, is_fake

pytestmark = pytest.mark.skipif(not is_fake, reason="only fakewallet")


def description(
    pay_invoice_state: str = "PAID",
    check_payment_state: str = "PAID",
    pay_err: bool = False,
    check_err: bool = False,
) -> dict:
    return {
        "pay_invoice_state": pay_invoice_state,
        "check_payment_state": check_payment_state,
        "pay_err": pay_err,
        "check_err": check_err,
    }


@pytest_asyncio.fixture(scope="function")
async def wallet(ledger: Ledger):
    wallet1 = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_fake_invoice_states",
        name="wallet_fake_invoice_states",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest.fixture(autouse=True)
def mint_wide_settings(monkeypatch):
    """Every invoice settles unless its description or the test says otherwise."""
    monkeypatch.setattr(settings, "fakewallet_pay_invoice_state", "SETTLED")
    monkeypatch.setattr(settings, "fakewallet_payment_state", "SETTLED")
    monkeypatch.setattr(settings, "fakewallet_pay_invoice_state_exception", False)
    monkeypatch.setattr(settings, "fakewallet_payment_state_exception", False)


async def quote_melt(wallet: Wallet, invoice_description):
    """Mints 100 sat and requests a melt quote for a 64 sat fake invoice."""
    mint_quote = await wallet.request_mint(100)
    proofs = await wallet.mint(amount=100, quote_id=mint_quote.quote)
    melt_quote = await wallet.melt_quote(get_fake_invoice(64, invoice_description))
    return proofs, melt_quote


async def proof_states(ledger: Ledger, proofs):
    return await ledger.db_read.get_proofs_states([p.Y for p in proofs])


def backend_quote(invoice_description) -> MeltQuote:
    return MeltQuote(
        quote="quote_id",
        method="bolt11",
        request=get_fake_invoice(64, invoice_description),
        checking_id="checking_id",
        unit="sat",
        amount=64,
        fee_reserve=2,
        state=MeltQuoteState.pending,
    )


@pytest.mark.parametrize(
    "state, pay_result, check_result",
    [
        ("SETTLED", PaymentResult.SETTLED, PaymentStatusResult.SETTLED),
        ("PAID", PaymentResult.SETTLED, PaymentStatusResult.SETTLED),
        ("PENDING", PaymentResult.PENDING, PaymentStatusResult.PENDING),
        ("FAILED", PaymentResult.FAILED, PaymentStatusResult.FAILED),
        ("UNPAID", PaymentResult.FAILED, PaymentStatusResult.FAILED),
        ("UNKNOWN", PaymentResult.ERROR, PaymentStatusResult.NOT_FOUND),
    ],
)
@pytest.mark.asyncio
async def test_backend_returns_described_states(state, pay_result, check_result):
    backend = FakeWallet()
    payment = await backend.pay_invoice(backend_quote(description(state, state)), 0)
    assert payment.result == pay_result
    assert payment.checking_id
    status = await backend.get_payment_status(payment.checking_id)
    assert status.result == check_result


@pytest.mark.asyncio
async def test_backend_error_flags():
    backend = FakeWallet()
    with pytest.raises(Exception, match="FakeWallet pay_invoice exception"):
        await backend.pay_invoice(backend_quote(description(pay_err=True)), 0)

    payment = await backend.pay_invoice(backend_quote(description(check_err=True)), 0)
    assert payment.settled
    assert payment.checking_id
    with pytest.raises(Exception, match="FakeWallet get_payment_status exception"):
        await backend.get_payment_status(payment.checking_id)


@pytest.mark.asyncio
async def test_description_overrides_mint_wide_exceptions(monkeypatch):
    monkeypatch.setattr(settings, "fakewallet_pay_invoice_state_exception", True)
    monkeypatch.setattr(settings, "fakewallet_payment_state_exception", True)
    backend = FakeWallet()
    payment = await backend.pay_invoice(backend_quote(description()), 0)
    assert payment.settled
    assert payment.checking_id
    assert (await backend.get_payment_status(payment.checking_id)).settled


@pytest.mark.parametrize(
    "plain",
    [
        "",
        "coffee",
        "[]",
        "42",
        '{"pay_invoice_state": "FAILED"}',
        '{"pay_invoice_state": "FAILED", "check_payment_state": "FAILED",'
        ' "pay_err": "no", "check_err": false}',
        '{"pay_invoice_state": "failed", "check_payment_state": "FAILED",'
        ' "pay_err": false, "check_err": false}',
    ],
)
def test_other_descriptions_are_ignored(plain):
    assert FakeInvoiceDescription.from_description(plain) is None


@pytest.mark.asyncio
async def test_failing_invoice_releases_proofs(wallet: Wallet, ledger: Ledger):
    proofs, melt_quote = await quote_melt(wallet, description("FAILED", "FAILED"))

    with pytest.raises(Exception, match="Lightning payment failed"):
        await ledger.melt(proofs=proofs, quote=melt_quote.quote)

    assert all(s.unspent for s in await proof_states(ledger, proofs))
    quote = await ledger.get_melt_quote(melt_quote.quote)
    assert quote.state == MeltQuoteState.unpaid

    # the released proofs pay the next invoice
    paying_quote = await wallet.melt_quote(get_fake_invoice(64, description()))
    response = await ledger.melt(proofs=proofs, quote=paying_quote.quote)
    assert response.state == MeltQuoteState.paid.value
    assert all(s.spent for s in await proof_states(ledger, proofs))


@pytest.mark.asyncio
async def test_pending_invoice_settles_on_check(wallet: Wallet, ledger: Ledger):
    proofs, melt_quote = await quote_melt(wallet, description("PENDING", "PAID"))

    response = await ledger.melt(proofs=proofs, quote=melt_quote.quote)
    assert response.state == MeltQuoteState.pending.value
    assert all(s.pending for s in await proof_states(ledger, proofs))

    quote = await ledger.get_melt_quote(melt_quote.quote)
    assert quote.state == MeltQuoteState.paid
    assert all(s.spent for s in await proof_states(ledger, proofs))


@pytest.mark.asyncio
async def test_pending_invoice_fails_on_check(wallet: Wallet, ledger: Ledger):
    proofs, melt_quote = await quote_melt(wallet, description("PENDING", "FAILED"))

    response = await ledger.melt(proofs=proofs, quote=melt_quote.quote)
    assert response.state == MeltQuoteState.pending.value

    quote = await ledger.get_melt_quote(melt_quote.quote)
    assert quote.state == MeltQuoteState.unpaid
    assert all(s.unspent for s in await proof_states(ledger, proofs))


@pytest.mark.asyncio
async def test_pay_err_with_failed_check_releases_proofs(
    wallet: Wallet, ledger: Ledger
):
    proofs, melt_quote = await quote_melt(
        wallet, description(check_payment_state="FAILED", pay_err=True)
    )

    with pytest.raises(Exception, match="Lightning payment failed"):
        await ledger.melt(proofs=proofs, quote=melt_quote.quote)

    assert all(s.unspent for s in await proof_states(ledger, proofs))


@pytest.mark.asyncio
async def test_check_err_keeps_melt_pending(wallet: Wallet, ledger: Ledger):
    proofs, melt_quote = await quote_melt(
        wallet, description(pay_err=True, check_err=True)
    )

    response = await ledger.melt(proofs=proofs, quote=melt_quote.quote)
    assert response.state == MeltQuoteState.pending.value

    quote = await ledger.get_melt_quote(melt_quote.quote)
    assert quote.state == MeltQuoteState.pending
    assert all(s.pending for s in await proof_states(ledger, proofs))


@pytest.mark.asyncio
async def test_plain_description_follows_mint_wide_settings(
    wallet: Wallet, ledger: Ledger, monkeypatch
):
    proofs, melt_quote = await quote_melt(wallet, "coffee")
    response = await ledger.melt(proofs=proofs, quote=melt_quote.quote)
    assert response.state == MeltQuoteState.paid.value

    monkeypatch.setattr(settings, "fakewallet_pay_invoice_state", "FAILED")
    monkeypatch.setattr(settings, "fakewallet_payment_state", "FAILED")
    proofs, melt_quote = await quote_melt(wallet, "coffee")
    with pytest.raises(Exception, match="Lightning payment failed"):
        await ledger.melt(proofs=proofs, quote=melt_quote.quote)
    assert all(s.unspent for s in await proof_states(ledger, proofs))
