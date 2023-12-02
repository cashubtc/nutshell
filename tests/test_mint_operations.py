import pytest
import pytest_asyncio

from cashu.core.base import PostMeltQuoteRequest
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import get_real_invoice, is_fake, is_regtest, pay_if_regtest


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        if msg not in str(exc.args[0]):
            raise Exception(f"Expected error: {msg}, got: {exc.args[0]}")
        return
    raise Exception(f"Expected error: {msg}, got no error")


@pytest_asyncio.fixture(scope="function")
async def wallet1(ledger: Ledger):
    wallet1 = await Wallet1.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1",
        name="wallet1",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only works with FakeWallet")
async def test_melt_internal(wallet1: Wallet, ledger: Ledger):
    # mint twice so we have enough to pay the second invoice back
    invoice = await wallet1.request_mint(128)
    await wallet1.mint(128, id=invoice.id)
    assert wallet1.balance == 128

    # create a mint quote so that we can melt to it internally
    invoice_to_pay = await wallet1.request_mint(64)
    invoice_payment_request = invoice_to_pay.bolt11

    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice_payment_request, unit="sat")
    )
    assert melt_quote.amount == 64
    assert melt_quote.fee_reserve == 0
    keep_proofs, send_proofs = await wallet1.split_to_send(wallet1.proofs, 64)
    await ledger.melt(proofs=send_proofs, quote=melt_quote.quote)


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only works with FakeWallet")
async def test_melt_external(wallet1: Wallet, ledger: Ledger):
    # mint twice so we have enough to pay the second invoice back
    invoice = await wallet1.request_mint(128)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(128, id=invoice.id)
    assert wallet1.balance == 128

    invoice_dict = get_real_invoice(64)
    invoice_payment_request = invoice_dict["payment_request"]

    mint_quote = await wallet1.get_pay_amount_with_fees(invoice_payment_request)
    total_amount = mint_quote.amount + mint_quote.fee_reserve
    keep_proofs, send_proofs = await wallet1.split_to_send(wallet1.proofs, total_amount)
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice_payment_request, unit="sat")
    )
    await ledger.melt(proofs=send_proofs, quote=melt_quote.quote)


@pytest.mark.asyncio
async def test_split(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)

    keep_proofs, send_proofs = await wallet1.split_to_send(wallet1.proofs, 10)
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(len(send_proofs))
    outputs, rs = wallet1._construct_outputs(
        [p.amount for p in send_proofs], secrets, rs
    )

    promises = await ledger.split(proofs=send_proofs, outputs=outputs)
    assert len(promises) == len(outputs)
    assert [p.amount for p in promises] == [p.amount for p in outputs]


@pytest.mark.asyncio
async def test_split_with_input_less_than_outputs(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)

    keep_proofs, send_proofs = await wallet1.split_to_send(
        wallet1.proofs, 10, set_reserved=False
    )

    all_send_proofs = send_proofs + keep_proofs

    # generate outputs for all proofs, not only the sent ones
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(all_send_proofs)
    )
    outputs, rs = wallet1._construct_outputs(
        [p.amount for p in all_send_proofs], secrets, rs
    )

    await assert_err(
        ledger.split(proofs=send_proofs, outputs=outputs),
        "inputs do not have same amount as outputs.",
    )

    # make sure we can still spend our tokens
    keep_proofs, send_proofs = await wallet1.split(wallet1.proofs, 10)


@pytest.mark.asyncio
async def test_split_with_input_more_than_outputs(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(128)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(128, id=invoice.id)

    inputs = wallet1.proofs

    # less outputs than inputs
    output_amounts = [8]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)

    await assert_err(
        ledger.split(proofs=inputs, outputs=outputs),
        "inputs do not have same amount as outputs",
    )

    # make sure we can still spend our tokens
    keep_proofs, send_proofs = await wallet1.split(inputs, 10)


@pytest.mark.asyncio
async def test_check_proof_state(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)

    keep_proofs, send_proofs = await wallet1.split_to_send(wallet1.proofs, 10)

    spendable, pending = await ledger.check_proof_state(proofs=send_proofs)
    assert sum(spendable) == len(send_proofs)
    assert sum(pending) == 0
