import pytest
import pytest_asyncio

from cashu.core.base import PostMeltQuoteRequest, PostMintQuoteRequest
from cashu.core.helpers import sum_proofs
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
    assert not melt_quote.paid
    assert melt_quote.amount == 64
    assert melt_quote.fee_reserve == 0

    melt_quote_pre_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert not melt_quote_pre_payment.paid, "melt quote should not be paid"

    keep_proofs, send_proofs = await wallet1.split_to_send(wallet1.proofs, 64)
    await ledger.melt(proofs=send_proofs, quote=melt_quote.quote)

    melt_quote_post_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert melt_quote_post_payment.paid, "melt quote should be paid"


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only works with Regtest")
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

    melt_quote_pre_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert not melt_quote_pre_payment.paid, "melt quote should not be paid"

    assert not melt_quote.paid, "melt quote should not be paid"
    await ledger.melt(proofs=send_proofs, quote=melt_quote.quote)

    melt_quote_post_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert melt_quote_post_payment.paid, "melt quote should be paid"


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only works with FakeWallet")
async def test_mint_internal(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(128)

    mint_quote = await ledger.get_mint_quote(invoice.id)

    assert mint_quote.paid, "mint quote should be paid"

    output_amounts = [128]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)
    await ledger.mint(outputs=outputs, quote_id=invoice.id)

    await assert_err(
        ledger.mint(outputs=outputs, quote_id=invoice.id),
        "outputs have already been signed before.",
    )


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only works with Regtest")
async def test_mint_external(wallet1: Wallet, ledger: Ledger):
    quote = await ledger.mint_quote(PostMintQuoteRequest(amount=128, unit="sat"))

    mint_quote = await ledger.get_mint_quote(quote.quote)
    assert not mint_quote.paid, "mint quote not should be paid"

    await assert_err(
        wallet1.mint(128, id=quote.quote),
        "quote not paid",
    )

    pay_if_regtest(quote.request)

    mint_quote = await ledger.get_mint_quote(quote.quote)
    assert mint_quote.paid, "mint quote should be paid"

    output_amounts = [128]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)
    await ledger.mint(outputs=outputs, quote_id=quote.quote)


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
async def test_split_twice_with_same_outputs(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(128)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(128, split=[64, 64], id=invoice.id)
    inputs1 = wallet1.proofs[:1]
    inputs2 = wallet1.proofs[1:]

    output_amounts = [64]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)

    await ledger.split(proofs=inputs1, outputs=outputs)

    # try to spend other proofs with the same outputs again
    await assert_err(
        ledger.split(proofs=inputs2, outputs=outputs),
        "outputs have already been signed before.",
    )

    # try to spend inputs2 again with new outputs
    output_amounts = [64]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)

    await ledger.split(proofs=inputs2, outputs=outputs)


@pytest.mark.asyncio
async def test_mint_with_same_outputs_twice(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(128)
    pay_if_regtest(invoice.bolt11)
    output_amounts = [128]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)
    await ledger.mint(outputs=outputs, quote_id=invoice.id)

    # now try to mint with the same outputs again
    invoice2 = await wallet1.request_mint(128)
    pay_if_regtest(invoice2.bolt11)

    await assert_err(
        ledger.mint(outputs=outputs, quote_id=invoice2.id),
        "outputs have already been signed before.",
    )


@pytest.mark.asyncio
async def test_melt_with_same_outputs_twice(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(130)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(130, id=invoice.id)

    output_amounts = [128]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)

    # we use the outputs once for minting
    invoice2 = await wallet1.request_mint(128)
    pay_if_regtest(invoice2.bolt11)
    await ledger.mint(outputs=outputs, quote_id=invoice2.id)

    # use the same outputs for melting
    mint_quote = await ledger.mint_quote(PostMintQuoteRequest(unit="sat", amount=128))
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=mint_quote.request)
    )
    await assert_err(
        ledger.melt(proofs=wallet1.proofs, quote=melt_quote.quote, outputs=outputs),
        "outputs have already been signed before.",
    )


@pytest.mark.asyncio
async def test_melt_with_less_inputs_than_invoice(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(32)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(32, id=invoice.id)

    # outputs for fee return
    output_amounts = [1, 1, 1, 1]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)

    # create a mint quote to pay
    mint_quote = await ledger.mint_quote(PostMintQuoteRequest(unit="sat", amount=128))
    # prepare melt quote
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=mint_quote.request)
    )

    assert melt_quote.amount + melt_quote.fee_reserve > sum_proofs(wallet1.proofs)

    # try to pay with not enough inputs
    await assert_err(
        ledger.melt(proofs=wallet1.proofs, quote=melt_quote.quote, outputs=outputs),
        "not enough inputs provided for melt",
    )


@pytest.mark.asyncio
async def test_melt_with_more_inputs_than_invoice(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(130)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(130, split=[64, 64, 2], id=invoice.id)

    # outputs for fee return
    output_amounts = [1, 1, 1, 1]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)

    # create a mint quote to pay
    mint_quote = await ledger.mint_quote(PostMintQuoteRequest(unit="sat", amount=128))
    # prepare melt quote
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=mint_quote.request)
    )
    # fees are 0 because it's internal
    assert melt_quote.fee_reserve == 0

    # make sure we have more inputs than the melt quote needs
    assert sum_proofs(wallet1.proofs) >= melt_quote.amount + melt_quote.fee_reserve
    payment_proof, return_outputs = await ledger.melt(
        proofs=wallet1.proofs, quote=melt_quote.quote, outputs=outputs
    )
    # we get 2 sats back because we overpaid
    assert sum([o.amount for o in return_outputs]) == 2


@pytest.mark.asyncio
async def test_check_proof_state(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)

    keep_proofs, send_proofs = await wallet1.split_to_send(wallet1.proofs, 10)

    proof_states = await ledger.check_proofs_state(
        secrets=[p.secret for p in send_proofs]
    )
    assert all([p.state.value == "UNSPENT" for p in proof_states])
