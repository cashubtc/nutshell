import pytest
import pytest_asyncio

from cashu.core.base import MeltQuoteState
from cashu.core.helpers import sum_proofs
from cashu.core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from cashu.core.nuts import nut20
from cashu.core.settings import settings
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
    mint_quote = await wallet1.request_mint(128)
    await ledger.get_mint_quote(mint_quote.quote)
    await wallet1.mint(128, quote_id=mint_quote.quote)
    assert wallet1.balance == 128

    # create a mint quote so that we can melt to it internally
    mint_quote_to_pay = await wallet1.request_mint(64)
    invoice_payment_request = mint_quote_to_pay.request

    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice_payment_request, unit="sat")
    )
    assert not melt_quote.paid
    assert melt_quote.state == MeltQuoteState.unpaid.value

    assert melt_quote.amount == 64
    assert melt_quote.fee_reserve == 0

    if not settings.debug_mint_only_deprecated:
        melt_quote_response_pre_payment = await wallet1.get_melt_quote(melt_quote.quote)
        assert (
            not melt_quote_response_pre_payment.state == MeltQuoteState.paid.value
        ), "melt quote should not be paid"
        assert melt_quote_response_pre_payment.amount == 64

    melt_quote_pre_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert not melt_quote_pre_payment.paid, "melt quote should not be paid"
    assert melt_quote_pre_payment.unpaid

    keep_proofs, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 64)
    await ledger.melt(proofs=send_proofs, quote=melt_quote.quote)

    melt_quote_post_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert melt_quote_post_payment.paid, "melt quote should be paid"
    assert melt_quote_post_payment.paid


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only works with Regtest")
async def test_melt_external(wallet1: Wallet, ledger: Ledger):
    # mint twice so we have enough to pay the second invoice back
    mint_quote = await wallet1.request_mint(128)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(128, quote_id=mint_quote.quote)
    assert wallet1.balance == 128

    invoice_dict = get_real_invoice(64)
    invoice_payment_request = invoice_dict["payment_request"]

    mint_quote = await wallet1.melt_quote(invoice_payment_request)
    assert not mint_quote.paid, "mint quote should not be paid"
    assert mint_quote.state == MeltQuoteState.unpaid.value

    total_amount = mint_quote.amount + mint_quote.fee_reserve
    keep_proofs, send_proofs = await wallet1.swap_to_send(wallet1.proofs, total_amount)
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice_payment_request, unit="sat")
    )

    if not settings.debug_mint_only_deprecated:
        melt_quote_response_pre_payment = await wallet1.get_melt_quote(melt_quote.quote)
        assert (
            melt_quote_response_pre_payment.state == MeltQuoteState.unpaid.value
        ), "melt quote should not be paid"
        assert melt_quote_response_pre_payment.amount == melt_quote.amount

    melt_quote_pre_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert not melt_quote_pre_payment.paid, "melt quote should not be paid"
    assert melt_quote_pre_payment.unpaid

    assert not melt_quote.paid, "melt quote should not be paid"
    await ledger.melt(proofs=send_proofs, quote=melt_quote.quote)

    melt_quote_post_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert melt_quote_post_payment.paid, "melt quote should be paid"
    assert melt_quote_post_payment.paid


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only works with FakeWallet")
async def test_mint_internal(wallet1: Wallet, ledger: Ledger):
    wallet_mint_quote = await wallet1.request_mint(128)
    await ledger.get_mint_quote(wallet_mint_quote.quote)
    mint_quote = await ledger.get_mint_quote(wallet_mint_quote.quote)

    assert mint_quote.paid, "mint quote should be paid"

    if not settings.debug_mint_only_deprecated:
        mint_quote_resp = await wallet1.get_mint_quote(mint_quote.quote)
        assert (
            mint_quote_resp.state == MeltQuoteState.paid.value
        ), "mint quote should be paid"

    output_amounts = [128]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)
    assert wallet_mint_quote.privkey
    signature = nut20.sign_mint_quote(
        mint_quote.quote, outputs, wallet_mint_quote.privkey
    )
    await ledger.mint(outputs=outputs, quote_id=mint_quote.quote, signature=signature)

    await assert_err(
        ledger.mint(outputs=outputs, quote_id=mint_quote.quote),
        "outputs have already been signed before.",
    )

    mint_quote_after_payment = await ledger.get_mint_quote(mint_quote.quote)
    assert mint_quote_after_payment.issued, "mint quote should be issued"
    assert mint_quote_after_payment.issued


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only works with Regtest")
async def test_mint_external(wallet1: Wallet, ledger: Ledger):
    quote = await wallet1.request_mint(128)

    mint_quote = await ledger.get_mint_quote(quote.quote)
    assert not mint_quote.paid, "mint quote already paid"
    assert mint_quote.unpaid

    if not settings.debug_mint_only_deprecated:
        mint_quote_resp = await wallet1.get_mint_quote(quote.quote)
        assert not mint_quote_resp.paid, "mint quote should not be paid"

    await assert_err(
        wallet1.mint(128, quote_id=quote.quote),
        "quote not paid",
    )

    await pay_if_regtest(quote.request)

    mint_quote = await ledger.get_mint_quote(quote.quote)
    assert mint_quote.paid, "mint quote should be paid"
    assert mint_quote.paid

    output_amounts = [128]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)
    assert quote.privkey
    signature = nut20.sign_mint_quote(quote.quote, outputs, quote.privkey)
    await ledger.mint(outputs=outputs, quote_id=quote.quote, signature=signature)

    mint_quote_after_payment = await ledger.get_mint_quote(quote.quote)
    assert mint_quote_after_payment.issued, "mint quote should be issued"


@pytest.mark.asyncio
async def test_split(wallet1: Wallet, ledger: Ledger):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    keep_proofs, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 10)
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(len(send_proofs))
    outputs, rs = wallet1._construct_outputs(
        [p.amount for p in send_proofs], secrets, rs
    )

    promises = await ledger.swap(proofs=send_proofs, outputs=outputs)
    assert len(promises) == len(outputs)
    assert [p.amount for p in promises] == [p.amount for p in outputs]


@pytest.mark.asyncio
async def test_split_with_no_outputs(wallet1: Wallet, ledger: Ledger):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 10, set_reserved=False)
    await assert_err(
        ledger.swap(proofs=send_proofs, outputs=[]),
        "no outputs provided",
    )


@pytest.mark.asyncio
async def test_split_with_input_less_than_outputs(wallet1: Wallet, ledger: Ledger):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    keep_proofs, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 10, set_reserved=False
    )

    too_many_proofs = send_proofs + send_proofs

    # generate more outputs than inputs
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(too_many_proofs)
    )
    outputs, rs = wallet1._construct_outputs(
        [p.amount for p in too_many_proofs], secrets, rs
    )

    await assert_err(
        ledger.swap(proofs=send_proofs, outputs=outputs),
        "are not balanced",
    )

    # make sure we can still spend our tokens
    keep_proofs, send_proofs = await wallet1.split(wallet1.proofs, 10)


@pytest.mark.asyncio
async def test_split_with_input_more_than_outputs(wallet1: Wallet, ledger: Ledger):
    mint_quote = await wallet1.request_mint(128)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(128, quote_id=mint_quote.quote)

    inputs = wallet1.proofs

    # less outputs than inputs
    output_amounts = [8]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)

    await assert_err(
        ledger.swap(proofs=inputs, outputs=outputs),
        "are not balanced",
    )

    # make sure we can still spend our tokens
    keep_proofs, send_proofs = await wallet1.split(inputs, 10)


@pytest.mark.asyncio
async def test_split_twice_with_same_outputs(wallet1: Wallet, ledger: Ledger):
    mint_quote = await wallet1.request_mint(128)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(128, split=[64, 64], quote_id=mint_quote.quote)
    inputs1 = wallet1.proofs[:1]
    inputs2 = wallet1.proofs[1:]

    assert inputs1[0].amount == 64
    assert inputs2[0].amount == 64

    output_amounts = [64]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)

    await ledger.swap(proofs=inputs1, outputs=outputs)

    # try to spend other proofs with the same outputs again
    await assert_err(
        ledger.swap(proofs=inputs2, outputs=outputs),
        "outputs have already been signed before.",
    )

    # try to spend inputs2 again with new outputs
    output_amounts = [64]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)

    await ledger.swap(proofs=inputs2, outputs=outputs)


@pytest.mark.asyncio
async def test_mint_with_same_outputs_twice(wallet1: Wallet, ledger: Ledger):
    mint_quote = await wallet1.request_mint(128)
    await pay_if_regtest(mint_quote.request)
    output_amounts = [128]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)
    assert mint_quote.privkey
    signature = nut20.sign_mint_quote(mint_quote.quote, outputs, mint_quote.privkey)
    await ledger.mint(outputs=outputs, quote_id=mint_quote.quote, signature=signature)

    # now try to mint with the same outputs again
    mint_quote_2 = await wallet1.request_mint(128)
    await pay_if_regtest(mint_quote_2.request)

    assert mint_quote_2.privkey
    signature = nut20.sign_mint_quote(mint_quote_2.quote, outputs, mint_quote_2.privkey)
    await assert_err(
        ledger.mint(outputs=outputs, quote_id=mint_quote_2.quote, signature=signature),
        "outputs have already been signed before.",
    )


@pytest.mark.asyncio
async def test_melt_with_same_outputs_twice(wallet1: Wallet, ledger: Ledger):
    mint_quote = await wallet1.request_mint(130)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(130, quote_id=mint_quote.quote)

    output_amounts = [128]
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(
        len(output_amounts)
    )
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)

    # we use the outputs once for minting
    mint_quote_2 = await wallet1.request_mint(128)
    await pay_if_regtest(mint_quote_2.request)
    assert mint_quote_2.privkey
    signature = nut20.sign_mint_quote(mint_quote_2.quote, outputs, mint_quote_2.privkey)
    await ledger.mint(outputs=outputs, quote_id=mint_quote_2.quote, signature=signature)

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
    mint_quote = await wallet1.request_mint(32)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(32, quote_id=mint_quote.quote)

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
    mint_quote = await wallet1.request_mint(130)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(130, split=[64, 64, 2], quote_id=mint_quote.quote)

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
    melt_resp = await ledger.melt(
        proofs=wallet1.proofs, quote=melt_quote.quote, outputs=outputs
    )
    # we get 2 sats back because we overpaid
    assert melt_resp.change
    assert sum([o.amount for o in melt_resp.change]) == 2


@pytest.mark.asyncio
async def test_check_proof_state(wallet1: Wallet, ledger: Ledger):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    keep_proofs, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 10)

    proof_states = await ledger.db_read.get_proofs_states(Ys=[p.Y for p in send_proofs])
    assert all([p.state.value == "UNSPENT" for p in proof_states])


# TODO: test keeps running forever, needs to be fixed
# @pytest.mark.asyncio
# async def test_websocket_quote_updates(wallet1: Wallet, ledger: Ledger):
#     mint_quote = await wallet1.request_mint(64)
#     ws = websocket.create_connection(
#         f"ws://localhost:{SERVER_PORT}/v1/quote/{invoice.id}"
#     )
#     await asyncio.sleep(0.1)
#     await pay_if_regtest(mint_quote.request)
#     await wallet1.mint(64, quote_id=mint_quote.quote)
#     await asyncio.sleep(0.1)
#     data = str(ws.recv())
#     ws.close()
#     n_lines = len(data.split("\n"))
#     assert n_lines == 1
