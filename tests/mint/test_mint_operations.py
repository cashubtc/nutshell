import pytest
import pytest_asyncio

from cashu.core.base import MeltQuoteState, MintQuoteState
from cashu.core.errors import OutputsAlreadySignedError, ProofsAlreadySpentError
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
    assert melt_quote.state != MeltQuoteState.paid.value
    assert melt_quote.state == MeltQuoteState.unpaid.value

    assert melt_quote.amount == 64
    assert melt_quote.fee_reserve == 0

    if not settings.debug_mint_only_deprecated:
        melt_quote_response_pre_payment = await wallet1.get_melt_quote(melt_quote.quote)
        assert melt_quote_response_pre_payment
        assert not melt_quote_response_pre_payment.state == MeltQuoteState.paid, (
            "melt quote should not be paid"
        )
        assert melt_quote_response_pre_payment.amount == 64

    melt_quote_pre_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert melt_quote_pre_payment.state != MeltQuoteState.paid, (
        "melt quote should not be paid"
    )
    assert melt_quote_pre_payment.state == MeltQuoteState.unpaid

    keep_proofs, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 64)
    await ledger.melt(proofs=send_proofs, quote=melt_quote.quote)

    melt_quote_post_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert melt_quote_post_payment.state == MeltQuoteState.paid, (
        "melt quote should be paid"
    )
    assert melt_quote_post_payment.state == MeltQuoteState.paid


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

    melt_quote = await wallet1.melt_quote(invoice_payment_request)
    assert melt_quote.state != MeltQuoteState.paid, "mint quote should not be paid"
    assert melt_quote.state == MeltQuoteState.unpaid

    total_amount = melt_quote.amount + melt_quote.fee_reserve
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, total_amount)
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice_payment_request, unit="sat")
    )

    if not settings.debug_mint_only_deprecated:
        melt_quote_response_pre_payment = await wallet1.get_melt_quote(melt_quote.quote)
        assert melt_quote_response_pre_payment
        assert melt_quote_response_pre_payment.state == MeltQuoteState.unpaid, (
            "melt quote should not be paid"
        )
        assert melt_quote_response_pre_payment.amount == melt_quote.amount

    melt_quote_pre_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert melt_quote_pre_payment.state != MeltQuoteState.paid, (
        "melt quote should not be paid"
    )
    assert melt_quote_pre_payment.state == MeltQuoteState.unpaid

    assert melt_quote.state != MeltQuoteState.paid, "melt quote should not be paid"
    await ledger.melt(proofs=send_proofs, quote=melt_quote.quote)

    melt_quote_post_payment = await ledger.get_melt_quote(melt_quote.quote)
    assert melt_quote_post_payment.state == MeltQuoteState.paid, (
        "melt quote should be paid"
    )
    assert melt_quote_post_payment.state == MeltQuoteState.paid


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only works with FakeWallet")
async def test_mint_internal(wallet1: Wallet, ledger: Ledger):
    wallet_mint_quote = await wallet1.request_mint(128)
    await ledger.get_mint_quote(wallet_mint_quote.quote)
    mint_quote = await ledger.get_mint_quote(wallet_mint_quote.quote)

    assert mint_quote.state == MintQuoteState.paid, "mint quote should be paid"

    if not settings.debug_mint_only_deprecated:
        mint_quote = await wallet1.get_mint_quote(mint_quote.quote)
        assert mint_quote.state == MintQuoteState.paid, "mint quote should be paid"

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
        OutputsAlreadySignedError.detail,
    )

    mint_quote_after_payment = await ledger.get_mint_quote(mint_quote.quote)
    assert mint_quote_after_payment.issued, "mint quote should be issued"
    assert mint_quote_after_payment.issued


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only works with Regtest")
async def test_mint_external(wallet1: Wallet, ledger: Ledger):
    quote = await wallet1.request_mint(128)

    mint_quote = await ledger.get_mint_quote(quote.quote)
    assert mint_quote.state != MintQuoteState.paid, "mint quote already paid"
    assert mint_quote.state == MintQuoteState.unpaid

    if not settings.debug_mint_only_deprecated:
        mint_quote = await wallet1.get_mint_quote(quote.quote)
        assert mint_quote.state != MintQuoteState.paid, "mint quote should not be paid"

    await assert_err(
        wallet1.mint(128, quote_id=quote.quote),
        "quote not paid",
    )

    await pay_if_regtest(quote.request)

    mint_quote = await ledger.get_mint_quote(quote.quote)
    assert mint_quote.state == MintQuoteState.paid, "mint quote should be paid"
    assert mint_quote.state == MintQuoteState.paid

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
async def test_verify_inputs_rejects_double_spent_proofs(
    wallet1: Wallet, ledger: Ledger
):
    """After a swap, inputs are spent in the DB; _verify_inputs must reject re-use."""
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, 10, set_reserved=False)
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(len(send_proofs))
    outputs, rs = wallet1._construct_outputs(
        [p.amount for p in send_proofs], secrets, rs
    )
    await ledger.swap(proofs=send_proofs, outputs=outputs)

    with pytest.raises(ProofsAlreadySpentError):
        await ledger._verify_inputs(send_proofs)


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

    # Raw Σinputs < Σoutputs is rejected in _verify_input_output_amounts before the
    # fee balance check (_verify_equation_balanced / "are not balanced").
    await assert_err(
        ledger.swap(proofs=send_proofs, outputs=outputs),
        "less than output amounts",
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
        OutputsAlreadySignedError.detail,
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
        OutputsAlreadySignedError.detail,
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
        OutputsAlreadySignedError.detail,
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

@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only works with FakeWallet")
async def test_melt_preserves_change_signatures_order_integration(wallet1: Wallet, ledger: Ledger):
    # mint enough to pay invoice
    mint_quote = await wallet1.request_mint(128)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(128, quote_id=mint_quote.quote)
    assert wallet1.balance >= 64

    invoice_dict = get_real_invoice(64)
    invoice_payment_request = invoice_dict["payment_request"] if is_regtest else "lnbcrt640n1pn0r3tfpp5e30xac756gvd26cn3tgsh8ug6ct555zrvl7vsnma5cwp4g7auq5qdqqcqzzsxqyz5vqsp5xfhtzg0y3mekv6nsdnj43c346smh036t4f8gcfa2zwpxzwcryqvs9qxpqysgqw5juev8y3zxpdu0mvdrced5c6a852f9x7uh57g6fgjgcg5muqzd5474d7xgh770frazel67eejfwelnyr507q46hxqehala880rhlqspw07ta0"
    if type(invoice_payment_request) is dict:
        invoice_payment_request = invoice_payment_request["payment_request"]

    # wallet asks for quote
    _ = await wallet1.melt_quote(invoice_payment_request)
    
    # Force the fee_reserve in the DB to be larger so we get multiple change outputs
    # Let's say overpaid_fee = 7 -> [4, 2, 1]
    total_amount = 64 + 7
    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, total_amount)
    
    melt_quote_internal = await ledger.melt_quote(
        PostMeltQuoteRequest(request=invoice_payment_request, unit="sat")
    )
    # forcefully update the fee_reserve and amount to allow 7 sat overpayment
    await ledger.db.execute(f"UPDATE {ledger.db.table_with_schema('melt_quotes')} SET fee_reserve = 7 WHERE quote = '{melt_quote_internal.quote}'")
    melt_quote_internal.fee_reserve = 7

    # prepare outputs for change
    output_amounts = [1, 2, 4, 8] # Provide change outputs
    secrets, rs, derivation_paths = await wallet1.generate_n_secrets(len(output_amounts))
    outputs, rs = wallet1._construct_outputs(output_amounts, secrets, rs)
    
    # We force pending state by tricking fakewallet
    from cashu.lightning.base import PaymentResult
    settings.fakewallet_pay_invoice_state = PaymentResult.PENDING.name
    settings.fakewallet_payment_state = PaymentResult.PENDING.name
    
    # Call melt with outputs
    melt_response = await ledger.melt(proofs=send_proofs, quote=melt_quote_internal.quote, outputs=outputs)
    assert melt_response.state == MeltQuoteState.pending.value
    
    # Now fake that payment settled
    settings.fakewallet_payment_state = PaymentResult.SETTLED.name
    
    # get_melt_quote will now settle the payment and generate the change
    quote_post = await ledger.get_melt_quote(melt_quote_internal.quote)
    assert quote_post.state == MeltQuoteState.paid
    assert quote_post.change is not None
    assert len(quote_post.change) == 3 # 7 splits into [4, 2, 1]
    
    # Verify the order of change corresponds strictly to the B_ order of outputs
    # To do this, we can unblind them sequentially and see if the amounts match the expected amounts
    # If they were out of order, the wallet mapping would assign the wrong amount or fail unblinding
    change_proofs = await wallet1._construct_proofs(
        quote_post.change,
        secrets[: len(quote_post.change)],
        rs[: len(quote_post.change)],
        derivation_paths[: len(quote_post.change)],
    )
    
    # The returned change proofs must have the exact same amounts as our outputs IN ORDER
    # The mint assigns amounts from largest to smallest, so [4, 2, 1]
    expected_amounts = [4, 2, 1]
    for i, proof in enumerate(change_proofs):
        assert proof.amount == expected_amounts[i]

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
