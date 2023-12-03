import pytest
import pytest_asyncio

from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import pay_if_regtest


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
async def wallet1(mint):
    wallet1 = await Wallet1.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1",
        name="wallet1",
    )
    await wallet1.load_mint()
    wallet1.status()
    yield wallet1


@pytest.mark.asyncio
async def test_melt(wallet1: Wallet, ledger: Ledger):
    # mint twice so we have enough to pay the second invoice back
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)
    invoice2 = await wallet1.request_mint(64)
    pay_if_regtest(invoice2.bolt11)
    await wallet1.mint(64, id=invoice2.id)
    assert wallet1.balance == 128
    total_amount, fee_reserve_sat = await wallet1.get_pay_amount_with_fees(
        invoice2.bolt11
    )
    melt_fees = await ledger.get_melt_fees(invoice2.bolt11)
    assert melt_fees == fee_reserve_sat

    keep_proofs, send_proofs = await wallet1.split_to_send(wallet1.proofs, total_amount)

    await ledger.melt(send_proofs, invoice2.bolt11, outputs=None)


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
    print(keep_proofs, send_proofs)


@pytest.mark.asyncio
async def test_split_twice_with_same_outputs(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(128)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(128, [64, 64], id=invoice.id)
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
    await ledger.mint(outputs, id=invoice.id)

    # now try to mint with the same outputs again
    invoice2 = await wallet1.request_mint(128)
    pay_if_regtest(invoice2.bolt11)

    await assert_err(
        ledger.mint(outputs, id=invoice2.id),
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
    await ledger.mint(outputs, id=invoice2.id)

    # use the same outputs for melting
    invoice3 = await wallet1.request_mint(128)
    await assert_err(
        ledger.melt(wallet1.proofs, invoice3.bolt11, outputs=outputs),
        "outputs have already been signed before.",
    )


@pytest.mark.asyncio
async def test_check_proof_state(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)

    keep_proofs, send_proofs = await wallet1.split_to_send(wallet1.proofs, 10)

    spendable, pending = await ledger.check_proof_state(proofs=send_proofs)
    assert sum(spendable) == len(send_proofs)
    assert sum(pending) == 0
