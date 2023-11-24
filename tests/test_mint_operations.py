import time

import pytest
import pytest_asyncio

from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import pay_if_regtest


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
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)
    assert wallet1.balance == 128
    total_amount, fee_reserve_sat = await wallet1.get_pay_amount_with_fees(
        invoice.bolt11
    )
    mint_fees = await ledger.get_melt_fees(invoice.bolt11)
    assert mint_fees == fee_reserve_sat

    keep_proofs, send_proofs = await wallet1.split_to_send(wallet1.proofs, total_amount)

    await ledger.melt(send_proofs, invoice.bolt11, outputs=None)


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
async def test_check_proof_state(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)

    keep_proofs, send_proofs = await wallet1.split_to_send(wallet1.proofs, 10)

    spendable, pending = await ledger.check_proof_state(proofs=send_proofs)
    assert sum(spendable) == len(send_proofs)
    assert sum(pending) == 0


@pytest.mark.asyncio
async def test_benchmark_check_proof_spendable(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(1000)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(1000, split=[1] * 1000, id=invoice.id)

    time_begin = time.time()
    spendable = await ledger._check_proofs_spendable(wallet1.proofs)
    time_end = time.time()
    time_elapsed = time_end - time_begin
    print(f"Time elapsed: {time_elapsed}")
    assert sum(spendable) == len(wallet1.proofs)
    assert time_elapsed < 0.5
