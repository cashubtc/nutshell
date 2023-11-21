import pytest
import pytest_asyncio

from cashu.core.base import PostMeltQuoteRequest
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import get_real_invoice, is_regtest, pay_if_regtest


@pytest_asyncio.fixture(scope="function")
async def wallet1(mint):
    wallet1 = await Wallet1.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1",
        name="wallet1",
    )
    await wallet1.load_mint()
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
    invoice_payment_request = invoice.bolt11
    if is_regtest:
        invoice_dict = get_real_invoice(64)
        invoice_payment_request = invoice_dict["payment_request"]
        str(invoice_dict["r_hash"])

    assert wallet1.balance == 128
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
async def test_check_proof_state(wallet1: Wallet, ledger: Ledger):
    invoice = await wallet1.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet1.mint(64, id=invoice.id)

    keep_proofs, send_proofs = await wallet1.split_to_send(wallet1.proofs, 10)

    spendable, pending = await ledger.check_proof_state(proofs=send_proofs)
    assert sum(spendable) == len(send_proofs)
    assert sum(pending) == 0
