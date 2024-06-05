from typing import List, Union

import pytest
import pytest_asyncio

from cashu.core.base import Proof
from cashu.core.errors import CashuError
from cashu.wallet.lightning import LightningWallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import get_real_invoice, is_fake, is_regtest, pay_if_regtest


async def assert_err(f, msg: Union[str, CashuError]):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        error_message: str = str(exc.args[0])
        if isinstance(msg, CashuError):
            if msg.detail not in error_message:
                raise Exception(
                    f"CashuError. Expected error: {msg.detail}, got: {error_message}"
                )
            return
        if msg not in error_message:
            raise Exception(f"Expected error: {msg}, got: {error_message}")
        return
    raise Exception(f"Expected error: {msg}, got no error")


def assert_amt(proofs: List[Proof], expected: int):
    """Assert amounts the proofs contain."""
    assert [p.amount for p in proofs] == expected


async def reset_wallet_db(wallet: LightningWallet):
    await wallet.db.execute("DELETE FROM proofs")
    await wallet.db.execute("DELETE FROM proofs_used")
    await wallet.db.execute("DELETE FROM keysets")
    await wallet._load_mint()


@pytest_asyncio.fixture(scope="function")
async def wallet():
    wallet = await LightningWallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1",
        name="wallet1",
    )
    await wallet.async_init()
    yield wallet


@pytest.mark.asyncio
async def test_create_invoice(wallet: LightningWallet):
    invoice = await wallet.create_invoice(64)
    assert invoice.payment_request
    assert invoice.payment_request.startswith("ln")


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only works with FakeWallet")
async def test_check_invoice_internal(wallet: LightningWallet):
    # fill wallet
    invoice = await wallet.create_invoice(64)
    assert invoice.payment_request
    assert invoice.checking_id
    status = await wallet.get_invoice_status(invoice.checking_id)
    assert status.paid


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only works with Regtest")
async def test_check_invoice_external(wallet: LightningWallet):
    # fill wallet
    invoice = await wallet.create_invoice(64)
    assert invoice.payment_request
    assert invoice.checking_id
    status = await wallet.get_invoice_status(invoice.checking_id)
    assert not status.paid
    pay_if_regtest(invoice.payment_request)
    status = await wallet.get_invoice_status(invoice.checking_id)
    assert status.paid


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only works with FakeWallet")
async def test_pay_invoice_internal(wallet: LightningWallet):
    # fill wallet
    invoice = await wallet.create_invoice(64)
    assert invoice.payment_request
    assert invoice.checking_id
    await wallet.get_invoice_status(invoice.checking_id)
    assert wallet.available_balance >= 64

    # pay invoice
    invoice2 = await wallet.create_invoice(16)
    assert invoice2.payment_request
    status = await wallet.pay_invoice(invoice2.payment_request)

    assert status.ok

    # check payment
    assert invoice2.checking_id
    status = await wallet.get_payment_status(invoice2.checking_id)
    assert status.paid


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only works with Regtest")
async def test_pay_invoice_external(wallet: LightningWallet):
    # fill wallet
    invoice = await wallet.create_invoice(64)
    assert invoice.payment_request
    assert invoice.checking_id
    pay_if_regtest(invoice.payment_request)
    status = await wallet.get_invoice_status(invoice.checking_id)
    assert status.paid
    assert wallet.available_balance >= 64

    # pay invoice
    invoice_real = get_real_invoice(16)
    status = await wallet.pay_invoice(invoice_real["payment_request"])

    assert status.ok

    # check payment
    assert status.checking_id
    status = await wallet.get_payment_status(status.checking_id)
    assert status.paid
