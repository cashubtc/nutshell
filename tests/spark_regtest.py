"""Run the shared mint/wallet regtests with the real local Spark backend."""

import asyncio
import copy
import os
from pathlib import Path

import pytest
import pytest_asyncio

_clients = []
_receive_requests = set()


async def pay_regtest_invoice(invoice):
    """Fund a shared-suite invoice and wait until its receiving wallet sees it."""
    import bolt11
    import httpx

    from cashu.core.base import Unit
    from cashu.core.db import Database
    from cashu.core.settings import settings
    from cashu.lightning.sparkl2 import SparkL2Wallet
    from cashu.mint.crud import LedgerCrudSqlite
    from tests.helpers import wait_for_result
    from tests.spark import lightning

    db = Database("mint", settings.mint_database)
    try:
        quote = await LedgerCrudSqlite().get_mint_quote(request=invoice, db=db)
    finally:
        await db.engine.dispose()

    # Mixed-unit tests use FakeWallet for USD alongside the real sat backend.
    if (
        quote is not None
        and quote.unit == Unit.usd.name
        and settings.mint_backend_bolt11_usd == "FakeWallet"
    ):
        await asyncio.sleep(settings.fakewallet_delay_incoming_payment or 0)
        return

    payment = await lightning("lnd", "payinvoice", "--force", "--json", invoice)
    assert payment["status"] == "SUCCEEDED", payment
    wallet = None
    if invoice in _receive_requests:
        import breez_sdk_spark as breez

        breez.uniffi_set_event_loop(asyncio.get_running_loop())
        wallet = SparkL2Wallet(Unit.sat)
        wallet.sdk = _clients[0]
    payment_hash = bolt11.decode(invoice).payment_hash
    async with httpx.AsyncClient(timeout=10, trust_env=False) as client:

        async def received():
            if wallet is not None:
                status = await wallet.get_invoice_status(payment_hash)
                return status.settled
            if quote is not None:
                response = await client.get(
                    f"{settings.mint_url}/v1/mint/quote/bolt11/{quote.quote}"
                )
                response.raise_for_status()
                return response.json()["state"] in ("PAID", "ISSUED")
            return False

        await wait_for_result(received, bool)


@pytest.fixture(scope="session")
def spark_regtest_config():
    from cashu.core.settings import settings

    if os.getenv("CASHU_SPARK_REGTEST", "").lower() != "true":
        yield None
        return
    if settings.mint_backend_bolt11_sat != "SparkL2Wallet":
        yield None
        return

    import breez_sdk_spark as breez
    from mnemonic import Mnemonic

    from tests.spark import connect_spark, local_spark_config

    # Configure endpoints before the mint forks; no SDK is connected in the
    # parent until the mint process has started its own event loop.
    config = asyncio.run(local_spark_config())
    clients = _clients
    state = {"clients": clients, "funded": False}
    parent_pid = os.getpid()
    process_seed = None

    def default_config(network):
        assert network == breez.Network.REGTEST
        return copy.deepcopy(config)

    async def connect(request):
        nonlocal process_seed
        if clients:
            return clients[0]
        # Each process owns its wallet and cache so its SDK can deliver incoming
        # payment events without another instance claiming the same transfers.
        if os.getpid() != parent_pid:
            if process_seed is None:
                process_seed = breez.Seed.MNEMONIC(
                    mnemonic=Mnemonic("english").generate(), passphrase=None
                )
            request.seed = process_seed
        request.storage_dir = str(Path(request.storage_dir) / f"process-{os.getpid()}")
        sdk = await connect_spark(request)

        # Record ownership while forwarding the receive operation unchanged.
        # The two processes share mint quotes, but have separate Spark wallets.
        receive_payment = sdk.receive_payment

        async def receive(request):
            response = await receive_payment(request)
            _receive_requests.add(response.payment_request)
            return response

        sdk.receive_payment = receive
        clients.append(sdk)
        return sdk

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(breez, "default_config", default_config)
        patch.setattr(breez, "connect", connect)
        patch.setattr(settings, "mint_spark_network", "REGTEST")
        patch.setattr(settings, "mint_spark_api_key", None)
        patch.setattr(settings, "mint_spark_mnemonic", Mnemonic("english").generate())
        yield state


@pytest_asyncio.fixture(autouse=True)
async def spark_regtest_clients(spark_regtest_config, mint):
    if spark_regtest_config is None:
        yield
        return

    from cashu.core.base import Amount, Unit
    from cashu.lightning.sparkl2 import SparkL2Wallet
    from tests.spark import TIMEOUT, lightning, wait_balance

    clients = spark_regtest_config["clients"]
    try:
        if not spark_regtest_config["funded"]:
            # Like the funded LND/CLN regtest nodes, the shared Spark backend
            # must be able to pay invoices before an individual test mints.
            wallet = SparkL2Wallet(Unit.sat)
            invoice = await wallet.create_invoice(Amount(Unit.sat, 10_000))
            assert invoice.ok, invoice.error_message
            result = await lightning(
                "lnd", "payinvoice", "--force", "--json", invoice.payment_request
            )
            assert result["status"] == "SUCCEEDED", result
            await wait_balance(wallet, 10_000)
            spark_regtest_config["funded"] = True
        yield
    finally:
        # CLI tests can run their own loop between fixture setup and teardown.
        import breez_sdk_spark as breez

        breez.uniffi_set_event_loop(asyncio.get_running_loop())
        for sdk in clients:
            await asyncio.wait_for(sdk.disconnect(), TIMEOUT)
        clients.clear()
