"""Real Spark payments against ``cashu-regtest/start.sh --spark``.

Run with CASHU_SPARK_REGTEST=true; see CONTRIBUTING.md for setup.
Only SDK connection configuration is replaced. Payments, storage, polling,
and event delivery use the installed Breez SDK and the local network.
"""

import asyncio
import copy
import hashlib
import json
import os
from contextlib import suppress
from pathlib import Path
from uuid import uuid4

import bolt11
import breez_sdk_spark as breez
import httpx
import pytest
import pytest_asyncio
from mnemonic import Mnemonic

from cashu.core.base import Amount, MeltQuote, MeltQuoteState, Unit
from cashu.core.models import PostMeltQuoteRequest
from cashu.core.settings import settings
from cashu.lightning.base import PaymentResult
from cashu.lightning.sparkl2 import SparkL2Wallet

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        os.getenv("CASHU_SPARK_REGTEST", "").lower() != "true",
        reason="requires CASHU_SPARK_REGTEST=true and cashu-regtest/start.sh --spark",
    ),
]

TIMEOUT = 120
SSP_URL = "http://127.0.0.1:5000"
ESPLORA_URL = "http://127.0.0.1:30000"


@pytest.fixture(scope="session", autouse=True)
def mint():
    """These backend tests do not need the parent conftest's HTTP mint server."""


async def compose(service, *args):
    regtest_dir = Path(
        os.getenv("CASHU_REGTEST_DIR", str(Path.home() / "cashu-regtest"))
    ).expanduser()
    compose_file = regtest_dir / "docker-compose.yml"
    assert compose_file.is_file(), f"cashu-regtest not found at {regtest_dir}"
    process = await asyncio.create_subprocess_exec(
        "docker",
        "compose",
        "--profile",
        "spark",
        "-p",
        "cashu",
        "-f",
        str(compose_file),
        "exec",
        "-T",
        service,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), TIMEOUT)
    except BaseException:
        if process.returncode is None:
            process.kill()
        await process.communicate()
        raise
    assert process.returncode == 0, (
        f"{service} {args[0]} failed: {stderr.decode()}. "
        "Start cashu-regtest with ./start.sh --spark first."
    )
    return stdout.decode().strip()


async def lightning(peer, *args):
    if peer == "lnd":
        output = await compose(
            "lnd-1", "lncli", "--network=regtest", "--rpcserver=lnd-1:10009", *args
        )
    else:
        output = await compose(
            "clightning-1", "lightning-cli", "--network=regtest", "-N", "none", *args
        )
    return json.loads(output)


async def wait_for(label, check):
    """Bound both individual RPCs and the total wait for eventual settlement."""
    deadline = asyncio.get_running_loop().time() + TIMEOUT
    last = None
    while (remaining := deadline - asyncio.get_running_loop().time()) > 0:
        last = await asyncio.wait_for(check(), remaining)
        if last:
            return last
        await asyncio.sleep(min(1, remaining))
    pytest.fail(f"Timed out waiting for {label}: {last}")


async def wait_balance(wallet, sats):
    expected = Amount(Unit.sat, sats).to(wallet.unit)

    async def check():
        status = await wallet.status()
        assert not status.error_message, status.error_message
        return status.balance == expected

    await wait_for(f"Spark balance {expected}", check)


async def wait_invoice(wallet, checking_id):
    async def check():
        status = await wallet.get_invoice_status(checking_id)
        assert not status.failed, status.error_message
        return status if status.settled else None

    return await wait_for(f"incoming payment {checking_id}", check)


async def wait_payment(wallet, checking_id):
    async def check():
        status = await wallet.get_payment_status(checking_id)
        assert not status.failed, status.error_message
        # The SDK can report completion before its cached preimage is updated.
        return status if status.settled and status.preimage else None

    return await wait_for(f"outgoing payment {checking_id}", check)


def assert_preimage(preimage, payment_hash):
    assert preimage
    assert hashlib.sha256(bytes.fromhex(preimage)).hexdigest() == payment_hash


@pytest_asyncio.fixture
async def spark_wallet_factory(monkeypatch, tmp_path):
    # Discover fixture identities and trust the generated operator certificates.
    # Do not use the default config's public SSP or sync service on regtest.
    try:
        async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
            response = await client.get(f"{SSP_URL}/identity")
            response.raise_for_status()
            identity = response.json()["identityPublicKey"]
            response = await client.get(f"{ESPLORA_URL}/blocks/tip/height")
            response.raise_for_status()
            assert int(response.text) > 0
    except httpx.HTTPError as exc:
        pytest.fail(
            "Spark regtest services are unavailable. Run ./start.sh --spark in "
            f"cashu-regtest first. {exc}",
            pytrace=False,
        )

    regtest_dir = Path(
        os.getenv("CASHU_REGTEST_DIR", str(Path.home() / "cashu-regtest"))
    ).expanduser()
    operators = json.loads((regtest_dir / "spark/operators.json").read_text())
    config = breez.default_config(breez.Network.REGTEST)
    config.api_key = None
    config.lnurl_domain = None
    config.real_time_sync_server_url = None
    config.use_default_external_input_parsers = False
    config.prefer_spark_over_lightning = False
    config.sync_interval_secs = 2
    config.leaf_optimization_config.auto_enabled = False
    config.token_optimization_config.auto_enabled = False
    assert config.spark_config is not None
    config.spark_config.coordinator_identifier = f"{1:064x}"
    config.spark_config.threshold = 2
    config.spark_config.signing_operators = [
        breez.SparkSigningOperator(
            id=operator["id"],
            identifier=f"{operator['id'] + 1:064x}",
            address=f"https://localhost:{8535 + operator['id']}",
            identity_public_key=operator["identity_public_key"],
            ca_cert_pem=await compose(
                f"spark-operator-{operator['id']}", "cat", operator["cert_path"]
            ),
        )
        for operator in operators
    ]
    config.spark_config.ssp_config = breez.SparkSspConfig(
        base_url=SSP_URL,
        identity_public_key=identity,
        schema_endpoint="graphql/spark/rc",
    )

    def local_config(network):
        assert network == breez.Network.REGTEST
        return copy.deepcopy(config)

    async def connect(request):
        # UniFFI retains a global loop. Pytest creates a new one for each case,
        # and these async builder methods run before build() resets that loop.
        breez.uniffi_set_event_loop(asyncio.get_running_loop())
        builder = breez.SdkBuilder(config=request.config, seed=request.seed)
        await builder.with_default_storage(request.storage_dir)
        await builder.with_rest_chain_service(
            ESPLORA_URL, breez.ChainApiType.ESPLORA, None
        )
        return await builder.build()

    monkeypatch.setattr(breez, "default_config", local_config)
    monkeypatch.setattr(breez, "connect", connect)
    monkeypatch.setattr(settings, "mint_spark_network", "REGTEST")
    monkeypatch.setattr(settings, "mint_spark_api_key", None)
    monkeypatch.setattr(settings, "mint_spark_mnemonic", Mnemonic("english").generate())
    monkeypatch.setattr(settings, "cashu_dir", str(tmp_path))
    wallets = []

    async def create(unit):
        wallet = SparkL2Wallet(unit=unit)
        wallets.append(wallet)
        status = await asyncio.wait_for(wallet.status(), TIMEOUT)
        assert not status.error_message, status.error_message
        assert wallet.sdk is not None
        return wallet

    yield create

    for wallet in wallets:
        if wallet.sdk is not None:
            await asyncio.wait_for(wallet.sdk.disconnect(), TIMEOUT)
            wallet.sdk = None


@pytest.mark.parametrize("unit", [Unit.sat, Unit.msat], ids=lambda unit: unit.name)
@pytest.mark.parametrize("peer", ["lnd", "cln"])
async def test_spark_lightning_round_trip(spark_wallet_factory, unit, peer):
    wallet = await spark_wallet_factory(unit)
    await wait_balance(wallet, 0)
    missing = await wallet.get_payment_status(str(uuid4()))
    assert missing.result == PaymentResult.UNKNOWN

    # Receive through Nutshell, including msat -> sat rounding and the listener.
    # This also funds the isolated wallet for the outgoing half of the test.
    receive_sats = 20_001
    requested = Amount(unit, receive_sats if unit == Unit.sat else 20_000_001)
    memo = f"nutshell-spark-{uuid4()}"
    invoice = await wallet.create_invoice(requested, memo=memo)
    assert invoice.ok, invoice.error_message
    assert invoice.payment_request
    assert invoice.checking_id
    decoded = bolt11.decode(invoice.payment_request)
    assert decoded.currency == "bcrt"
    assert decoded.amount_msat == receive_sats * 1000
    assert decoded.description == memo
    assert decoded.payment_hash == invoice.checking_id
    unpaid = await wallet.get_invoice_status(invoice.checking_id)
    assert unpaid.result in (PaymentResult.UNKNOWN, PaymentResult.PENDING)

    stream = wallet.paid_invoices_stream()
    event = asyncio.create_task(stream.__anext__())
    try:
        if peer == "lnd":
            received = await lightning(
                peer,
                "payinvoice",
                "--force",
                "--json",
                "--fee_limit=100",
                invoice.payment_request,
            )
            assert received["status"] == "SUCCEEDED", received
        else:
            received = await lightning(peer, "pay", invoice.payment_request)
            assert received["status"] == "complete", received
        assert received["payment_hash"] == invoice.checking_id
        assert_preimage(received["payment_preimage"], invoice.checking_id)
        assert await asyncio.wait_for(event, TIMEOUT) == invoice.checking_id
    finally:
        event.cancel()
        with suppress(asyncio.CancelledError):
            await event
        await stream.aclose()
    await wait_invoice(wallet, invoice.checking_id)
    await wait_balance(wallet, receive_sats)

    # Send to the same Lightning peer, verifying quote units and actual fees.
    send_sats = 3000
    if peer == "lnd":
        outgoing = await lightning(peer, "addinvoice", str(send_sats))
        request = outgoing["payment_request"]
    else:
        outgoing = await lightning(peer, "invoice", str(send_sats * 1000), memo, memo)
        request = outgoing["bolt11"]
    payment_hash = bolt11.decode(request).payment_hash
    payment_quote = await wallet.get_payment_quote(
        PostMeltQuoteRequest(request=request, unit=unit.name)
    )
    assert payment_quote.checking_id == payment_hash
    assert payment_quote.amount == Amount(Unit.sat, send_sats).to(unit)
    assert payment_quote.fee.unit == unit
    assert payment_quote.fee.amount >= 0
    quote = MeltQuote(
        quote=str(uuid4()),
        method="bolt11",
        unit=unit.name,
        state=MeltQuoteState.unpaid,
        request=request,
        checking_id=payment_quote.checking_id,
        amount=payment_quote.amount.amount,
        fee_reserve=payment_quote.fee.amount,
    )
    fee_limit_msat = payment_quote.fee.to(Unit.msat).amount
    payment = await asyncio.wait_for(wallet.pay_invoice(quote, fee_limit_msat), TIMEOUT)
    assert payment.result in (PaymentResult.SETTLED, PaymentResult.PENDING), payment
    assert payment.checking_id
    settled = await wait_payment(wallet, payment.checking_id)
    assert_preimage(settled.preimage, payment_hash)
    assert settled.fee is not None
    assert settled.fee.unit == unit
    assert 0 <= settled.fee.to(Unit.msat).amount <= fee_limit_msat
    if payment.settled:
        if payment.preimage is not None:
            assert payment.preimage == settled.preimage
        assert payment.fee == settled.fee

    if peer == "lnd":
        peer_invoice = await lightning(peer, "lookupinvoice", payment_hash)
        assert peer_invoice["state"] == "SETTLED"
        assert int(peer_invoice["amt_paid_sat"]) == send_sats
        assert peer_invoice["r_preimage"] == settled.preimage
    else:
        peer_invoice = (await lightning(peer, "listinvoices", memo))["invoices"][0]
        assert peer_invoice["status"] == "paid"
        assert peer_invoice["amount_received_msat"] == send_sats * 1000
        assert peer_invoice["payment_preimage"] == settled.preimage

    remaining_sats = receive_sats - send_sats - settled.fee.to(Unit.sat).amount
    await wait_balance(wallet, remaining_sats)

    # Reopen the same seed/storage to verify persisted backend status and fees.
    assert wallet.sdk is not None
    await wallet.sdk.disconnect()
    wallet.sdk = None
    reopened = await spark_wallet_factory(unit)
    await wait_balance(reopened, remaining_sats)
    await wait_invoice(reopened, invoice.checking_id)
    restored = await wait_payment(reopened, payment.checking_id)
    assert restored.preimage == settled.preimage
    assert restored.fee == settled.fee
