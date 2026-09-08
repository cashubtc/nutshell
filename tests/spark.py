"""Connection and RPC helpers for the local cashu-regtest Spark stack."""

import asyncio
import hashlib
import json
import os
from pathlib import Path

import breez_sdk_spark as breez
import httpx
import pytest

from cashu.core.base import Amount, Unit

TIMEOUT = 120
SSP_URL = "http://127.0.0.1:5000"
ESPLORA_URL = "http://127.0.0.1:30000"


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


async def local_spark_config():
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

    return config


async def connect_spark(request):
    # UniFFI retains a global loop. Pytest creates a new one for each case,
    # and these async builder methods run before build() resets that loop.
    breez.uniffi_set_event_loop(asyncio.get_running_loop())
    builder = breez.SdkBuilder(config=request.config, seed=request.seed)
    await builder.with_default_storage(request.storage_dir)
    await builder.with_rest_chain_service(ESPLORA_URL, breez.ChainApiType.ESPLORA, None)
    return await builder.build()
