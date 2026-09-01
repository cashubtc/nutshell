import os
import uuid

import bdkpython as bdk
import httpx
import pytest

from cashu.core.base import Unit
from cashu.lightning.base import PaymentResult
from cashu.payment.onchain import BdkOnchainBackend

pytestmark = pytest.mark.skipif(
    os.getenv("ONCHAIN_REGTEST") != "1", reason="requires Bitcoin Core regtest"
)


def rpc(method: str, params=None, wallet: str | None = None):
    base_url = os.environ["ONCHAIN_REGTEST_RPC_URL"].rstrip("/")
    url = f"{base_url}/wallet/{wallet}" if wallet else base_url
    response = httpx.post(
        url,
        auth=("cashu", "cashu"),
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []},
        timeout=30,
    )
    result = response.json()
    if result.get("error"):
        raise RuntimeError(result["error"])
    return result["result"]


@pytest.mark.asyncio
async def test_bdk_onchain_receive_send_and_confirm(tmp_path):
    suffix = uuid.uuid4().hex[:8]
    miner_wallet = f"onchain-miner-{suffix}"
    rpc("createwallet", [miner_wallet])
    mining_address = rpc("getnewaddress", wallet=miner_wallet)
    rpc("generatetoaddress", [101, mining_address])

    backend = BdkOnchainBackend(
        Unit.sat,
        {
            "rpc_url": os.environ["ONCHAIN_REGTEST_RPC_URL"],
            "rpc_user": "cashu",
            "rpc_password": "cashu",
            "wallet": f"nutshell-bdk-{suffix}",
            "mnemonic": bdk.Mnemonic(bdk.WordCount.WORDS12).as_string(),
            "database_path": str(tmp_path / "bdk.sqlite"),
            "confirmations": 1,
            "min_amount": 1000,
        },
    )

    deposit_address = await backend.new_address()
    rpc("sendtoaddress", [deposit_address, 0.000005], wallet=miner_wallet)
    rpc("sendtoaddress", [deposit_address, 0.0001], wallet=miner_wallet)
    rpc("generatetoaddress", [1, mining_address])

    # NUT-30 evaluates min_amount per UTXO: the 500-sat output is ineligible.
    assert await backend.received(deposit_address) == 10_000

    destination = rpc("getnewaddress", wallet=miner_wallet)
    reserve, fee_options = await backend.fee_quote(destination, 5_000)
    assert reserve > 0
    assert fee_options == [
        {"fee_index": 0, "fee_reserve": reserve, "estimated_blocks": 1}
    ]

    txid, fee, outpoint = await backend.send(destination, 5_000)
    assert fee <= reserve
    assert outpoint.startswith(f"{txid}:")
    assert (await backend.transaction_status(txid)).result == PaymentResult.PENDING

    rpc("generatetoaddress", [1, mining_address])
    settled = await backend.transaction_status(txid)
    assert settled.result == PaymentResult.SETTLED
    assert settled.preimage == outpoint
