import asyncio
import hashlib
import importlib
import json
import os
import random
import string
import time
from subprocess import PIPE, Popen, TimeoutExpired
from typing import List, Tuple, Union

from loguru import logger

from cashu.core.errors import CashuError
from cashu.core.settings import settings


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


async def assert_err_multiple(f, msgs: List[str]):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        for msg in msgs:
            if msg in str(exc.args[0]):
                return
        raise Exception(f"Expected error: {msgs}, got: {exc.args[0]}")
    raise Exception(f"Expected error: {msgs}, got no error")


def get_random_string(N: int = 10):
    return "".join(
        random.SystemRandom().choice(string.ascii_uppercase + string.digits)
        for _ in range(N)
    )


async def get_random_invoice_data():
    return {"out": False, "amount": 10, "memo": f"test_memo_{get_random_string(10)}"}


wallets_module = importlib.import_module("cashu.lightning")
wallet_class = getattr(wallets_module, settings.mint_backend_bolt11_sat)
WALLET = wallet_class()
is_fake: bool = WALLET.__class__.__name__ == "FakeWallet"
is_regtest: bool = not is_fake
is_deprecated_api_only = settings.debug_mint_only_deprecated
is_github_actions = os.getenv("GITHUB_ACTIONS") == "true"
is_postgres = settings.mint_database.startswith("postgres")
SLEEP_TIME = 1 if not is_github_actions else 2

docker_lightning_cli = [
    "docker",
    "exec",
    "cashu-lnd-1-1",
    "lncli",
    "--network",
    "regtest",
    "--rpcserver=lnd-1",
]

docker_bitcoin_cli = [
    "docker",
    "exec",
    "cashu-bitcoind-1-1bitcoin-cli",
    "-rpcuser=lnbits",
    "-rpcpassword=lnbits",
    "-regtest",
]


docker_lightning_unconnected_cli = [
    "docker",
    "exec",
    "cashu-lnd-2-1",
    "lncli",
    "--network",
    "regtest",
    "--rpcserver=lnd-2",
]


def docker_clightning_cli(index):
    return [
        "docker",
        "exec",
        f"cashu-clightning-{index}-1",
        "lightning-cli",
        "--network",
        "regtest",
    ]


def run_cmd(cmd: list) -> str:
    timeout = 20
    process = Popen(cmd, stdout=PIPE, stderr=PIPE)

    def process_communication(comm):
        stdout, stderr = comm
        output = stdout.decode("utf-8").strip()
        error = stderr.decode("utf-8").strip()
        return output, error

    try:
        now = time.time()
        output, error = process_communication(process.communicate(timeout=timeout))
        took = time.time() - now
        logger.debug(f"ran command output: {output}, error: {error}, took: {took}s")
        return output
    except TimeoutExpired:
        process.kill()
        output, error = process_communication(process.communicate())
        logger.error(f"timeout command: {cmd}, output: {output}, error: {error}")
        raise


def run_cmd_json(cmd: list) -> dict:
    output = run_cmd(cmd)
    try:
        return json.loads(output) if output else {}
    except json.decoder.JSONDecodeError:
        logger.error(f"failed to decode json from cmd `{cmd}`: {output}")
        raise


def get_hold_invoice(sats: int) -> Tuple[str, dict]:
    preimage = os.urandom(32)
    preimage_hash = hashlib.sha256(preimage).hexdigest()
    cmd = docker_lightning_cli.copy()
    cmd.extend(["addholdinvoice", preimage_hash, str(sats)])
    json = run_cmd_json(cmd)
    return preimage.hex(), json


def settle_invoice(preimage: str) -> str:
    cmd = docker_lightning_cli.copy()
    cmd.extend(["settleinvoice", preimage])
    return run_cmd(cmd)


def cancel_invoice(preimage_hash: str) -> str:
    cmd = docker_lightning_cli.copy()
    cmd.extend(["cancelinvoice", preimage_hash])
    return run_cmd(cmd)


def get_real_invoice(sats: int) -> dict:
    cmd = docker_lightning_cli.copy()
    cmd.extend(["addinvoice", str(sats)])
    return run_cmd_json(cmd)


def pay_real_invoice(invoice: str) -> str:
    cmd = docker_lightning_cli.copy()
    cmd.extend(["payinvoice", "--force", invoice])
    return run_cmd(cmd)


def partial_pay_real_invoice(invoice: str, amount: int, node: int) -> str:
    cmd = docker_clightning_cli(node)
    cmd.extend(["pay", f"bolt11={invoice}", f"partial_msat={amount*1000}"])
    return run_cmd(cmd)


def get_real_invoice_cln(sats: int) -> str:
    cmd = docker_clightning_cli(1)
    cmd.extend(
        ["invoice", f"{sats*1000}", hashlib.sha256(os.urandom(32)).hexdigest(), "test"]
    )
    result = run_cmd_json(cmd)
    return result["bolt11"]


def mine_blocks(blocks: int = 1) -> str:
    cmd = docker_bitcoin_cli.copy()
    cmd.extend(["-generate", str(blocks)])
    return run_cmd(cmd)


def get_unconnected_node_uri() -> str:
    cmd = docker_lightning_unconnected_cli.copy()
    cmd.append("getinfo")
    info = run_cmd_json(cmd)
    pubkey = info["identity_pubkey"]
    return f"{pubkey}@lnd-2:9735"


def create_onchain_address(address_type: str = "bech32") -> str:
    cmd = docker_bitcoin_cli.copy()
    cmd.extend(["getnewaddress", address_type])
    return run_cmd(cmd)


def pay_onchain(address: str, sats: int) -> str:
    btc = sats * 0.00000001
    cmd = docker_bitcoin_cli.copy()
    cmd.extend(["sendtoaddress", address, str(btc)])
    return run_cmd(cmd)


async def pay_if_regtest(bolt11: str) -> None:
    if is_regtest:
        pay_real_invoice(bolt11)
    if is_fake:
        await asyncio.sleep(settings.fakewallet_delay_incoming_payment or 0)
    await asyncio.sleep(0.1)
