import os
import re
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from tests.compatibility import load_targets

ROOT = Path(__file__).resolve().parents[2]
ENABLED = os.getenv("CASHU_TEST_COMPATIBILITY", "").lower() == "true"
MINT_IMAGES = load_targets() if ENABLED else {}

pytestmark = pytest.mark.skipif(
    not ENABLED,
    reason="Run with make test-wallet-compatibility (requires Docker)",
)


@pytest.fixture(scope="session", autouse=True)
def mint():
    """The released_mint fixture starts the mint for this suite."""


def docker(*args: str, timeout: int = 60) -> str:
    result = subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


@pytest.fixture(params=MINT_IMAGES, ids=MINT_IMAGES)
def released_mint(request):
    version = request.param
    image = MINT_IMAGES[version]
    name = f"nutshell-compat-{uuid4().hex}"
    docker("pull", image, timeout=300)
    try:
        docker(
            "run",
            "--detach",
            "--name",
            name,
            "--publish",
            "127.0.0.1::3338",
            "--env",
            "MINT_BACKEND_BOLT11_SAT=FakeWallet",
            "--env",
            "MINT_LISTEN_HOST=0.0.0.0",
            "--env",
            "MINT_LISTEN_PORT=3338",
            "--env",
            "MINT_PRIVATE_KEY=TEST_PRIVATE_KEY",
            "--env",
            "MINT_DATABASE=/tmp/compat-mint",
            "--env",
            "MINT_INPUT_FEE_PPK=0",
            "--env",
            "FAKEWALLET_BRR=true",
            "--env",
            "FAKEWALLET_DELAY_INCOMING_PAYMENT=0",
            image,
            "poetry",
            "run",
            "mint",
        )
        port = docker("port", name, "3338/tcp").rsplit(":", 1)[1]
        url = f"http://127.0.0.1:{port}"
        with httpx.Client(base_url=url, timeout=2, trust_env=False) as client:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                try:
                    response = client.get("/v1/info")
                    if response.status_code == 200:
                        info = response.json()
                        assert info["version"] == f"Nutshell/{version}", info
                        break
                except httpx.TransportError:
                    pass
                time.sleep(0.5)
            else:
                pytest.fail(f"Nutshell {version} did not become ready")
        yield url
    finally:
        try:
            logs = subprocess.run(
                ["docker", "logs", name], capture_output=True, text=True, timeout=30
            )
            print(f"\nNutshell {version} logs:\n{logs.stdout}{logs.stderr}")
        finally:
            docker("rm", "--force", name)


def test_cli_mints_against_released_mint(released_mint, tmp_path):
    (tmp_path / ".env").touch()
    env = {
        "PATH": os.environ["PATH"],
        "PYTHONPATH": str(ROOT),
        "PYTHONUNBUFFERED": "1",
        "CASHU_DIR": str(tmp_path / "wallets"),
        "TOR": "false",
    }

    def cashu(*args: str) -> str:
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from cashu.wallet.cli.cli import cli; cli()",
                "--host",
                released_mint,
                "--wallet",
                "compatibility",
                "--unit",
                "sat",
                "--yes",
                *args,
            ],
            cwd=tmp_path,
            env=env,
            input="",
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout

    assert re.search(r"^Balance: 0 sat$", cashu("balance"), re.MULTILINE)
    output = cashu("invoice", "64", "--no-check")
    quote_match = re.search(r"cashu invoice 64 --id (\S+)", output)
    assert quote_match, output
    quote_id = quote_match[1]

    with httpx.Client(base_url=released_mint, timeout=5, trust_env=False) as client:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            response = client.get(f"/v1/mint/quote/bolt11/{quote_id}")
            response.raise_for_status()
            quote = response.json()
            assert quote["pubkey"], "The mint quote must remain signature-locked"
            if quote["state"] == "PAID":
                break
            time.sleep(0.2)
        else:
            pytest.fail(f"FakeWallet did not pay quote: {quote}")

        cashu("invoice", "64", "--id", quote_id)
        assert re.search(r"^Balance: 64 sat$", cashu("balance"), re.MULTILINE)
        response = client.get(f"/v1/mint/quote/bolt11/{quote_id}")
        response.raise_for_status()
        assert response.json()["state"] == "ISSUED"
