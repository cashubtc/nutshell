"""Run the wallet test suite against released Nutshell mint images. Resolve targets
with `python -m tests.compatibility`; run one by setting CASHU_TEST_MINT_IMAGE."""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

import httpx
import pytest

from cashu.core.settings import settings

RELEASE_LINES = 3
MINT_IMAGE = os.getenv("CASHU_TEST_MINT_IMAGE", "")


# Older mints are unsupported (cashubtc/nutshell#1086). Against them, failures with
# BELOW_MINIMUM_ERROR are expected (see tests/conftest.py).
MINIMUM_MINT_VERSION = "0.20.1"
MINIMUM_MINT_VERSION_REFERENCE = "https://github.com/cashubtc/nutshell/pull/1086"
BELOW_MINIMUM_ERROR = (
    "validation error for PostMintQuoteResponse\nmethod\n  Field required"
)


def parse_version(version: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", version)
    if match is None:
        raise ValueError(f"Expected a release version, got {version!r}")
    major, minor, patch = map(int, match.groups())
    return major, minor, patch


def image_version(image: str) -> str:
    """Release version from an image reference such as `repo:0.20.3@sha256:...`."""
    match = re.search(r":(v?\d+\.\d+\.\d+)(?:@|$)", image)
    if match is None:
        raise ValueError(f"Expected a release tag in mint image {image!r}")
    return match[1].removeprefix("v")


MINT_VERSION: Optional[str] = image_version(MINT_IMAGE) if MINT_IMAGE else None


def mint_older_than(version: str) -> bool:
    """Whether the tests run against a released mint older than `version`."""
    return MINT_VERSION is not None and parse_version(MINT_VERSION) < parse_version(
        version
    )


# For tests that need funds minted earlier but whose failure does not carry
# BELOW_MINIMUM_ERROR, because the CLI reports the error and carries on.
xfail_below_minimum = pytest.mark.xfail(
    mint_older_than(MINIMUM_MINT_VERSION),
    reason=f"Minting fails on mints older than {MINIMUM_MINT_VERSION}",
    strict=True,
)


# Resolving targets


def select_release_tags(releases: list[dict], lines: int = RELEASE_LINES) -> list[str]:
    """Select the latest stable patch of each of the most recent release lines."""
    if lines < 1:
        raise ValueError("Expected a positive number of release lines")
    candidates = []
    for release in releases:
        if release["draft"] or release["prerelease"]:
            continue
        try:
            candidates.append((parse_version(release["tag_name"]), release["tag_name"]))
        except ValueError:
            continue

    latest: dict[tuple[int, ...], str] = {}
    for version, tag in sorted(candidates, reverse=True):
        latest.setdefault(version[:2], tag)
    if len(latest) < lines:
        raise ValueError(f"Expected {lines} release lines, found {len(latest)}")
    return list(latest.values())[:lines]


def fetch_releases(repository: str, client: httpx.Client) -> list[dict]:
    releases = []
    url = f"https://api.github.com/repos/{repository}/releases?per_page=100"
    while url:
        response = client.get(url)
        response.raise_for_status()
        page = response.json()
        if not isinstance(page, list):
            raise ValueError(f"Invalid release list from {url}")
        releases.extend(page)
        url = response.links.get("next", {}).get("url", "")
    return releases


def pin_image(image: str) -> str:
    result = subprocess.run(
        [
            "docker",
            "buildx",
            "imagetools",
            "inspect",
            image,
            "--format",
            "{{json .Manifest}}",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode:
        raise RuntimeError(f"Could not resolve {image}: {result.stderr.strip()}")
    digest = json.loads(result.stdout).get("digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError(f"Invalid image digest for {image}: {digest!r}")
    return f"{image}@{digest}"


def resolve_targets(
    repository: str, image_repository: str, lines: int = RELEASE_LINES
) -> list[dict[str, str]]:
    headers = {"Accept": "application/vnd.github+json"}
    if token := os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    with httpx.Client(headers=headers, timeout=30) as client:
        releases = fetch_releases(repository, client)
    tags = select_release_tags(releases, lines)
    return [
        {
            "version": tag.removeprefix("v"),
            "image": pin_image(f"{image_repository}:{tag}"),
        }
        for tag in tags
    ]


# Running a released mint


# Settings from tests/conftest.py that shape the mint's behavior under test.
FORWARDED_SETTINGS = [
    "mint_url",
    "mint_private_key",
    "mint_seed_decryption_key",
    "mint_derivation_path",
    "mint_derivation_path_list",
    "mint_backend_bolt11_sat",
    "mint_backend_bolt11_usd",
    "fakewallet_brr",
    "fakewallet_delay_outgoing_payment",
    "fakewallet_delay_incoming_payment",
    "fakewallet_stochastic_invoice",
    "lightning_fee_percent",
    "lightning_reserve_fee_min",
    "mint_max_balance",
    "mint_transaction_rate_limit_per_minute",
    "mint_input_fee_ppk",
    "mint_lnd_enable_mpp",
    "mint_clnrest_enable_mpp",
    "mint_watchdog_enabled",
    "db_connection_pool",
]


def env_value(value) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, list):
        return json.dumps(value)
    return str(value)


def mint_container_env(port: int) -> dict[str, str]:
    env = {
        name.upper(): env_value(getattr(settings, name))
        for name in FORWARDED_SETTINGS
        if getattr(settings, name) is not None
    }
    env.update(
        DEBUG="true",
        TOR="false",
        MINT_LISTEN_HOST="0.0.0.0",
        MINT_LISTEN_PORT=str(port),
        MINT_DATABASE="data/mint",
        # The rate limiter exempts only 127.0.0.1, and requests through Docker's
        # port mapping arrive from the bridge gateway instead.
        MINT_RATE_LIMIT="false",
    )
    return env


def docker(*args: str, timeout: int = 60) -> str:
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout
    )
    if result.returncode:
        raise RuntimeError(f"docker {args[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


@contextmanager
def run_mint_container(image: str, port: int, log_file: Path) -> Iterator[str]:
    """Run a released mint on localhost:`port`, configured like the test mint."""
    if settings.mint_backend_bolt11_sat != "FakeWallet":
        raise RuntimeError(
            "Released mint images run with FakeWallet, but MINT_BACKEND_BOLT11_SAT is "
            f"{settings.mint_backend_bolt11_sat!r}. A local .env overrides "
            "environment variables."
        )
    version = image_version(image)
    docker("pull", image, timeout=300)
    env_args = [
        arg
        for key, value in mint_container_env(port).items()
        for arg in ("--env", f"{key}={value}")
    ]
    name = f"nutshell-test-mint-{os.getpid()}"
    try:
        docker(
            "run",
            "--detach",
            "--name",
            name,
            "--publish",
            f"127.0.0.1:{port}:{port}",
            *env_args,
            image,
            "poetry",
            "run",
            "mint",
        )
        url = f"http://localhost:{port}"
        deadline = time.monotonic() + 60
        while True:
            try:
                response = httpx.get(f"{url}/v1/info", timeout=2)
                if response.status_code == 200:
                    break
            except httpx.TransportError:
                pass
            if time.monotonic() > deadline:
                raise RuntimeError(f"Nutshell {version} did not become ready")
            time.sleep(0.5)
        reported = response.json().get("version")
        if reported != f"Nutshell/{version}":
            raise RuntimeError(f"{image} reports {reported!r}, expected {version}")
        yield url
    finally:
        # Cleanup must not raise, or it would replace the error that got us here.
        try:
            logs = subprocess.run(
                ["docker", "logs", name], capture_output=True, text=True, timeout=30
            )
            log_file.write_text(logs.stdout + logs.stderr)
        except (OSError, subprocess.SubprocessError) as exc:
            print(f"Could not save the logs of {name}: {exc}", file=sys.stderr)
        finally:
            try:
                subprocess.run(
                    ["docker", "rm", "--force", name], capture_output=True, timeout=60
                )
            except (OSError, subprocess.SubprocessError) as exc:
                print(f"Could not remove container {name}: {exc}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Print the released mint images to test as a JSON list."
    )
    parser.add_argument("--repository", default="cashubtc/nutshell")
    parser.add_argument("--image-repository", default="cashubtc/nutshell")
    parser.add_argument("--lines", type=int, default=RELEASE_LINES)
    args = parser.parse_args()
    try:
        targets = resolve_targets(args.repository, args.image_repository, args.lines)
    except (
        ValueError,
        RuntimeError,
        httpx.HTTPError,
        subprocess.TimeoutExpired,
    ) as exc:
        parser.exit(1, f"Compatibility target resolution failed: {exc}\n")
    print(json.dumps(targets, separators=(",", ":")))
    for target in targets:
        print(f"{target['version']}: {target['image']}", file=sys.stderr)


if __name__ == "__main__":
    main()
