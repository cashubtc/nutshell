"""Resolve released container images for compatibility suites."""

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

import httpx

TARGETS_FILE = Path("compatibility-targets.json")


def select_release_tags(
    releases: list[dict], current_version: str, previous_lines: int = 2
) -> list[str]:
    """Select the latest stable patch in each preceding major.minor release line."""
    current = re.match(r"^v?(\d+)\.(\d+)\.", current_version)
    if current is None or previous_lines < 1:
        raise ValueError("Expected a release version and a positive release-line count")
    current_line = tuple(map(int, current.groups()))
    candidates = []
    for release in releases:
        if release["draft"] or release["prerelease"]:
            continue
        tag = release["tag_name"]
        version_match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", tag)
        if version_match:
            parsed = tuple(map(int, version_match.groups()))
            if parsed[:2] < current_line:
                candidates.append((parsed, tag))

    latest: dict[tuple[int, ...], str] = {}
    for version, tag in sorted(candidates, reverse=True):
        latest.setdefault(version[:2], tag)
    if len(latest) < previous_lines:
        raise ValueError(
            f"Expected {previous_lines} released lines before {current_version}, "
            f"found {len(latest)}"
        )
    return list(latest.values())[:previous_lines]


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


def resolve_release_images(
    repository: str,
    image_repository: str,
    current_version: str,
    previous_lines: int = 2,
) -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    if token := os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    with httpx.Client(headers=headers, timeout=30) as client:
        releases = fetch_releases(repository, client)
    tags = select_release_tags(releases, current_version, previous_lines)
    return {
        tag.removeprefix("v"): pin_image(f"{image_repository}:{tag}") for tag in tags
    }


def load_targets(path: Path = TARGETS_FILE) -> dict[str, str]:
    targets = json.loads(path.read_text())
    if not isinstance(targets, dict) or not targets:
        raise ValueError(f"Expected a nonempty version-to-image mapping in {path}")
    for version, image in targets.items():
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise ValueError(f"Invalid release version in {path}: {version!r}")
        if not isinstance(image, str) or not re.fullmatch(
            r"[^@\s]+@sha256:[0-9a-f]{64}", image
        ):
            raise ValueError(f"Expected a digest-pinned image for {version} in {path}")
    return targets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current-version", required=True)
    parser.add_argument("--repository", default="cashubtc/nutshell")
    parser.add_argument("--image-repository", default="cashubtc/nutshell")
    parser.add_argument("--previous-lines", type=int, default=2)
    parser.add_argument("--output", type=Path, default=TARGETS_FILE)
    args = parser.parse_args()
    try:
        targets = resolve_release_images(
            args.repository,
            args.image_repository,
            args.current_version,
            args.previous_lines,
        )
        manifest = json.dumps(targets, indent=2) + "\n"
        args.output.write_text(manifest)
    except (
        OSError,
        ValueError,
        RuntimeError,
        httpx.HTTPError,
        subprocess.TimeoutExpired,
    ) as exc:
        parser.exit(1, f"Compatibility target resolution failed: {exc}\n")
    print(f"Compatibility targets saved to {args.output}:\n{manifest}", end="")


if __name__ == "__main__":
    main()
