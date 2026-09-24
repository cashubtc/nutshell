import json
import subprocess
from unittest.mock import Mock

import httpx
import pytest

from tests import compatibility

DIGEST = "sha256:" + "a" * 64
RELEASES_URL = "https://api.github.com/repos/cashubtc/nutshell/releases?per_page=100"


@pytest.fixture(scope="session", autouse=True)
def mint():
    """Resolver tests do not need a running mint."""


def release(tag, **kwargs):
    return {"tag_name": tag, "draft": False, "prerelease": False, **kwargs}


def test_select_latest_stable_patch_per_line():
    releases = [
        release("v0.19.3"),
        release("0.20.9"),
        release("0.21.0"),
        release("0.20.10"),
        release("0.20.11", draft=True),
        release("0.20.12", prerelease=True),
        release("0.20.13-rc1"),
        release("0.19.2"),
        release("0.22.0"),
        release("0.18.20"),
        release("latest"),
    ]
    assert compatibility.select_release_tags(releases, "0.21.0") == [
        "0.20.10",
        "v0.19.3",
    ]


@pytest.mark.parametrize(
    "current, expected",
    [
        ("0.21.1", ["0.20.3", "0.19.2"]),
        ("0.22.0", ["0.21.1", "0.20.3"]),
        ("0.22.0rc1", ["0.21.1", "0.20.3"]),
        ("1.0.0", ["0.21.1", "0.20.3"]),
    ],
)
def test_support_window_follows_checkout(current, expected):
    releases = [release(tag) for tag in ["0.19.2", "0.20.3", "0.21.1"]]
    assert compatibility.select_release_tags(releases, current) == expected


def test_missing_release_line_fails():
    with pytest.raises(ValueError, match="Expected 2 released lines.*found 1"):
        compatibility.select_release_tags([release("0.20.3")], "0.21.0")


@pytest.mark.parametrize("current, count", [("main", 2), ("0.21.0", 0)])
def test_invalid_support_window_fails(current, count):
    with pytest.raises(ValueError, match="release version"):
        compatibility.select_release_tags([], current, count)


def test_resolve_all_pages_before_selecting(respx_mock, monkeypatch):
    next_page = RELEASES_URL + "&page=2"
    first = respx_mock.get(RELEASES_URL).respond(
        json=[release("0.20.3"), release("0.19.2")],
        headers={"Link": f'<{next_page}>; rel="next"'},
    )
    second = respx_mock.get(next_page).respond(
        json=[release("0.20.10"), release("v0.19.3")]
    )
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    pin = Mock(side_effect=lambda image: f"{image}@{DIGEST}")
    monkeypatch.setattr(compatibility, "pin_image", pin)

    targets = compatibility.resolve_release_images(
        "cashubtc/nutshell", "cashubtc/nutshell", "0.21.0"
    )

    assert targets == {
        "0.20.10": f"cashubtc/nutshell:0.20.10@{DIGEST}",
        "0.19.3": f"cashubtc/nutshell:v0.19.3@{DIGEST}",
    }
    assert first.called and second.called
    assert first.calls[0].request.headers["Authorization"] == "Bearer test-token"
    assert pin.call_count == 2


def test_discovery_failure_does_not_select_fallbacks(respx_mock, monkeypatch):
    respx_mock.get(RELEASES_URL).respond(403, json={"message": "rate limited"})
    pin = Mock()
    monkeypatch.setattr(compatibility, "pin_image", pin)
    with pytest.raises(httpx.HTTPStatusError):
        compatibility.resolve_release_images(
            "cashubtc/nutshell", "cashubtc/nutshell", "0.21.0"
        )
    pin.assert_not_called()


def test_unpublished_image_does_not_fall_back_to_older_patch(respx_mock, monkeypatch):
    respx_mock.get(RELEASES_URL).respond(
        json=[release("0.20.4"), release("0.20.3"), release("0.19.2")]
    )
    run = Mock(return_value=subprocess.CompletedProcess([], 1, "", "manifest unknown"))
    monkeypatch.setattr(compatibility.subprocess, "run", run)
    with pytest.raises(
        RuntimeError, match="Could not resolve cashubtc/nutshell:0.20.4"
    ):
        compatibility.resolve_release_images(
            "cashubtc/nutshell", "cashubtc/nutshell", "0.21.0"
        )
    assert run.call_count == 1


def test_pin_image_uses_manifest_digest_not_platform_digest(monkeypatch):
    manifest = {"digest": DIGEST, "manifests": [{"digest": "sha256:" + "b" * 64}]}
    monkeypatch.setattr(
        compatibility.subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(manifest), "")),
    )
    assert compatibility.pin_image("example/mint:v1.2.3") == (
        f"example/mint:v1.2.3@{DIGEST}"
    )


def test_invalid_registry_digest_fails(monkeypatch):
    monkeypatch.setattr(
        compatibility.subprocess,
        "run",
        Mock(
            return_value=subprocess.CompletedProcess([], 0, '{"digest": "latest"}', "")
        ),
    )
    with pytest.raises(ValueError, match="Invalid image digest"):
        compatibility.pin_image("example/mint:v1.2.3")


@pytest.mark.parametrize(
    "targets",
    [
        {},
        [],
        {"latest": f"example/mint@{DIGEST}"},
        {"0.20.3": "example/mint:0.20.3"},
        {"0.20.3": "example/mint@sha256:short"},
        {"0.20.3": None},
    ],
)
def test_invalid_target_manifest_fails(tmp_path, targets):
    path = tmp_path / "targets.json"
    path.write_text(json.dumps(targets))
    with pytest.raises(ValueError):
        compatibility.load_targets(path)


def test_resolver_refreshes_existing_targets(tmp_path, monkeypatch):
    targets = {
        "0.20.3": f"cashubtc/nutshell:0.20.3@{DIGEST}",
        "0.19.2": f"cashubtc/nutshell:0.19.2@{DIGEST}",
    }
    output = tmp_path / "resolved.json"
    output.write_text(json.dumps({"0.18.2": f"cashubtc/nutshell:0.18.2@{DIGEST}"}))
    monkeypatch.setattr(
        "sys.argv",
        ["compatibility", "--current-version", "0.21.0", "--output", str(output)],
    )
    resolve = Mock(return_value=targets)
    monkeypatch.setattr(compatibility, "resolve_release_images", resolve)

    compatibility.main()

    assert compatibility.load_targets(output) == targets
    resolve.assert_called_once_with(
        "cashubtc/nutshell", "cashubtc/nutshell", "0.21.0", 2
    )
