import json
import subprocess
from unittest.mock import Mock

import httpx
import pytest

from cashu.core.settings import settings
from tests import compatibility

DIGEST = "sha256:" + "a" * 64
RELEASES_URL = "https://api.github.com/repos/cashubtc/nutshell/releases?per_page=100"


@pytest.fixture(scope="session", autouse=True)
def mint():
    """Resolver tests do not need a running mint."""


def release(tag, **kwargs):
    return {"tag_name": tag, "draft": False, "prerelease": False, **kwargs}


def test_select_latest_stable_patch_of_recent_lines():
    releases = [
        release("v0.19.3"),
        release("0.20.9"),
        release("0.21.0"),
        release("0.20.10"),
        release("0.21.1", draft=True),
        release("0.21.2", prerelease=True),
        release("0.22.0-rc1"),
        release("0.19.2"),
        release("0.18.20"),
        release("latest"),
    ]
    assert compatibility.select_release_tags(releases) == [
        "0.21.0",
        "0.20.10",
        "v0.19.3",
    ]


def test_missing_release_line_fails():
    releases = [release("0.21.0"), release("0.20.3")]
    with pytest.raises(ValueError, match="Expected 3 release lines, found 2"):
        compatibility.select_release_tags(releases)


def test_invalid_line_count_fails():
    with pytest.raises(ValueError, match="positive"):
        compatibility.select_release_tags([release("0.21.0")], 0)


def test_resolve_all_pages_before_selecting(respx_mock, monkeypatch):
    next_page = RELEASES_URL + "&page=2"
    first = respx_mock.get(RELEASES_URL).respond(
        json=[release("0.21.0"), release("0.20.3"), release("0.19.2")],
        headers={"Link": f'<{next_page}>; rel="next"'},
    )
    second = respx_mock.get(next_page).respond(
        json=[release("0.20.10"), release("v0.19.3")]
    )
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    pin = Mock(side_effect=lambda image: f"{image}@{DIGEST}")
    monkeypatch.setattr(compatibility, "pin_image", pin)

    targets = compatibility.resolve_targets("cashubtc/nutshell", "cashubtc/nutshell")

    assert targets == [
        {"version": "0.21.0", "image": f"cashubtc/nutshell:0.21.0@{DIGEST}"},
        {"version": "0.20.10", "image": f"cashubtc/nutshell:0.20.10@{DIGEST}"},
        {"version": "0.19.3", "image": f"cashubtc/nutshell:v0.19.3@{DIGEST}"},
    ]
    assert first.called and second.called
    assert first.calls[0].request.headers["Authorization"] == "Bearer test-token"
    assert pin.call_count == 3


def test_discovery_failure_does_not_select_fallbacks(respx_mock, monkeypatch):
    respx_mock.get(RELEASES_URL).respond(403, json={"message": "rate limited"})
    pin = Mock()
    monkeypatch.setattr(compatibility, "pin_image", pin)
    with pytest.raises(httpx.HTTPStatusError):
        compatibility.resolve_targets("cashubtc/nutshell", "cashubtc/nutshell")
    pin.assert_not_called()


def test_unpublished_image_does_not_fall_back_to_older_patch(respx_mock, monkeypatch):
    respx_mock.get(RELEASES_URL).respond(
        json=[
            release("0.21.1"),
            release("0.21.0"),
            release("0.20.3"),
            release("0.19.2"),
        ]
    )
    run = Mock(return_value=subprocess.CompletedProcess([], 1, "", "manifest unknown"))
    monkeypatch.setattr(compatibility.subprocess, "run", run)
    with pytest.raises(
        RuntimeError, match="Could not resolve cashubtc/nutshell:0.21.1"
    ):
        compatibility.resolve_targets("cashubtc/nutshell", "cashubtc/nutshell")
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
    "image, version",
    [
        ("cashubtc/nutshell:0.20.3", "0.20.3"),
        (f"cashubtc/nutshell:v0.19.3@{DIGEST}", "0.19.3"),
        ("localhost:5000/nutshell:0.21.0", "0.21.0"),
    ],
)
def test_image_version(image, version):
    assert compatibility.image_version(image) == version


@pytest.mark.parametrize(
    "image", ["cashubtc/nutshell", "cashubtc/nutshell:latest", f"nutshell@{DIGEST}"]
)
def test_image_without_release_tag_fails(image):
    with pytest.raises(ValueError, match="release tag"):
        compatibility.image_version(image)


def test_mint_older_than(monkeypatch):
    monkeypatch.setattr(compatibility, "MINT_VERSION", None)
    assert not compatibility.mint_older_than("0.21.0")
    monkeypatch.setattr(compatibility, "MINT_VERSION", "0.20.3")
    assert compatibility.mint_older_than("0.21.0")
    assert not compatibility.mint_older_than("0.20.3")


def test_mint_container_env_mirrors_test_settings():
    env = compatibility.mint_container_env(3337)
    assert env["MINT_PRIVATE_KEY"] == settings.mint_private_key
    assert env["MINT_DERIVATION_PATH_LIST"] == json.dumps(
        settings.mint_derivation_path_list
    )
    assert env["FAKEWALLET_BRR"] == str(settings.fakewallet_brr).lower()
    assert env["MINT_LISTEN_PORT"] == "3337"
    assert env["MINT_RATE_LIMIT"] == "false"


def test_main_prints_targets_as_json(monkeypatch, capsys):
    targets = [{"version": "0.21.0", "image": f"cashubtc/nutshell:0.21.0@{DIGEST}"}]
    resolve = Mock(return_value=targets)
    monkeypatch.setattr(compatibility, "resolve_targets", resolve)
    monkeypatch.setattr("sys.argv", ["compatibility"])

    compatibility.main()

    assert json.loads(capsys.readouterr().out) == targets
    resolve.assert_called_once_with("cashubtc/nutshell", "cashubtc/nutshell", 3)


class FakeDocker:
    """Stands in for subprocess.run, failing the given docker subcommands."""

    def __init__(self, fail=(), timeout=()):
        self.fail, self.timeout, self.calls = fail, timeout, []

    def __call__(self, args, **kwargs):
        command = args[1]
        self.calls.append(command)
        if command in self.timeout:
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])
        failed = command in self.fail
        return subprocess.CompletedProcess(args, int(failed), "", "failed" * failed)


@pytest.fixture
def ready_mint(monkeypatch):
    monkeypatch.setattr(settings, "mint_backend_bolt11_sat", "FakeWallet")
    info = Mock(status_code=200, json=Mock(return_value={"version": "Nutshell/0.20.3"}))
    monkeypatch.setattr(compatibility.httpx, "get", Mock(return_value=info))


def run_container(tmp_path):
    return compatibility.run_mint_container(
        "cashubtc/nutshell:0.20.3", 3337, tmp_path / "mint.log"
    )


def test_container_removed_when_start_fails(monkeypatch, tmp_path, ready_mint):
    docker = FakeDocker(fail={"run"})
    monkeypatch.setattr(compatibility.subprocess, "run", docker)
    with pytest.raises(RuntimeError, match="docker run failed"):
        with run_container(tmp_path):
            pass
    assert docker.calls == ["pull", "run", "logs", "rm"]


def test_container_removed_when_saving_logs_fails(monkeypatch, tmp_path, ready_mint):
    docker = FakeDocker(timeout={"logs"})
    monkeypatch.setattr(compatibility.subprocess, "run", docker)
    with run_container(tmp_path) as url:
        assert url == "http://localhost:3337"
    assert docker.calls == ["pull", "run", "logs", "rm"]


def test_cleanup_failure_keeps_original_error(monkeypatch, tmp_path, ready_mint):
    docker = FakeDocker(timeout={"logs", "rm"})
    monkeypatch.setattr(compatibility.subprocess, "run", docker)
    with pytest.raises(ValueError, match="test failure"):
        with run_container(tmp_path):
            raise ValueError("test failure")
    assert docker.calls == ["pull", "run", "logs", "rm"]
