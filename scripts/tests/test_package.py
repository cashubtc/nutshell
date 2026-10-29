"""Exercise secret and symlink attacks against real distribution builds."""

import importlib.util
import io
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CANARY = b"TEST_ONLY_PACKAGE_SECRET_1211"


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    with pytest.MonkeyPatch.context() as patch:
        patch.syspath_prepend(str(ROOT / "scripts"))
        spec.loader.exec_module(module)
    return module


backend = load_script("build_backend")
checker = load_script("check_package")


@pytest.fixture
def project(tmp_path):
    project = tmp_path / "project"
    for name in (*backend.SOURCE_FILES, *backend.package_files(ROOT)):
        target = project / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)
    yield project
    shutil.rmtree(project)


def build(project, *args):
    return subprocess.run(
        [
            "uv",
            "build",
            "--clear",
            "--no-sources",
            "--python",
            sys.executable,
            *args,
        ],
        cwd=project,
        capture_output=True,
        text=True,
    )


def assert_no_canary(artifact):
    if artifact.suffix == ".whl":
        with zipfile.ZipFile(artifact) as archive:
            assert all(CANARY not in archive.read(name) for name in archive.namelist())
    else:
        with tarfile.open(artifact) as archive:
            assert all(
                CANARY not in archive.extractfile(member).read()
                for member in archive.getmembers()
                if member.isfile()
            )


def test_manifest_contains_all_tracked_package_files():
    tracked = subprocess.check_output(
        ["git", "ls-files", "-z", "cashu"], cwd=ROOT, text=True
    ).split("\0")[:-1]
    assert set(backend.package_files(ROOT)) == set(tracked)


@pytest.mark.parametrize("git_checkout", [False, True])
def test_build_excludes_local_secrets_and_preserves_resources(project, git_checkout):
    if git_checkout:
        subprocess.run(["git", "init", "-q"], cwd=project, check=True)
        shutil.copy2(ROOT / ".gitignore", project / ".gitignore")
        with (project / ".gitignore").open("a") as stream:
            stream.write("\noperator-settings.py\nprivate-store\n")
    for name in (
        "cashu/mint/.env",
        "cashu/mint/mint.sqlite3",
        "cashu/mint/operator.db",
        "cashu/mint/seed.key",
        "cashu/mint/operator.log",
        "cashu/mint/operator-settings.py",
        "cashu/mint/private-store",
        "cashu/tor/bundle/linux/private-store",
        "cashu/wallet/.ssh/id_ed25519",
    ):
        target = project / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(CANARY)
    if git_checkout:
        # Even an accidentally tracked secret is excluded by the allow-list.
        subprocess.run(
            ["git", "add", "--force", "cashu/mint/.env"], cwd=project, check=True
        )

    result = build(project)
    assert result.returncode == 0, result.stderr
    wheel = next((project / "dist").glob("*.whl"))
    sdist = next((project / "dist").glob("*.tar.gz"))
    checker.check_contents(wheel, sdist)
    assert_no_canary(wheel)
    assert_no_canary(sdist)
    with zipfile.ZipFile(wheel) as archive:
        for name in backend.package_files(ROOT):
            assert archive.read(name) == (ROOT / name).read_bytes()
        if os.name != "nt":
            for name in ("cashu/tor/bundle/linux/tor", "cashu/tor/bundle/mac/tor"):
                assert archive.getinfo(name).external_attr >> 16 & stat.S_IXUSR
        entry_points = archive.read("cashu-0.21.0.dist-info/entry_points.txt").decode()
        assert "mint = cashu.mint.main:main" in entry_points
        assert "cashu = cashu.wallet.cli.cli:cli" in entry_points
        assert "mint-cli = cashu.mint.management_rpc.cli.cli:cli" in entry_points

    # Exercise the direct-wheel path separately from uv's wheel-from-sdist path.
    result = build(project, "--wheel", "--out-dir", "direct")
    assert result.returncode == 0, result.stderr
    direct = next((project / "direct").glob("*.whl"))
    checker.check_contents(direct, sdist)
    assert_no_canary(direct)


@pytest.mark.parametrize("wheel_only", [False, True])
@pytest.mark.parametrize(
    "name,target,directory",
    [
        ("cashu/telemetry_usage.py", "../.git/config", False),
        ("cashu/core/base.py", "absolute", False),
        ("cashu/mint/telemetry.py", ".env", False),
        ("cashu/broken.py", "missing", False),
        ("cashu/linked", "absolute", True),
        ("cashu/mint", "absolute", True),
        ("cashu", "absolute", True),
        ("README.md", "absolute", False),
        ("requirements.txt", "absolute", False),
    ],
)
def test_build_rejects_symlinks(project, tmp_path, name, target, directory, wheel_only):
    outside = tmp_path / "outside"
    if directory:
        outside.mkdir()
        (outside / "secret.py").write_bytes(CANARY)
    else:
        outside.write_bytes(CANARY)
    if target == "../.git/config":
        subprocess.run(["git", "init", "-q"], cwd=project, check=True)
        subprocess.run(
            ["git", "config", "http.https://github.com/.extraheader", CANARY.decode()],
            cwd=project,
            check=True,
        )
    elif target == ".env":
        (project / "cashu/mint/.env").write_bytes(CANARY)
    path = project / name
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()
    try:
        path.symlink_to(outside if target == "absolute" else target, directory)
    except OSError as error:
        pytest.skip(f"Symlinks unavailable: {error}")
    if target == "../.git/config":
        subprocess.run(["git", "add", name], cwd=project, check=True)

    result = build(project, *(["--wheel"] if wheel_only else []))
    assert result.returncode != 0
    assert "Packaging refuses symlink" in result.stderr
    assert not list((project / "dist").glob("*.whl"))
    assert not list((project / "dist").glob("*.tar.gz"))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="Requires POSIX FIFOs")
def test_build_rejects_special_files_without_reading_them(project):
    path = project / "cashu/__init__.py"
    path.unlink()
    os.mkfifo(path)
    result = build(project, "--wheel")
    assert result.returncode != 0
    assert "Packaging requires a regular file" in result.stderr


@pytest.mark.parametrize(
    "path", ["../outside", "cashu/../../outside", "/outside", "cashu\\outside"]
)
def test_manifest_rejects_unsafe_paths(project, path):
    (project / "package-files.txt").write_text(path + "\n")
    result = build(project, "--wheel")
    assert result.returncode != 0
    assert "Invalid package path" in result.stderr


@pytest.mark.parametrize("artifact", ["wheel", "sdist"])
@pytest.mark.parametrize(
    "attack",
    ["secret", "metadata-secret", "symlink", "hardlink", "traversal", "duplicate"],
)
def test_artifact_check_rejects_unexpected_contents(tmp_path, artifact, attack):
    wheel = tmp_path / "cashu-0.21.0-py3-none-any.whl"
    sdist = tmp_path / "cashu-0.21.0.tar.gz"
    package = backend.package_files(ROOT)
    metadata = [
        "METADATA",
        "WHEEL",
        "RECORD",
        "entry_points.txt",
        "licenses/LICENSE.md",
    ]
    attack_name = {
        "secret": "cashu/mint/.env",
        "metadata-secret": "cashu-0.21.0.dist-info/.env",
        "symlink": "cashu/leak.py",
        "hardlink": "cashu/leak.py",
        "traversal": "cashu/../../outside",
        "duplicate": "cashu/__init__.py",
    }[attack]
    with zipfile.ZipFile(wheel, "w") as archive:
        for name in package + [f"cashu-0.21.0.dist-info/{name}" for name in metadata]:
            archive.writestr(name, b"safe")
        if artifact == "wheel":
            member = zipfile.ZipInfo(attack_name)
            member.create_system = 3
            kind = stat.S_IFLNK if attack in ("symlink", "hardlink") else stat.S_IFREG
            member.external_attr = (kind | 0o644) << 16
            archive.writestr(member, CANARY)
    with tarfile.open(sdist, "w:gz") as archive:
        for name in (
            package + list(backend.SOURCE_FILES) + ["PKG-INFO", "pyproject.toml.orig"]
        ):
            member = tarfile.TarInfo(f"cashu-0.21.0/{name}")
            member.size = 4
            archive.addfile(member, io.BytesIO(b"safe"))
        if artifact == "sdist":
            member = tarfile.TarInfo(f"cashu-0.21.0/{attack_name}")
            if attack in ("symlink", "hardlink"):
                member.type = (
                    tarfile.SYMTYPE if attack == "symlink" else tarfile.LNKTYPE
                )
                member.linkname = "/outside"
                archive.addfile(member)
            else:
                member.size = len(CANARY)
                archive.addfile(member, io.BytesIO(CANARY))
    with pytest.raises(ValueError):
        checker.check_contents(wheel, sdist)
