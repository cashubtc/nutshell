"""Check published artifacts with fresh dependency resolution, outside the checkout."""

import argparse
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path, PurePosixPath

from build_backend import SOURCE_FILES, package_files


def check_paths(names, expected):
    if len(names) != len(set(names)):
        raise ValueError("Distribution contains duplicate paths")
    if set(names) != expected:
        raise ValueError(
            f"Unexpected distribution contents: extra={sorted(set(names) - expected)}, "
            f"missing={sorted(expected - set(names))}"
        )


def check_member(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name:
        raise ValueError(f"Unsafe distribution path: {name!r}")


def check_contents(wheel, sdist):
    """Check all paths, not just known secret filenames, before installing."""
    allowed = set(package_files(Path(__file__).resolve().parents[1]))
    with zipfile.ZipFile(wheel) as archive:
        names = []
        for member in archive.infolist():
            check_member(member.filename)
            kind = stat.S_IFMT(member.external_attr >> 16)
            if kind not in (0, stat.S_IFDIR, stat.S_IFREG):
                raise ValueError(
                    f"Distribution contains a link or special file: {member.filename}"
                )
            if not member.is_dir():
                names.append(member.filename)
        metadata = {name.split("/")[0] for name in names if ".dist-info/" in name}
        if len(metadata) != 1:
            raise ValueError("Expected exactly one wheel metadata directory")
        prefix = metadata.pop()
        check_paths(
            names,
            allowed
            | {
                f"{prefix}/{name}"
                for name in (
                    "METADATA",
                    "WHEEL",
                    "RECORD",
                    "entry_points.txt",
                    "licenses/LICENSE.md",
                )
            },
        )
    with tarfile.open(sdist) as archive:
        names = []
        prefix = sdist.name.removesuffix(".tar.gz") + "/"
        for member in archive.getmembers():
            check_member(member.name)
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError(
                    f"Distribution contains a link or special file: {member.name}"
                )
            if not member.name.startswith(prefix):
                raise ValueError(f"Invalid source distribution root: {member.name}")
            names.append(member.name.removeprefix(prefix))
        check_paths(
            names, allowed | set(SOURCE_FILES) | {"PKG-INFO", "pyproject.toml.orig"}
        )


def run(*args, cwd, env):
    subprocess.run(args, cwd=cwd, env=env, check=True)


def bin_dir(directory):
    return directory / ("Scripts" if os.name == "nt" else "bin")


def python_path(directory):
    return bin_dir(directory) / ("python.exe" if os.name == "nt" else "python")


def smoke(commands, cwd, env):
    for command in commands:
        run(str(command), "--help", cwd=cwd, env=env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path)
    parser.add_argument("--contents-only", action="store_true")
    args = parser.parse_args()
    wheels = list(args.dist.resolve().glob("*.whl"))
    sdists = list(args.dist.resolve().glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        parser.error("expected exactly one wheel and one sdist")
    check_contents(wheels[0], sdists[0])
    if args.contents_only:
        return

    with tempfile.TemporaryDirectory(prefix="cashu-package-") as directory:
        root = Path(directory)
        home = root / "home"
        home.mkdir()
        env = {
            key: value
            for key, value in os.environ.items()
            if key not in {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"}
        }
        env.update(
            HOME=str(home),
            USERPROFILE=str(home),
            CASHU_DIR=str(home / ".cashu"),
            MINT_BACKEND_BOLT11_SAT="FakeWallet",
            TOR="FALSE",
        )
        suffix = ".exe" if os.name == "nt" else ""
        for artifact in [*wheels, *sdists]:
            target = root / artifact.suffix.removeprefix(".")
            venv.create(target, with_pip=True)
            python = str(python_path(target))
            run(python, "-m", "pip", "install", str(artifact), cwd=root, env=env)
            run(python, "-m", "pip", "check", cwd=root, env=env)
            smoke(
                [
                    bin_dir(target) / (name + suffix)
                    for name in ("cashu", "mint", "mint-cli")
                ],
                root,
                env,
            )
            run(
                python,
                "-c",
                "import cashu.mint.ledger; "
                "import cashu.mint.management_rpc.protos.management_pb2_grpc",
                cwd=root,
                env=env,
            )

        tools = root / "tools"
        venv.create(tools, with_pip=True)
        python = str(python_path(tools))
        run(python, "-m", "pip", "install", "pipx", cwd=root, env=env)
        env.update(
            PIPX_HOME=str(root / "pipx"),
            PIPX_BIN_DIR=str(root / "apps"),
            PIPX_MAN_DIR=str(root / "man"),
        )
        run(
            python,
            "-m",
            "pipx",
            "install",
            "--python",
            sys.executable,
            str(wheels[0]),
            cwd=root,
            env=env,
        )
        smoke(
            [root / "apps" / (name + suffix) for name in ("cashu", "mint", "mint-cli")],
            root,
            env,
        )


if __name__ == "__main__":
    main()
