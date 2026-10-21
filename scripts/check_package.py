"""Check published artifacts with fresh dependency resolution, outside the checkout."""

import argparse
import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path


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
    args = parser.parse_args()
    wheels = list(args.dist.resolve().glob("*.whl"))
    sdists = list(args.dist.resolve().glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        parser.error("expected exactly one wheel and one sdist")

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
