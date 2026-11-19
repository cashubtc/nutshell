"""Run one revision of the local CDK wallet benchmark on Linux."""

import argparse
import itertools
import json
import math
import os
import re
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from urllib.request import urlopen


def output(*args):
    return subprocess.check_output(args, text=True).strip()


def physical_cores():
    topology = Path("/sys/devices/system/cpu")
    return len(
        {
            (
                path.joinpath("physical_package_id").read_text(),
                path.joinpath("core_id").read_text(),
            )
            for cpu in os.sched_getaffinity(0)
            for path in [topology / f"cpu{cpu}/topology"]
        }
    )


@contextmanager
def postgres():
    container = output(
        "docker",
        "run",
        "--rm",
        "-d",
        "-p",
        "127.0.0.1::5432",
        "-e",
        "POSTGRES_PASSWORD=bench",
        "-e",
        "POSTGRES_DB=bench",
        "postgres:16-alpine",
        "-c",
        "max_connections=256",
    )
    try:
        port = output("docker", "port", container, "5432/tcp").split(":")[-1]
        for _ in range(120):
            ready = subprocess.run(
                ["docker", "exec", container, "pg_isready", "-q", "-h", "127.0.0.1"],
            )
            if ready.returncode == 0:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("PostgreSQL startup timed out")
        yield container, f"postgres://postgres:bench@127.0.0.1:{port}/bench"
    finally:
        subprocess.run(
            ["docker", "stop", container], stdout=subprocess.DEVNULL, check=True
        )


def pg(container, sql):
    return output(
        "docker",
        "exec",
        container,
        "psql",
        "-XAt",
        "-U",
        "postgres",
        "-d",
        "bench",
        "-c",
        sql,
    )


def worker_cpu(supervisor, expected):
    pids = Path(f"/proc/{supervisor}/task/{supervisor}/children").read_text().split()
    ticks = {}
    for pid in pids:
        if b"spawn_main" in Path(f"/proc/{pid}/cmdline").read_bytes():
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            ticks[pid] = int(fields[11]) + int(fields[12])
    if len(ticks) != expected:
        raise RuntimeError(f"expected {expected} Uvicorn workers, saw {len(ticks)}")
    return ticks


@contextmanager
def mint(args, directory, db_url):
    # An empty, private working directory isolates all local mint state.
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(2048)
        port = sock.getsockname()[1]
        url = f"http://127.0.0.1:{port}"
        env = dict(
            os.environ,
            PYTHONPATH=str(args.source),
            CASHU_DIR=str(directory),
            MINT_PRIVATE_KEY="cdk-local-benchmark",
            MINT_DATABASE=db_url,
            MINT_AUTH_DATABASE=str(directory / "auth"),
            MINT_LISTEN_HOST="127.0.0.1",
            MINT_LISTEN_PORT=str(port),
            MINT_URL=url,
            MINT_BACKEND_BOLT11_SAT="FakeWallet",
            MINT_RATE_LIMIT="false",
            FAKEWALLET_BRR="true",
            MINT_INPUT_FEE_PPK="0",
            FAKEWALLET_DELAY_INCOMING_PAYMENT="0",
            FAKEWALLET_DELAY_OUTGOING_PAYMENT="0",
            MINT_RPC_SERVER_ENABLE="false",
            TOR="false",
            LOG_LEVEL="INFO",
            DEBUG="false",
        )
        if (Path.home() / ".cashu/.env").exists():
            # Nutshell loads this file with override=True if the current directory has no .env.
            (directory / ".env").touch()
        with args.log.open("w") as log:
            bootstrap = (
                "import asyncio\nfrom cashu.mint.startup import start_mint, shutdown_mint\n"
                "async def bootstrap():\n await start_mint()\n await shutdown_mint()\n"
                "asyncio.run(bootstrap())"
            )
            subprocess.run(
                [sys.executable, "-c", bootstrap],
                env=env,
                cwd=directory,
                stdout=log,
                stderr=log,
                timeout=90,
                check=True,
            )
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "cashu.mint.app:app",
                    "--fd",
                    str(sock.fileno()),
                    "--workers",
                    str(args.workers),
                    "--no-access-log",
                    "--timeout-graceful-shutdown",
                    "10",
                ],
                pass_fds=(sock.fileno(),),
                env=env,
                cwd=directory,
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
            try:
                for _ in range(360):
                    if proc.poll() is not None:
                        raise RuntimeError(f"Uvicorn exited, see {args.log}")
                    if (
                        args.log.read_text().count("Application startup complete.")
                        >= args.workers
                    ):
                        break
                    time.sleep(0.25)
                else:
                    raise RuntimeError(f"Uvicorn startup timed out, see {args.log}")
                worker_cpu(proc.pid, args.workers)
                with urlopen(f"{url}/v1/info", timeout=5) as response:
                    assert json.load(response)["version"].startswith("Nutshell/")
                yield proc.pid, port, env
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()


def read_marker(proc, expected, timeout):
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdout, selectors.EVENT_READ)
        if not selector.select(timeout) or proc.stdout.readline().strip() != expected:
            raise RuntimeError(f"wallet driver did not reach {expected}")


def measure(args, directory, pid, port, env, clients, kind):
    iterations = max(args.min_iterations, math.ceil(args.attempts / clients))
    invoices = directory / "invoices"
    with invoices.open("w") as f:
        if kind == "melt":
            count = clients * (
                iterations + 3
            )  # Includes a fresh warmup invoice per setup try.
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from tests.helpers import get_fake_invoice\n"
                    f"for _ in range({count}): print(get_fake_invoice(16))",
                ],
                cwd=directory,
                env=env,
                stdout=f,
                check=True,
            )
    with subprocess.Popen(
        [args.driver, str(port), kind, str(clients), str(iterations), invoices],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    ) as proc:
        try:
            read_marker(proc, "READY", max(300, clients * 30))
            offset = args.log.stat().st_size
            before = worker_cpu(pid, args.workers)
            proc.stdin.write("GO\n")
            proc.stdin.flush()
            read_marker(proc, "DONE", iterations * 30 + 30)
            after = worker_cpu(pid, args.workers)
            end = args.log.stat().st_size
            if before.keys() != after.keys():
                raise RuntimeError("Uvicorn replaced a worker during a measurement")
            tail = proc.stdout.readline()
            proc.wait(timeout=60)
            if proc.returncode:
                raise RuntimeError(f"driver exited {proc.returncode}")
            result = json.loads(tail)
        finally:
            if proc.poll() is None:
                proc.kill()
    with args.log.open("rb") as log:
        log.seek(offset)
        access_log = log.read(end - offset).decode(errors="replace")
    result["http_status"] = dict(
        Counter(
            f"{path} {status}"
            for path, status in re.findall(
                r'"POST (/v1/(?:swap|mint/bolt11|melt/bolt11)) HTTP/1.1" (\d{3})',
                access_log,
            )
        )
    )
    assert len(result["samples"]) == clients * iterations
    result.update(
        workload=kind,
        wallets=clients,
        mint_cpu_s=sum(after[k] - before[k] for k in before) / os.sysconf("SC_CLK_TCK"),
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", type=Path, required=True, help="Nutshell worktree to serve"
    )
    parser.add_argument(
        "--driver", type=Path, required=True, help="optimized stress example executable"
    )
    parser.add_argument("--output", type=Path, required=True, help="new JSONL file")
    parser.add_argument("--workers", type=int, default=physical_cores())
    parser.add_argument("--wallets", type=int, nargs="+", default=[1, 8, 32, 64])
    parser.add_argument(
        "--attempts",
        type=int,
        default=32,
        help="per cell, rounded up to a multiple of wallets",
    )
    parser.add_argument(
        "--min-iterations",
        type=int,
        default=8,
        help="minimum measured operations per wallet",
    )
    args = parser.parse_args()
    if min(args.wallets + [args.attempts, args.min_iterations]) < 1 or args.workers < 2:
        parser.error(
            "positive wallet and attempt counts and at least two workers are required"
        )
    args.source, args.driver = args.source.resolve(), args.driver.resolve()
    args.log = args.output.with_suffix(".server.log")
    commit = output("git", "-C", str(args.source), "rev-parse", "HEAD")
    with (
        args.output.open("x", buffering=1) as out,
        tempfile.TemporaryDirectory() as work,
        postgres() as (container, db_url),
    ):
        header = {
            "commit": commit,
            "workers": args.workers,
            "logical_cpus": len(os.sched_getaffinity(0)),
            "physical_cores": physical_cores(),
            "postgres": pg(container, "show server_version"),
            "image": output("docker", "inspect", "-f", "{{.Image}}", container),
        }
        print(json.dumps(header), file=out)
        with mint(args, Path(work), db_url) as (pid, port, env):
            for clients, kind in itertools.product(
                args.wallets, ["mint", "swap", "melt"]
            ):
                result = measure(args, Path(work), pid, port, env, clients, kind)
                print(json.dumps(result, separators=(",", ":")), file=out)
                passed = sum(s["error"] is None for s in result["samples"])
                print(
                    f"{commit[:8]} {clients:2} {kind:4}  {passed}/{len(result['samples'])}  "
                    f"{passed / result['elapsed_s']:.2f} successful/s",
                    flush=True,
                )
        print(
            json.dumps(
                {
                    "pending_proofs": int(
                        pg(container, "select count(*) from proofs_pending")
                    ),
                    "melt_states": pg(
                        container,
                        "select state,count(*) from melt_quotes group by state order by state",
                    ),
                }
            ),
            file=out,
        )


if __name__ == "__main__":
    main()
