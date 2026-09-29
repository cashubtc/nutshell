"""Runner regressions live outside the suite that mutmut executes recursively."""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load_script("run_mutation")
merger = load_script("merge_mutation_reports")


@pytest.mark.parametrize(
    "profile,shards",
    [("mint", 4), ("wallet", 4), ("core", 2), ("lightning", 2), ("tor", 1)],
)
def test_shards_partition_entire_profile(profile, shards, monkeypatch):
    monkeypatch.chdir(SCRIPTS.parent)
    groups = [
        set(runner.profile_paths(profile, index, shards)) for index in range(shards)
    ]
    expected = set(map(str, Path("cashu", profile).rglob("*.py")))
    assert set.union(*groups) == expected
    assert sum(map(len, groups)) == len(expected)
    assert all(groups)


def test_profile_cache_invalidates_dependency_changes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("cashu/wallet").mkdir(parents=True)
    dependency = Path("cashu/wallet/helper.py")
    dependency.write_text("value = 1\n")
    Path("pyproject.toml").write_text("")
    Path("poetry.lock").write_text("")
    runner.prepare_profile_cache(["cashu/mint/ledger.py"])
    verdict = Path("mutants/verdict")
    verdict.write_text("cached")
    runner.prepare_profile_cache(["cashu/mint/ledger.py"])
    assert verdict.exists()
    dependency.write_text("value = 2\n")
    runner.prepare_profile_cache(["cashu/mint/ledger.py"])
    assert not verdict.exists()


def test_profile_resumes_only_unchecked_mutants(tmp_path):
    """Use real mutmut to catch explicit-target cache bypasses and scope leaks."""
    for directory in ("cashu", "cashu/core", "cashu/wallet", "tests"):
        (tmp_path / directory).mkdir(exist_ok=True)
        (tmp_path / directory / "__init__.py").touch()
    (tmp_path / "cashu/core/example.py").write_text(
        "def increment(value):\n    return value + 1\n"
    )
    (tmp_path / "cashu/wallet/example.py").write_text(
        "def decrement(value):\n    return value - 1\n"
    )
    execution_log = tmp_path / "executed.jsonl"
    unrelated_log = tmp_path / "unrelated.jsonl"
    (tmp_path / "tests/test_example.py").write_text(
        "import os\nfrom pathlib import Path\n"
        "from cashu.core.example import increment\n"
        "def test_increment():\n"
        "    mutant = os.getenv('MUTANT_UNDER_TEST', '')\n"
        "    if '__mutmut_' in mutant:\n"
        f"        with Path({str(execution_log)!r}).open('a') as stream:\n"
        "            stream.write(mutant + '\\n')\n"
        "    assert increment(4) == 5\n"
        "def test_other_subsystem():\n"
        "    from cashu.wallet.example import decrement\n"
        f"    with Path({str(unrelated_log)!r}).open('a') as stream:\n"
        "        stream.write(os.getenv('MUTANT_UNDER_TEST', '') + '\\n')\n"
        "    assert decrement(4) == 3\n"
    )
    (tmp_path / "pyproject.toml").write_text(
        '[tool.mutmut]\nsource_paths = ["cashu/"]\n'
        'pytest_add_cli_args_test_selection = ["tests/"]\n'
        'pytest_add_cli_args = ["-o", "addopts=", "-q"]\n'
        'process_isolation = "forkserver"\nforkserver_warmup = "none"\n'
    )
    (tmp_path / "poetry.lock").touch()
    command = [sys.executable, str(SCRIPTS / "run_mutation.py"), "--profile", "core"]
    env = {**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
    for key in ("MUTANT_UNDER_TEST", "PYTEST_PLUGINS", "NUTSHELL_MUTATION_PATHS"):
        env.pop(key, None)

    def run():
        result = subprocess.run(
            command,
            cwd=tmp_path,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=90,
        )
        assert result.returncode == 0, result.stdout

    run()
    metadata = tmp_path / "mutants/cashu/core/example.py.meta"
    data = json.loads(metadata.read_text())
    verdicts = data["exit_code_by_key"]
    assert len(verdicts) > 1
    assert all(code is not None for code in verdicts.values())
    assert not (tmp_path / "mutants/cashu/wallet/example.py.meta").exists()
    pending = next(iter(verdicts))
    verdicts[pending] = None
    metadata.write_text(json.dumps(data))
    execution_log.write_text("")
    run()
    assert execution_log.read_text().splitlines() == [pending]
    # Discovery remains comprehensive; clean baselines only repeat relevant tests.
    assert unrelated_log.read_text().splitlines() == ["stats"]
    assert json.loads(metadata.read_text())["exit_code_by_key"] == {
        **verdicts,
        pending: 1,
    }
    # Switching from a profile to an explicit rerun must discover coverage for
    # the previously uninstrumented subsystem, rather than label it untested.
    command[-2:] = ["cashu.wallet*"]
    run()
    wallet_metadata = tmp_path / "mutants/cashu/wallet/example.py.meta"
    assert set(
        json.loads(wallet_metadata.read_text())["exit_code_by_key"].values()
    ) == {1}


@pytest.mark.parametrize(
    "state", ["complete", "partial", "interrupted", "missing", "unchecked"]
)
def test_merge_preserves_partial_results(tmp_path, monkeypatch, state):
    monkeypatch.chdir(tmp_path)
    excluded = [{"nodeid": "tests/test_example.py::test_example"}]
    for shard in range(2):
        if shard == 1 and state == "missing":
            continue
        status = state if shard == 1 and state != "unchecked" else "complete"
        Path(f"mutation-mint-{shard}-baseline.json").write_text(
            json.dumps(
                {
                    "status": status,
                    "excluded_tests": excluded if status == "partial" else [],
                    "attempts": [],
                }
            )
        )
        Path(f"mutation-mint-{shard}-results.txt").write_text(
            f"    cashu.mint.example{shard}: "
            + ("not checked" if shard == 1 and state == "unchecked" else "killed")
            + "\n"
        )
    result = merger.merge("mint", 2, tmp_path)
    report = json.loads(Path("mutation-mint-baseline.json").read_text())
    assert result == (1 if state in ("interrupted", "missing", "unchecked") else 0)
    assert report["status"] == ("incomplete" if result else state)
    assert report["missing_shards"] == ([1] if state == "missing" else [])
    assert report["excluded_tests"] == (excluded if state == "partial" else [])
    assert (
        "cashu.mint.example0: killed" in Path("mutation-mint-results.txt").read_text()
    )


@pytest.mark.skipif(shutil.which("jq") is None, reason="Weekly report requires jq")
def test_weekly_report_includes_failed_profile_counts(tmp_path):
    # Intercept every gh call, including issue creation: no network or posting.
    gh = tmp_path / "gh"
    gh.write_text(
        f"#!{sys.executable}\n"
        "import datetime, json, os, shutil, sys\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "if args[:2] == ['run', 'list']:\n"
        "    print(json.dumps({'databaseId': 123, 'conclusion': 'failure',\n"
        "        'createdAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),\n"
        "        'url': 'https://example.invalid/run/123'}))\n"
        "elif args[:2] == ['run', 'download']:\n"
        "    directory = Path(args[args.index('--dir') + 1])\n"
        "    profile = args[args.index('--name') + 1].split('-')[1]\n"
        "    prefix = directory / f'mutation-{profile}'\n"
        "    Path(f'{prefix}-results.txt').write_text(\n"
        "        '    example.first: killed\\n    example.second: not checked\\n')\n"
        "    Path(f'{prefix}-baseline.json').write_text(\n"
        "        json.dumps({'status': 'incomplete', 'excluded_tests': []}))\n"
        "elif args[:2] == ['issue', 'create']:\n"
        "    shutil.copyfile(args[args.index('--body-file') + 1], os.environ['BODY_COPY'])\n"
    )
    gh.chmod(0o755)
    body = tmp_path / "body.md"
    result = subprocess.run(
        ["bash", str(SCRIPTS / "mutation_weekly_report.sh")],
        env={
            **os.environ,
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "REPOSITORY": "example/fixture",
            "BODY_COPY": str(body),
        },
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    report = body.read_text()
    assert "unavailable |" not in report
    assert report.count("| 1 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |") == 5
    assert "5 profile report(s)" in report
