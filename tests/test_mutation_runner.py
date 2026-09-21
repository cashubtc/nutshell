import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
pytestmark = pytest.mark.skipif(
    os.environ.get("MUTATION_TESTING") == "true",
    reason="Test the mutation harness outside its own mutation runs",
)


@pytest.fixture(scope="session", autouse=True)
def mint():
    """These tooling tests do not need a mint server."""


@pytest.fixture
def sample_project(tmp_path):
    (tmp_path / "sample").mkdir()
    (tmp_path / "sample/__init__.py").write_text("")
    (tmp_path / "sample/logic.py").write_text(
        "def increment(value):\n    return value + 1\n"
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "pyproject.toml").write_text(
        '[tool.mutmut]\nsource_paths = ["sample/"]\n'
        'pytest_add_cli_args_test_selection = ["tests/"]\n'
        'pytest_add_cli_args = ["-q"]\n'
    )
    return tmp_path


def run_sample(project, *args, workers=1):
    env = os.environ.copy()
    for key in (
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
        "MUTANT_UNDER_TEST",
        "NUTSHELL_MUTATION_BASELINE_REPORT",
        "NUTSHELL_MUTATION_EXCLUSIONS",
    ):
        env.pop(key, None)
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "run_mutation.py"),
            "sample*",
            "--max-children",
            str(workers),
            *args,
        ],
        cwd=project,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    report = json.loads((project / "mutation-baseline.json").read_text())
    return result, report


@pytest.mark.parametrize("workers", [1, 2])
def test_baseline_exclusion_preserves_mutation_results_and_retries_fixed_tests(
    sample_project, workers
):
    test_file = sample_project / "tests/test_sample.py"
    test_file.write_text(
        "from sample.logic import increment\n\n"
        "def test_healthy():\n    assert increment(1) > 0\n\n"
        "def test_broken():\n    assert increment(1) == 999\n"
    )
    result, report = run_sample(sample_project, workers=workers)
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["status"] == "partial"
    assert [test["nodeid"] for test in report["excluded_tests"]] == [
        "tests/test_sample.py::test_broken"
    ]
    assert report["attempts"][-1]["baseline"]["exit_code"] == 0
    metadata_path = sample_project / "mutants/sample/logic.py.meta"
    results = json.loads(metadata_path.read_text())["exit_code_by_key"]
    # A baseline failure must never make surviving mutants appear killed.
    assert set(results.values()) == {0, 1}

    test_file.write_text(test_file.read_text().replace("== 999", "== 2"))
    result, report = run_sample(sample_project, workers=workers)
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["status"] == "complete"
    assert report["excluded_tests"] == []
    assert report["attempts"][-1]["baseline"]["passed"] == 2
    # Restoring the stronger test invalidates the partial run's results.
    results = json.loads(metadata_path.read_text())["exit_code_by_key"]
    assert set(results.values()) == {1}


def test_clean_pass_failure_is_excluded(sample_project):
    (sample_project / "tests/test_sample.py").write_text(
        "import os\nfrom sample.logic import increment\n\n"
        "def test_healthy():\n    assert increment(1) > 0\n\n"
        "def test_clean_only_failure():\n"
        "    assert increment(1) == 2\n"
        "    assert os.environ['MUTANT_UNDER_TEST'] != ''\n"
    )
    result, report = run_sample(sample_project)
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["status"] == "partial"
    assert report["attempts"][0]["baseline"]["phase"] == "clean"
    assert len(report["excluded_tests"]) == 1


def test_repeated_baseline_failures_exhaust_retry_limit(sample_project):
    (sample_project / "tests/test_sample.py").write_text(
        "import json, os, pytest\nfrom pathlib import Path\n"
        "from sample.logic import increment\n\n"
        "excluded = json.loads(Path(os.environ['NUTSHELL_MUTATION_EXCLUSIONS']).read_text())\n\n"
        "def test_healthy():\n    assert increment(1) > 0\n\n"
        "@pytest.mark.parametrize('index', range(3))\n"
        "def test_staged_failure(index):\n"
        "    assert increment(1) == 2\n"
        "    assert index != len(excluded)\n"
    )
    result, report = run_sample(sample_project, "--baseline-retries", "1")
    assert result.returncode == 1, result.stdout + result.stderr
    assert report["status"] == "failed"
    assert len(report["attempts"]) == 2
    assert [test["nodeid"] for test in report["excluded_tests"]] == [
        "tests/test_sample.py::test_staged_failure[0]"
    ]
    assert report["attempts"][-1]["baseline"]["failures"][0]["nodeid"] == (
        "tests/test_sample.py::test_staged_failure[1]"
    )


@pytest.mark.parametrize(
    "scenario",
    ["fixture", "collection", "all_fail", "strict", "no_tests", "no_coverage"],
)
def test_unusable_baselines_still_fail(sample_project, scenario):
    source = (
        "import pytest\nfrom sample.logic import increment\n\n"
        "def test_healthy():\n    assert increment(1) > 0\n\n"
    )
    if scenario == "fixture":
        source += (
            "@pytest.fixture\ndef broken():\n    raise RuntimeError('fixture failed')\n\n"
            "def test_broken(broken):\n    pass\n"
        )
    elif scenario == "collection":
        source += "raise RuntimeError('collection failed')\n"
    elif scenario == "all_fail":
        source = source.replace("increment(1) > 0", "increment(1) == 999")
    elif scenario == "no_tests":
        source = "from sample.logic import increment\n"
    elif scenario == "no_coverage":
        source = "def test_unrelated():\n    assert True\n"
    else:
        source += "def test_broken():\n    assert increment(1) == 999\n"
    (sample_project / "tests/test_sample.py").write_text(source)
    args = ("--baseline-retries", "0") if scenario == "strict" else ()
    result, report = run_sample(sample_project, *args)
    assert result.returncode != 0
    assert report["status"] == "failed"
    assert report["excluded_tests"] == []
    assert len(report["attempts"]) == 1


def test_failure_after_baseline_is_not_excluded(sample_project):
    (sample_project / "tests/test_sample.py").write_text(
        "import os\nfrom sample.logic import increment\n\n"
        "def test_healthy():\n"
        "    if os.environ.get('MUTANT_UNDER_TEST') == 'fail':\n"
        "        os.environ['MUTANT_UNDER_TEST'] = ''\n"
        "    assert increment(1) == 2\n"
    )
    result, report = run_sample(sample_project)
    assert result.returncode != 0
    assert "Unable to force test failures" in result.stdout
    assert report["status"] == "failed"
    assert report["excluded_tests"] == []
    assert report["attempts"][-1]["baseline"]["exit_code"] == 0


def test_weekly_report_includes_exclusions_without_survivors(tmp_path, monkeypatch):
    # Stub every GitHub operation: this test only writes local files.
    gh = tmp_path / "gh"
    gh.write_text(
        f"#!{sys.executable}\n"
        "import datetime, json, os, pathlib, shutil, sys\n"
        "args = sys.argv[1:]\n"
        "if args[:2] == ['run', 'list']:\n"
        "    print(json.dumps({'databaseId': 1, 'createdAt': "
        "datetime.datetime.now(datetime.timezone.utc).isoformat(), "
        "'url': 'https://example.com/run', 'conclusion': 'success'}))\n"
        "elif args[:2] == ['run', 'download']:\n"
        "    profile = args[args.index('--name') + 1].split('-')[1]\n"
        "    dest = pathlib.Path(args[args.index('--dir') + 1])\n"
        "    (dest / f'mutation-{profile}-results.txt').write_text('    sample: killed\\n')\n"
        "    excluded = [{'nodeid': 'test_broken'}] if profile == 'core' else []\n"
        "    (dest / f'mutation-{profile}-baseline.json').write_text("
        "json.dumps({'excluded_tests': excluded}))\n"
        "elif args[:2] == ['issue', 'create']:\n"
        "    shutil.copyfile(args[args.index('--body-file') + 1], os.environ['REPORT_COPY'])\n"
        "elif args[:2] != ['label', 'create']:\n"
        "    sys.exit('Unexpected gh invocation')\n"
    )
    gh.chmod(0o755)
    body = tmp_path / "report.md"
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("REPOSITORY", "test/repo")
    monkeypatch.setenv("REPORT_COPY", str(body))
    result = subprocess.run(
        ["bash", str(SCRIPTS / "mutation_weekly_report.sh")],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    text = body.read_text()
    assert "Excluded tests" in text
    assert "| [core](https://example.com/run) | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |" in text
    assert "1 profile report(s) were missing, stale, or had excluded" in text
