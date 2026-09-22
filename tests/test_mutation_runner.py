"""Exercise baseline recovery against a small project using real mutmut runs."""

import json
import os
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

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
        dedent("""
        [tool.mutmut]
        source_paths = ["sample/"]
        pytest_add_cli_args_test_selection = ["tests/"]
        pytest_add_cli_args = ["-q"]
        """).lstrip()
    )
    return tmp_path


def write_tests(project, source):
    test_file = project / "tests/test_sample.py"
    test_file.write_text(dedent(source).lstrip())
    return test_file


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
    test_file = write_tests(
        sample_project,
        """
        from sample.logic import increment

        def test_healthy():
            assert increment(1) > 0

        def test_broken():
            assert increment(1) == 999
        """,
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
    write_tests(
        sample_project,
        """
        import os
        from sample.logic import increment

        def test_healthy():
            assert increment(1) > 0

        def test_clean_only_failure():
            assert increment(1) == 2
            assert os.environ["MUTANT_UNDER_TEST"] != ""
        """,
    )
    result, report = run_sample(sample_project)
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["status"] == "partial"
    assert report["attempts"][0]["baseline"]["phase"] == "clean"
    assert len(report["excluded_tests"]) == 1


def test_repeated_baseline_failures_exhaust_retry_limit(sample_project):
    write_tests(
        sample_project,
        """
        import json
        import os
        from pathlib import Path

        import pytest
        from sample.logic import increment

        excluded = json.loads(
            Path(os.environ["NUTSHELL_MUTATION_EXCLUSIONS"]).read_text()
        )

        def test_healthy():
            assert increment(1) > 0

        @pytest.mark.parametrize("index", range(3))
        def test_staged_failure(index):
            assert increment(1) == 2
            assert index != len(excluded)
        """,
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
    source = dedent("""
        import pytest
        from sample.logic import increment

        def test_healthy():
            assert increment(1) > 0

    """)
    if scenario == "fixture":
        source += dedent("""
            @pytest.fixture
            def broken():
                raise RuntimeError("fixture failed")

            def test_broken(broken):
                pass
        """)
    elif scenario == "collection":
        source += "raise RuntimeError('collection failed')\n"
    elif scenario == "all_fail":
        source = source.replace("increment(1) > 0", "increment(1) == 999")
    elif scenario == "no_tests":
        source = "from sample.logic import increment\n"
    elif scenario == "no_coverage":
        source = "def test_unrelated():\n    assert True\n"
    else:
        source += dedent("""
            def test_broken():
                assert increment(1) == 999
        """)
    write_tests(sample_project, source)
    args = ("--baseline-retries", "0") if scenario == "strict" else ()
    result, report = run_sample(sample_project, *args)
    assert result.returncode != 0
    assert report["status"] == "failed"
    assert report["excluded_tests"] == []
    assert len(report["attempts"]) == 1


def test_failure_after_baseline_is_not_excluded(sample_project):
    write_tests(
        sample_project,
        """
        import os
        from sample.logic import increment

        def test_healthy():
            if os.environ.get("MUTANT_UNDER_TEST") == "fail":
                os.environ["MUTANT_UNDER_TEST"] = ""
            assert increment(1) == 2
        """,
    )
    result, report = run_sample(sample_project)
    assert result.returncode != 0
    assert "Unable to force test failures" in result.stdout
    assert report["status"] == "failed"
    assert report["excluded_tests"] == []
    assert report["attempts"][-1]["baseline"]["exit_code"] == 0
