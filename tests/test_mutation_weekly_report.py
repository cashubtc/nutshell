"""Check weekly-report rendering without contacting GitHub."""

import os
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import pytest

REPORT_SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts/mutation_weekly_report.sh"
)
pytestmark = pytest.mark.skipif(
    os.environ.get("MUTATION_TESTING") == "true",
    reason="Test mutation tooling outside its own mutation runs",
)


@pytest.fixture(scope="session", autouse=True)
def mint():
    """These tooling tests do not need a mint server."""


@pytest.fixture
def report_output(tmp_path, monkeypatch):
    # Intercept every GitHub operation, including issue creation.
    gh = tmp_path / "gh"
    gh.write_text(
        f"#!{sys.executable}\n"
        + dedent(r"""
        import datetime
        import json
        import os
        import shutil
        import sys
        from pathlib import Path

        args = sys.argv[1:]
        command = args[:2]

        if command == ["run", "list"]:
            print(json.dumps({
                "databaseId": 1,
                "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "url": "https://example.com/run",
                "conclusion": "success",
            }))
        elif command == ["run", "download"]:
            profile = args[args.index("--name") + 1].split("-")[1]
            dest = Path(args[args.index("--dir") + 1])
            (dest / f"mutation-{profile}-results.txt").write_text("    sample: killed\n")
            excluded = [{"nodeid": "test_broken"}] if profile == "core" else []
            (dest / f"mutation-{profile}-baseline.json").write_text(
                json.dumps({"excluded_tests": excluded})
            )
        elif command == ["issue", "create"]:
            shutil.copyfile(
                args[args.index("--body-file") + 1], os.environ["REPORT_COPY"]
            )
        elif command != ["label", "create"]:
            sys.exit(f"Unexpected gh invocation: {args!r}")
        """).lstrip()
    )
    gh.chmod(0o755)
    body = tmp_path / "report.md"
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("REPOSITORY", "test/repo")
    monkeypatch.setenv("REPORT_COPY", str(body))
    return body


def test_weekly_report_includes_exclusions_without_survivors(report_output):
    result = subprocess.run(
        ["bash", str(REPORT_SCRIPT)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    text = report_output.read_text()
    assert "Excluded tests" in text
    assert "| [core](https://example.com/run) | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |" in text
    assert "1 profile report(s) were missing, stale, or had excluded" in text
