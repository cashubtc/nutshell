"""Run mutmut with bounded retries excluding tests that fail without mutations."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def reset_changed_selection(excluded):
    """Never reuse coverage or mutation results from a different test selection."""
    cache = Path("mutants")
    selection_file = cache / ".nutshell-excluded-tests.json"
    previous = json.loads(selection_file.read_text()) if selection_file.exists() else []
    if previous != sorted(excluded):
        for metadata in cache.rglob("*.py.meta"):
            # Mutmut also uses the generated source's mtime as a cache key.
            metadata.with_suffix("").unlink(missing_ok=True)
            metadata.unlink()
        (cache / "mutmut-stats.json").unlink(missing_ok=True)
    cache.mkdir(exist_ok=True)
    selection_file.write_text(json.dumps(sorted(excluded)) + "\n")


def run(args):
    excluded = {}
    report = {"status": "running", "excluded_tests": [], "attempts": []}
    report_path = args.report.resolve()

    def save_report():
        report["excluded_tests"] = list(excluded.values())
        report_path.write_text(json.dumps(report, indent=2) + "\n")

    save_report()
    with tempfile.TemporaryDirectory(prefix="nutshell-mutation-") as temp_dir:
        baseline_path = Path(temp_dir) / "baseline.json"
        exclusions_path = Path(temp_dir) / "excluded.json"
        env = os.environ.copy()
        env["NUTSHELL_MUTATION_BASELINE_REPORT"] = str(baseline_path)
        env["NUTSHELL_MUTATION_EXCLUSIONS"] = str(exclusions_path)
        env["PYTHONPATH"] = os.pathsep.join(
            filter(
                None,
                (
                    str(Path(__file__).resolve().parent),
                    env.get("PYTHONPATH"),
                ),
            )
        )
        env["PYTEST_PLUGINS"] = ",".join(
            filter(
                None,
                (
                    env.get("PYTEST_PLUGINS"),
                    "mutation_baseline",
                ),
            )
        )
        command = [
            sys.executable,
            "-c",
            "from mutmut.__main__ import cli; cli()",
            "run",
            *args.targets,
        ]
        if args.max_children is not None:
            command += ["--max-children", str(args.max_children)]

        try:
            for attempt in range(args.baseline_retries + 1):
                reset_changed_selection(excluded)
                exclusions_path.write_text(json.dumps(sorted(excluded)))
                baseline_path.unlink(missing_ok=True)
                print(
                    f"Mutation attempt {attempt + 1}; excluding {len(excluded)} baseline failures",
                    flush=True,
                )
                result = subprocess.run(command, env=env)
                baseline = (
                    json.loads(baseline_path.read_text())
                    if baseline_path.exists()
                    else None
                )
                report["attempts"].append(
                    {
                        "exit_code": result.returncode,
                        "baseline": baseline,
                    }
                )
                if result.returncode == 0:
                    report["status"] = "partial" if excluded else "complete"
                    if excluded:
                        print(
                            f"WARNING: Partial mutation coverage: {len(excluded)} baseline tests excluded. See {report_path}.",
                            flush=True,
                        )
                    return 0

                # Interruptions, collection/fixture errors, no tests, and errors
                # after the baseline must remain failures, not exclusions.
                if (
                    result.returncode != 1
                    or not baseline
                    or baseline["exit_code"] != 1
                    or baseline["infrastructure_error"]
                    or not baseline["passed"]
                    or not baseline["failures"]
                    or attempt == args.baseline_retries
                ):
                    report["status"] = "failed"
                    return (
                        result.returncode
                        if result.returncode > 0
                        else 128 - result.returncode
                    )

                new_failures = {
                    failure["nodeid"]: failure
                    for failure in baseline["failures"]
                    if failure["nodeid"] not in excluded
                }
                if not new_failures:
                    report["status"] = "failed"
                    return 1
                for nodeid in new_failures:
                    print(
                        f"Excluding baseline failure for this run: {nodeid}", flush=True
                    )
                excluded.update(new_failures)
                save_report()
        except KeyboardInterrupt:
            report["status"] = "interrupted"
            return 130
        finally:
            save_report()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="*")
    parser.add_argument("--report", type=Path, default=Path("mutation-baseline.json"))
    parser.add_argument("--baseline-retries", type=int, default=3)
    parser.add_argument("--max-children", type=int)
    args = parser.parse_args()
    if args.baseline_retries < 0:
        parser.error("--baseline-retries must be nonnegative")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
