"""Run mutmut with bounded retries excluding tests that fail without mutations."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def profile_paths(profile, shard, shards):
    """Assign every source file to one stable shard, including future files."""
    return [
        str(path)
        for path in sorted(Path("cashu", profile).rglob("*.py"))
        if int(hashlib.sha256(str(path).encode()).hexdigest(), 16) % shards == shard
    ]


def configuration_fingerprint():
    """Resolve .env settings in a fresh process, keeping credentials out of output."""
    from cashu.core.settings import settings

    environment = {
        name: value
        for name, value in os.environ.items()
        if (
            name.startswith(("CASHU_", "PYTEST_")) and name != "PYTEST_CURRENT_TEST"
        )
        or name
        in ("GITHUB_ACTIONS", "MUTATION_TESTING", "PYTHONPATH", "PYTHONHASHSEED")
    }
    return hashlib.sha256(
        json.dumps(
            {"settings": settings.model_dump(mode="json"), "environment": environment},
            sort_keys=True,
        ).encode()
    ).hexdigest()


def prepare_profile_cache(paths, env=None):
    # Uninstrumented dependencies can change behavior too. Reuse verdicts only
    # for identical source, tests, runner, effective configuration, and selection.
    digest = hashlib.sha256(json.dumps(paths).encode())
    # Loading settings applies .env overrides and interpolation. Isolate those
    # side effects from the runner and fingerprint the environment tests receive.
    configuration = subprocess.check_output(
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "from run_mutation import configuration_fingerprint; "
            "print(configuration_fingerprint())",
            str(Path(__file__).resolve().parent),
        ],
        env=env,
        text=True,
    )
    digest.update(configuration.encode())
    inputs = [Path("pyproject.toml"), Path("poetry.lock")]
    for directory in ("cashu", "tests", "scripts"):
        inputs.extend(sorted(Path(directory).rglob("*.py")))
    for path in inputs:
        digest.update(str(path).encode())
        digest.update(path.read_bytes())
    cache = Path("mutants")
    identity = cache / ".nutshell-profile"
    fingerprint = digest.hexdigest()
    if cache.exists() and (
        not identity.exists() or identity.read_text() != fingerprint
    ):
        shutil.rmtree(cache)
    cache.mkdir(exist_ok=True)
    identity.write_text(fingerprint)


def mutmut_main():
    """Configure file selection without forcing cached mutant verdicts to rerun."""
    from mutmut.__main__ import cli
    from mutmut.configuration import config

    paths = os.environ.get("NUTSHELL_MUTATION_PATHS")
    if paths is not None:
        config().only_mutate = json.loads(paths)
    cli()


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
        paths = None
        if args.profile:
            paths = profile_paths(args.profile, args.shard, args.shards)
            if not paths:
                raise ValueError("Mutation shard contains no source files")
            env["NUTSHELL_MUTATION_PATHS"] = json.dumps(paths)
        else:
            env.pop("NUTSHELL_MUTATION_PATHS", None)
        # Switching back to a full or explicit-target run must also rebuild
        # coverage: a prior profile did not instrument the other subsystems.
        prepare_profile_cache(paths, env)
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
            "from run_mutation import mutmut_main; mutmut_main()",
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
    parser.add_argument(
        "--profile", choices=["core", "mint", "wallet", "lightning", "tor"]
    )
    parser.add_argument("--shard", type=int, default=0)
    parser.add_argument("--shards", type=int, default=1)
    parser.add_argument("--report", type=Path, default=Path("mutation-baseline.json"))
    parser.add_argument("--baseline-retries", type=int, default=3)
    # Tests share HTTP/RPC ports and data paths. Parallelism belongs in isolated
    # CI shards, not concurrent workers in the same test environment.
    parser.add_argument("--max-children", type=int, default=1)
    args = parser.parse_args()
    if args.baseline_retries < 0:
        parser.error("--baseline-retries must be nonnegative")
    if args.shards < 1 or not 0 <= args.shard < args.shards:
        parser.error("--shard must be between zero and --shards minus one")
    if args.profile and args.targets:
        parser.error("Use --profile for incremental runs or targets for forced reruns")
    if not args.profile and (args.shard != 0 or args.shards != 1):
        parser.error("Sharding requires --profile")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
