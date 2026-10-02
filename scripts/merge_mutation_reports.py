"""Combine shard artifacts without hiding incomplete mutation coverage."""

import argparse
import json
from pathlib import Path


def merge(profile, shards, directory):
    results = {}
    excluded = {}
    reports = []
    missing = []
    for shard in range(shards):
        prefix = directory / f"mutation-{profile}-{shard}"
        baseline = Path(f"{prefix}-baseline.json")
        verdicts = Path(f"{prefix}-results.txt")
        if not baseline.exists() or not verdicts.exists():
            missing.append(shard)
            continue
        report = json.loads(baseline.read_text())
        reports.append({"shard": shard, **report})
        for failure in report["excluded_tests"]:
            excluded[failure["nodeid"]] = failure
        for line in verdicts.read_text().splitlines():
            name, status = line.strip().rsplit(": ", 1)
            if name in results:
                raise ValueError(f"Mutant occurs in multiple shards: {name}")
            results[name] = status

    incomplete = (
        bool(missing)
        or not results
        or "not checked" in results.values()
        or any(r["status"] not in ("complete", "partial") for r in reports)
    )
    report = {
        "status": "incomplete" if incomplete else "partial" if excluded else "complete",
        "excluded_tests": list(excluded.values()),
        "missing_shards": missing,
        "shards": reports,
    }
    Path(f"mutation-{profile}-baseline.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    Path(f"mutation-{profile}-results.txt").write_text(
        "".join(f"    {name}: {status}\n" for name, status in sorted(results.items()))
    )
    return 1 if incomplete else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile")
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    if args.shards < 1:
        parser.error("--shards must be positive")
    raise SystemExit(merge(args.profile, args.shards, args.directory))
