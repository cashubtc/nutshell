"""Pool repeated CDK trials by mint revision, workload and wallet concurrency."""

import argparse
import csv
import gzip
import json
import math
import sys
from collections import defaultdict
from pathlib import Path


def percentile(values, fraction):
    if not values:
        return ""
    return round(sorted(values)[math.ceil(len(values) * fraction) - 1] / 1000, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trials", type=Path, nargs="+")
    args = parser.parse_args()
    cells = defaultdict(list)
    for path in args.trials:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt") as data:
            header, *measurements, audit = map(json.loads, data)
        if "pending_proofs" not in audit:
            raise ValueError(f"Incomplete trial in {path}")
        for cell in measurements:
            key = (
                header["commit"],
                header["workers"],
                cell["wallets"],
                cell["workload"],
            )
            cells[key].append(cell)

    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(
        [
            "commit",
            "workers",
            "wallets",
            "workload",
            "runs",
            "attempts",
            "ok",
            "errors",
            "successful_ops_s",
            "min_run_ops_s",
            "max_run_ops_s",
            "success_p50_ms",
            "success_p95_ms",
            "all_p95_ms",
            "mint_cpu_ms_per_attempt",
            "execution_http_errors",
            "setup_retries",
        ]
    )
    for key, trials in sorted(cells.items()):
        samples = [s for trial in trials for s in trial["samples"]]
        successes = [s["us"] for s in samples if s["error"] is None]
        elapsed = sum(t["elapsed_s"] for t in trials)
        rates = [
            sum(s["error"] is None for s in t["samples"]) / t["elapsed_s"]
            for t in trials
        ]
        http_errors = sum(
            n
            for t in trials
            for route, n in t["http_status"].items()
            if int(route.rsplit(" ", 1)[1]) >= 400
        )
        writer.writerow(
            [
                *key,
                len(trials),
                len(samples),
                len(successes),
                len(samples) - len(successes),
                round(len(successes) / elapsed, 2),
                round(min(rates), 2),
                round(max(rates), 2),
                percentile(successes, 0.50),
                percentile(successes, 0.95),
                percentile([s["us"] for s in samples], 0.95),
                round(sum(t["mint_cpu_s"] for t in trials) * 1000 / len(samples), 1),
                http_errors,
                sum(len(t["setup_errors"]) for t in trials),
            ]
        )


if __name__ == "__main__":
    main()
