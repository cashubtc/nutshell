"""Record baseline failures and exclude quarantined tests for one mutation run."""

import json
import os
from pathlib import Path

import pytest


def pytest_configure(config):
    report_path = os.environ.get("NUTSHELL_MUTATION_BASELINE_REPORT")
    if report_path:
        config.pluginmanager.register(BaselineReport(Path(report_path)))
        if os.environ.get("MUTANT_UNDER_TEST") in ("", "stats"):
            # Collect all baseline failures; retain fail-fast for actual mutants.
            config.option.maxfail = 0


class BaselineReport:
    def __init__(self, report_path):
        self.report_path = report_path
        self.phase = os.environ.get("MUTANT_UNDER_TEST")
        self.excluded = set(
            json.loads(Path(os.environ["NUTSHELL_MUTATION_EXCLUSIONS"]).read_text())
        )
        self.failures = []
        self.passed = 0
        self.infrastructure_error = False

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, config, items):
        deselected = [
            item
            for item in items
            if item.nodeid.removeprefix("mutants/") in self.excluded
        ]
        if deselected:
            items[:] = [item for item in items if item not in deselected]
            config.hook.pytest_deselected(items=deselected)

    def pytest_collectreport(self, report):
        if report.failed:
            self.infrastructure_error = True

    def pytest_runtest_logreport(self, report):
        if report.failed:
            if report.when != "call":
                self.infrastructure_error = True
            self.failures.append(
                {
                    "nodeid": report.nodeid.removeprefix("mutants/"),
                    "when": report.when,
                    "detail": str(report.longrepr),
                }
            )
        elif report.when == "call" and report.passed:
            self.passed += 1

    def pytest_sessionfinish(self, session, exitstatus):
        if self.phase in ("", "stats"):
            self.report_path.write_text(
                json.dumps(
                    {
                        "phase": self.phase or "clean",
                        "exit_code": int(exitstatus),
                        "passed": self.passed,
                        "infrastructure_error": self.infrastructure_error,
                        "failures": self.failures,
                    },
                    indent=2,
                )
                + "\n"
            )
