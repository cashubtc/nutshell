"""Tests for the conventional-commits commit-msg hook script."""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]


def load_script():
    spec = importlib.util.spec_from_file_location(
        "check_commit_msg", SCRIPTS / "check_commit_msg.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check_commit_msg = load_script()


@pytest.mark.parametrize(
    "subject",
    [
        "feat: add new feature",
        "fix: correct a bug",
        "docs: update documentation",
        "style: reformat code",
        "refactor: restructure module",
        "perf: speed up loop",
        "test: add regression test",
        "build: update dependencies",
        "ci: update workflow",
        "chore: maintenance / tooling",
        "revert: revert a change",
        "feat(wallet): add new feature",
        "fix(mint): correct a bug",
        "docs(core): update documentation",
        "feat!: breaking change",
        "refactor(mint)!: restructure ledger",
        "feat: 4 as the first character",
        "Merge pull request #1234 from cashubtc/fix-thing",
        "Merge branch 'fix-thing' into main",
        'Revert "feat: add new feature"',
        "fixup! feat: add new feature",
        "squash! feat: add new feature",
    ],
)
def test_valid_subjects(subject):
    assert check_commit_msg.is_valid(subject)


@pytest.mark.parametrize(
    "subject",
    [
        "feat add new feature",  # missing colon
        "feat:add new feature",  # missing space after colon
        "feat: ",  # empty description
        "feature: not a valid type",
        "FEAT: wrong case",
        "feat(): empty scope",
        "Merge",  # missing trailing space / incomplete merge subject
        "Revert missing quote",
        "fixup missing bang",
        "update some stuff",
        "1.0.1",
        "",
    ],
)
def test_invalid_subjects(subject):
    assert not check_commit_msg.is_valid(subject)


def test_main_accepts_valid_message(tmp_path):
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_text("feat: add new feature\n\nLonger body explaining the change.\n")
    result = run_hook(msg)
    assert result.returncode == 0, result.stderr


def test_main_rejects_invalid_message(tmp_path):
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_text("update some stuff\n")
    result = run_hook(msg)
    assert result.returncode == 1
    assert "Conventional Commits" in result.stderr
    assert "update some stuff" in result.stderr


def test_main_requires_a_message_file():
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "check_commit_msg.py")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "usage" in result.stderr


def run_hook(msg):
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "check_commit_msg.py"), str(msg)],
        capture_output=True,
        text=True,
    )
