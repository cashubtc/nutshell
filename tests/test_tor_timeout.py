import pytest

from cashu.tor import timeout as timeout_module


def test_timeout_main_requires_minimum_arguments(monkeypatch):
    monkeypatch.setattr(timeout_module.sys, "argv", ["timeout.py", "2"])
    with pytest.raises(AssertionError, match="Usage: timeout.py"):
        timeout_module.main()


def test_timeout_main_requires_positive_timeout(monkeypatch):
    monkeypatch.setattr(timeout_module.sys, "argv", ["timeout.py", "0", "python"])
    with pytest.raises(AssertionError, match="must be a positive integer"):
        timeout_module.main()


def test_timeout_main_terminates_process_and_children(monkeypatch):
    class DummyProcess:
        pid = 100

        def __init__(self):
            self.calls: list[str] = []

        def terminate(self):
            self.calls.append("terminate")

        def wait(self):
            self.calls.append("wait")

        def kill(self):
            self.calls.append("kill")

    process = DummyProcess()
    popen_calls = {}
    kill_calls: list[tuple[int, int]] = []
    sleep_calls: list[int] = []

    def fake_popen(cmd, shell=False):
        popen_calls["cmd"] = cmd
        popen_calls["shell"] = shell
        return process

    time_points = iter([0.0, 0.5, 3.0])
    monkeypatch.setattr(timeout_module.time, "time", lambda: next(time_points))
    monkeypatch.setattr(
        timeout_module.time, "sleep", lambda seconds: sleep_calls.append(seconds)
    )
    monkeypatch.setattr(timeout_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        timeout_module.os, "kill", lambda pid, sig: kill_calls.append((pid, sig))
    )
    monkeypatch.setattr(
        timeout_module.sys,
        "argv",
        ["timeout.py", "1", "python", "script.py"],
    )

    timeout_module.main()

    assert popen_calls == {"cmd": ["python", "script.py"], "shell": False}
    assert sleep_calls == [1]
    assert process.calls == ["terminate", "wait", "kill", "wait"]
    assert kill_calls == [(101, 15), (101, 9), (102, 15), (102, 9)]
