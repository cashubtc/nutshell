"""Configuration precedence checks, isolated from module-level settings state."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class SettingsEnvTests(unittest.TestCase):
    def test_env_file_precedence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            (home / ".cashu").mkdir(parents=True)
            cwd = root / "work"
            cwd.mkdir()
            home_env = home / ".cashu" / ".env"
            home_env.write_text("MINT_INFO_NAME=home\n", encoding="utf-8")
            local_env = cwd / ".env"
            local_env.write_text(
                "TEST_ENV_NAME=local\nMINT_INFO_NAME=${TEST_ENV_NAME}\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env.update(
                HOME=str(home),
                USERPROFILE=str(home),
                PYTHONPATH=str(Path(__file__).resolve().parents[1]),
                MINT_INFO_NAME="shell",
            )
            # Local file wins, overrides the shell, and expands variables.
            # Home file is the fallback; no file leaves the shell untouched.
            for expected, expected_file in [
                ("local", str(local_env)),
                ("home", str(home_env)),
                ("shell", ""),
            ]:
                with self.subTest(expected=expected):
                    subprocess.run(
                        [
                            sys.executable,
                            "-c",
                            "from cashu.core.settings import settings; "
                            f"assert settings.mint_info_name == {expected!r}; "
                            f"assert settings.env_file == {expected_file!r}",
                        ],
                        cwd=cwd,
                        env=env,
                        check=True,
                    )
                if expected_file:
                    Path(expected_file).unlink()


if __name__ == "__main__":
    unittest.main()
