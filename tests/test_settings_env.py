"""Configuration precedence checks, isolated from module-level settings state."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from textwrap import dedent


class SettingsEnvTests(unittest.TestCase):
    def test_secret_limits_use_startup_configuration(self):
        script = dedent(
            """
            import sys
            from typing import Annotated
            from unittest.mock import patch
            from pydantic import BeforeValidator, TypeAdapter, ValidationError
            from cashu.core.base import AuthProof
            from cashu.core.models import PostMeltRequest, PostSwapRequest
            from cashu.core.settings import settings
            from cashu.mint.validation import validate_input_secret_lengths

            limit = settings.mint_max_secret_length
            assert limit == int(sys.argv[1])
            proof = {
                "id": "00deadbeefdeadbe", "amount": 1,
                "C": "02" + "11" * 32, "secret": "😀" * limit,
            }
            auth = AuthProof(**proof)
            token = auth.to_base64()
            assert len(token) <= AuthProof.max_token_length()
            assert AuthProof.from_base64(token) == auth
            for model, fields in (
                (PostSwapRequest, {}), (PostMeltRequest, {"quote": "quote"}),
            ):
                adapter = TypeAdapter(
                    Annotated[model, BeforeValidator(validate_input_secret_lengths)]
                )
                body = {"inputs": [proof], "outputs": [], **fields}
                request = adapter.validate_python(body)
                assert request.inputs[0].secret == proof["secret"]
                assert request.inputs[0].Y
                proof["secret"] += "x"
                with patch("cashu.core.base.hash_to_curve") as hashed:
                    try:
                        adapter.validate_python(body)
                    except ValidationError as exc:
                        assert exc.errors(include_input=False)[0]["loc"] == (
                            "inputs", 0, "secret"
                        )
                    else:
                        raise AssertionError("request accepted overlong secret")
                    hashed.assert_not_called()
                wallet_request = model.model_validate(body)
                assert wallet_request.inputs[0].secret == proof["secret"]
                try:
                    AuthProof(**proof)
                except ValidationError as exc:
                    assert exc.errors(include_input=False)[0]["loc"] == ("secret",)
                else:
                    raise AssertionError("auth accepted overlong secret")
                proof["secret"] = "😀" * limit
            """
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = {
                **os.environ,
                "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
            }
            if env.get("MUTANT_UNDER_TEST") == "stats":
                # Stats collection cannot run from the temporary subprocess cwd.
                env["MUTANT_UNDER_TEST"] = ""
            for limit in (8, 2048):
                with self.subTest(limit=limit):
                    (root / ".env").write_text(
                        f"MINT_MAX_SECRET_LENGTH={limit}\n", encoding="utf-8"
                    )
                    subprocess.run(
                        [sys.executable, "-c", script, str(limit)],
                        cwd=root,
                        env=env,
                        check=True,
                    )

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
            if env.get("MUTANT_UNDER_TEST") == "stats":
                # Mutmut cannot collect coverage from this subprocess, whose
                # temporary cwd also has no mutation configuration. Disable only
                # stats collection; keep actual mutant IDs for mutation runs.
                env["MUTANT_UNDER_TEST"] = ""
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
