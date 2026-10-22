"""Release validation reads the same version metadata used by the build."""

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "check_version.py"
pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 11), reason="Release validation uses stdlib tomllib"
)


@pytest.mark.parametrize("tag", ["0.21.0", "v0.21.0", "v0.22.0"])
def test_check_version_uses_project_metadata(tmp_path, tag):
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.21.0"\n')
    settings = tmp_path / "cashu/core/settings.py"
    settings.parent.mkdir(parents=True)
    settings.write_text('VERSION = "0.21.0"\n')

    result = subprocess.run(
        [sys.executable, str(SCRIPT), tag],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )

    assert "Pyproject version: 0.21.0" in result.stdout
    assert result.returncode == (1 if tag == "v0.22.0" else 0)
