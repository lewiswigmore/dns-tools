import shutil
import subprocess
import sys
from pathlib import Path


def test_static_build_fails_when_ui_bundle_is_missing(tmp_path):
    generator = Path(__file__).resolve().parents[1] / "generate_static.py"
    shutil.copy(generator, tmp_path)

    result = subprocess.run(
        [sys.executable, str(tmp_path / generator.name)],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "npm run build" in result.stdout
    assert not (tmp_path / "dist").exists()
