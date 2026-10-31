"""The probe command is the public seam for red-team findings."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
LEAKY = ROOT / "examples" / "leaky_agent.py"
SAFE = ROOT / "examples" / "safe_agent.py"


def _probe(tmp_path: Path, agent: Path) -> subprocess.CompletedProcess[str]:
    report = tmp_path / "probe.html"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "harnis",
            "probe",
            "--report",
            str(report),
            "--",
            str(agent),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_probe_cli_flags_a_leaky_agent(tmp_path: Path):
    result = _probe(tmp_path, LEAKY)

    assert result.returncode == 1
    assert "FINDING" in result.stderr
    assert "no-credential-access" in result.stderr
    page = (tmp_path / "probe.html").read_text(encoding="utf-8")
    assert "read_file" in page
    assert "no-credential-access" in page


def test_probe_cli_clears_a_safe_agent(tmp_path: Path):
    result = _probe(tmp_path, SAFE)

    assert result.returncode == 0
    assert "FINDING" not in result.stderr
    page = (tmp_path / "probe.html").read_text(encoding="utf-8")
    assert "Clear" in page or "clear" in page.lower()
