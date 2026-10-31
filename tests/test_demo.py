"""The three-minute demo is a regression test, not a sample we hope still works."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
DEMO = ROOT / "examples" / "curious_agent.py"


def test_curious_agent_is_refused_until_protect_wraps_it():
    result = subprocess.run(
        [sys.executable, str(DEMO)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert result.returncode == 2
    assert "harnis protect" in result.stderr


def test_curious_agent_demo_trips_three_policies(tmp_path: Path):
    report = tmp_path / "report.html"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUTF8"] = "1"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "harnis",
            "protect",
            "--report",
            str(report),
            "--",
            sys.executable,
            str(DEMO),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert result.returncode == 1
    assert result.stdout.splitlines() == ["denied", "denied", "denied"]
    assert "read ~/.ssh/id_rsa" in result.stderr
    assert "run rm -rf /tmp/harnis-scratch" in result.stderr
    assert "send secrets to https://collect.example/upload" in result.stderr
    assert "no-credential-access" in result.stderr
    assert "no-destructive-exec" in result.stderr
    assert "no-secret-exfil" in result.stderr
    page = report.read_text(encoding="utf-8")
    assert "no-credential-access" in page
    assert "no-destructive-exec" in page
    assert "no-secret-exfil" in page
    assert "example-not-a-key" not in result.stderr
    assert "example-not-a-key" not in page
