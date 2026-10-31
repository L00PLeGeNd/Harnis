"""Live ptrace denials. Skip everywhere that is not Linux x86_64."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from harnis.linux_ptrace import available, supervise

pytestmark = pytest.mark.skipif(
    not available(),
    reason="ptrace supervisor needs Linux x86_64",
)

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def _protect_command(tmp_path: Path, command: list[str]) -> subprocess.CompletedProcess[str]:
    report = tmp_path / "report.html"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "harnis",
            "protect",
            "--report",
            str(report),
            "--",
            *command,
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_ptrace_blocks_cat_of_ssh_key(tmp_path: Path):
    key = tmp_path / ".ssh" / "id_rsa"
    key.parent.mkdir()
    key.write_text("not-a-real-key\n", encoding="utf-8")

    result = _protect_command(tmp_path, ["cat", str(key)])

    assert "not-a-real-key" not in result.stdout
    assert "not-a-real-key" not in result.stderr
    assert "no-credential-access" in result.stderr
    assert result.returncode != 0
    report = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "no-credential-access" in report


def test_ptrace_allows_cat_of_an_ordinary_file(tmp_path: Path):
    note = tmp_path / "notes.txt"
    note.write_text("hello\n", encoding="utf-8")

    result = _protect_command(tmp_path, ["cat", str(note)])

    assert result.returncode == 0
    assert result.stdout == "hello\n"
    assert "BLOCKED" not in result.stderr


def test_ptrace_blocks_rm_rf(tmp_path: Path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep\n", encoding="utf-8")

    result = _protect_command(tmp_path, ["rm", "-rf", str(victim)])

    assert victim.read_text(encoding="utf-8") == "keep\n"
    assert "no-destructive-exec" in result.stderr
    assert result.returncode != 0


def test_supervise_direct_open_denial(tmp_path: Path):
    key = tmp_path / ".ssh" / "id_rsa"
    key.parent.mkdir()
    key.write_text("not-a-real-key\n", encoding="utf-8")
    report = tmp_path / "direct.html"

    code = supervise(["cat", str(key)], report, None)

    assert code != 0
    assert "no-credential-access" in report.read_text(encoding="utf-8")
