"""Run the ptrace path without pytest. Used from WSL when apt/venv is unavailable."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from harnis.linux_ptrace import available, supervise  # noqa: E402


def main() -> int:
    if not available():
        print("SKIP: not Linux x86_64", file=sys.stderr)
        return 0
    failures = 0
    with tempfile.TemporaryDirectory(prefix="harnis-ptrace-") as raw:
        base = Path(raw)
        failures += _expect_block_cat_key(base)
        failures += _expect_allow_cat_note(base)
        failures += _expect_block_rm_rf(base)
    if failures:
        print(f"FAIL: {failures} case(s)", file=sys.stderr)
        return 1
    print("PASS: ptrace smoke")
    return 0


def _expect_block_cat_key(base: Path) -> int:
    key = base / ".ssh" / "id_rsa"
    key.parent.mkdir()
    key.write_text("not-a-real-key\n", encoding="utf-8")
    report = base / "key.html"
    code = supervise(["cat", str(key)], report, None)
    text = report.read_text(encoding="utf-8")
    if code == 0 or "no-credential-access" not in text:
        print("FAIL cat key", code, text[:200], file=sys.stderr)
        return 1
    print("ok block cat key")
    return 0


def _expect_allow_cat_note(base: Path) -> int:
    note = base / "notes.txt"
    note.write_text("hello\n", encoding="utf-8")
    report = base / "note.html"
    # Capture stdout from the supervised process by wrapping in a shell that
    # writes cat output to a file we control.
    out = base / "out.txt"
    code = supervise(["sh", "-c", f"cat {note} > {out}"], report, None)
    if code != 0:
        print("FAIL allow cat", code, report.read_text(encoding="utf-8")[:200], file=sys.stderr)
        return 1
    if out.read_text(encoding="utf-8") != "hello\n":
        print("FAIL allow cat content", out.read_text(encoding="utf-8"), file=sys.stderr)
        return 1
    if "BLOCKED" in report.read_text(encoding="utf-8"):
        print("FAIL allow cat blocked", file=sys.stderr)
        return 1
    print("ok allow cat note")
    return 0


def _expect_block_rm_rf(base: Path) -> int:
    victim = base / "victim.txt"
    victim.write_text("keep\n", encoding="utf-8")
    report = base / "rm.html"
    code = supervise(["rm", "-rf", str(victim)], report, None)
    if victim.read_text(encoding="utf-8") != "keep\n":
        print("FAIL rm deleted the file", file=sys.stderr)
        return 1
    text = report.read_text(encoding="utf-8")
    if code == 0 or "no-destructive-exec" not in text:
        print("FAIL rm", code, text[:200], file=sys.stderr)
        return 1
    print("ok block rm -rf")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
