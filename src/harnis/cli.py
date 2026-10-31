"""The one verb: harnis protect -- python agent.py"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from harnis.runtime import BOOTSTRAP, looks_like_python

USAGE = """\
harnis protect -- python agent.py

Deny credential reads, rm -rf, and outbound secrets while the agent runs.
A blocked action is printed to stderr and written to harnis-report.html.

Options:
  --report PATH    HTML report (default: ./harnis-report.html)
  --policy PATH    JSON file adding deny_path_parts and deny_file_names
"""

def main(argv: list[str] | None = None) -> None:
    raise SystemExit(run(argv))


def run(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help"}:
        sys.stdout.write(USAGE)
        return 0
    if args[0] != "protect":
        sys.stderr.write(
            "harnis: unknown command. The entry point is: harnis protect -- python agent.py\n"
        )
        return 2
    return protect(args[1:])


def protect(args: list[str]) -> int:
    report = Path("harnis-report.html")
    policy: Path | None = None
    rest = list(args)
    while rest and rest[0] != "--":
        flag = rest[0]
        if flag in {"-h", "--help"}:
            sys.stdout.write(USAGE)
            return 0
        if flag == "--report":
            if len(rest) < 2:
                return _error("--report needs a path")
            report = Path(rest[1])
            rest = rest[2:]
            continue
        if flag == "--policy":
            if len(rest) < 2:
                return _error("--policy needs a path")
            policy = Path(rest[1])
            rest = rest[2:]
            continue
        return _error(f"unknown option {flag}")
    if not rest or rest[0] != "--" or len(rest) < 2:
        return _error("usage: harnis protect -- python agent.py")
    command = rest[1:]
    report = report.resolve()
    if _is_python(command[0]):
        if len(command) < 2:
            return _error("python needs a script, -c, or -m")
        return _run_python(command[0], command[1:], report, policy)
    from harnis.linux_ptrace import available, supervise

    if available():
        return supervise(command, report, policy)
    sys.stderr.write(
        "harnis: non-Python commands are enforced with ptrace on Linux x86_64.\n"
        "       On this machine run: harnis protect -- python agent.py\n"
    )
    return 2


def _run_python(executable: str, user_args: list[str], report: Path, policy: Path | None) -> int:
    env = os.environ.copy()
    package_root = str(Path(__file__).resolve().parent.parent)
    env["PYTHONPATH"] = package_root + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUTF8"] = "1"
    env["HARNIS_REPORT"] = str(report)
    if policy is not None:
        env["HARNIS_POLICY"] = str(policy)
    completed = subprocess.run([executable, "-c", BOOTSTRAP, *user_args], env=env)
    return completed.returncode


def _is_python(token: str) -> bool:
    return looks_like_python(token)


def _error(message: str) -> int:
    sys.stderr.write(f"harnis: {message}\n")
    return 2
