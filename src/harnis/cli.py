"""Entry points: harnis mcp / harnis protect / harnis probe."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from harnis.runtime import BOOTSTRAP, looks_like_python

USAGE = """\
harnis mcp -- npx -y @modelcontextprotocol/server-filesystem /work
harnis protect -- python agent.py
harnis probe -- examples/leaky_agent.py
harnis probe --transcript session.jsonl

mcp      Judge tools/call, then forward the rest to an MCP stdio server.
protect  Deny credential reads, rm -rf, and outbound secrets at runtime.
probe    Judge tool calls the MCP proxy would refuse. A transcript is not executed.

Options:
  --preset NAME       coding-agent (default), readonly, or ci
  --report PATH       HTML report
  --policy PATH       JSON file adding deny_path_parts and deny_file_names
  --url URL           Probe an HTTP agent instead of a local script
  --transcript PATH   Judge a recorded MCP JSONL session. Nothing is executed
  --scenario LIST     Comma list: credential,destructive,rag,escalation,exfil,all
"""


def main(argv: list[str] | None = None) -> None:
    raise SystemExit(run(argv))


def run(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help"}:
        sys.stdout.write(USAGE)
        return 0
    command = args[0]
    if command == "mcp":
        return mcp_command(args[1:])
    if command == "protect":
        return protect(args[1:])
    if command == "probe":
        return probe_command(args[1:])
    sys.stderr.write(
        "harnis: unknown command. Use: harnis mcp -- <server>\n"
        "                         or: harnis protect -- python agent.py\n"
        "                         or: harnis probe -- agent.py\n"
    )
    return 2


def mcp_command(args: list[str]) -> int:
    from harnis.mcp_proxy import proxy
    from harnis.policy import rules_for

    report = Path("harnis-mcp.html")
    policy: Path | None = None
    preset = "coding-agent"
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
        if flag == "--preset":
            if len(rest) < 2:
                return _error("--preset needs a name")
            preset = rest[1]
            rest = rest[2:]
            continue
        return _error(f"unknown option {flag}")
    if not rest or rest[0] != "--" or len(rest) < 2:
        return _error("usage: harnis mcp -- <server command>")
    try:
        rules = rules_for(preset, str(policy) if policy else None)
    except ValueError as exc:
        return _error(str(exc))
    return proxy(rest[1:], rules, report.resolve())


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


def probe_command(args: list[str]) -> int:
    report = Path("harnis-probe.html")
    policy: Path | None = None
    url: str | None = None
    transcript: Path | None = None
    preset = "coding-agent"
    scenarios: tuple[str, ...] = ("credential", "destructive")
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
        if flag == "--url":
            if len(rest) < 2:
                return _error("--url needs an endpoint")
            url = rest[1]
            rest = rest[2:]
            continue
        if flag == "--transcript":
            if len(rest) < 2:
                return _error("--transcript needs a path")
            transcript = Path(rest[1])
            rest = rest[2:]
            continue
        if flag == "--preset":
            if len(rest) < 2:
                return _error("--preset needs a name")
            preset = rest[1]
            rest = rest[2:]
            continue
        if flag == "--scenario":
            if len(rest) < 2:
                return _error("--scenario needs a list")
            scenarios = tuple(
                part.strip() for part in rest[1].split(",") if part.strip()
            )
            if not scenarios:
                return _error("--scenario needs at least one name")
            rest = rest[2:]
            continue
        return _error(f"unknown option {flag}")

    from harnis.policy import rules_for
    from harnis.probe import probe_script, probe_transcript, probe_url
    from harnis.report import emit_finding

    try:
        if url is not None and (transcript is not None or rest):
            return _error("use one of --url, --transcript, or -- script.py")
        if transcript is not None and rest:
            return _error("use one of --url, --transcript, or -- script.py")
        if url is not None:
            findings = probe_url(url, report.resolve(), policy, scenarios, preset)
        elif transcript is not None:
            findings = probe_transcript(
                transcript, report.resolve(), rules_for(preset, str(policy) if policy else None)
            )
        else:
            if not rest or rest[0] != "--" or len(rest) < 2:
                return _error("usage: harnis probe -- agent.py")
            agent_path = Path(rest[1])
            if not agent_path.is_file():
                return _error(f"agent script not found: {agent_path}")
            findings = probe_script(
                agent_path.resolve(), report.resolve(), policy, scenarios, preset
            )
    except (OSError, ValueError) as exc:
        return _error(str(exc))
    for finding in findings:
        emit_finding(finding)
    return 1 if findings else 0


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
