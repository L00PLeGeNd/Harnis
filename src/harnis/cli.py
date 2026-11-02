"""Entry points: harnis mcp / harnis protect / harnis probe."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from harnis.runtime import BOOTSTRAP, looks_like_python

USAGE = """\
harnis init
harnis status
harnis scan
harnis scan --apply
harnis scan --json
harnis demo
harnis mcp -- npx -y @modelcontextprotocol/server-filesystem /work
harnis protect -- python agent.py
harnis probe -- examples/leaky_agent.py
harnis probe --transcript session.jsonl
harnis hook

init     Write .harnis/policy.json and wrap local MCP servers (optional editor hooks).
status   Show policy, wraps, and optional hooks posture.
scan     Read mcp.json. Name the dangerous tool and print a wrap, or --apply it.
demo     Print one BLOCKED line for a GitHub delete_file. Nothing is executed.
mcp      Judge tools/call and resources/read, then forward the rest.
protect  Deny credential reads, rm -rf, and outbound secrets at runtime.
probe    Judge tool calls the MCP proxy would refuse. A transcript is not executed.
hook     Editor hook adapter: stdin JSON event → permission JSON.

Options:
  --apply             Rewrite bare catalog servers in mcp.json. Keep a .bak copy
  --no-apply          init: policy only (and hooks if requested), no wraps
  --hooks             init: install editor hooks under .cursor/hooks.json
  --no-hooks          init: never install hooks
  --json              Print scan findings as JSON
  --preset NAME       coding-agent (default), github, readonly, ci (extras: postgres, slack, browser, email)
  --report PATH       HTML report
  --policy PATH       JSON: deny/allow paths, deny_tools, budgets
  --url URL           Probe an HTTP agent instead of a local script
  --transcript PATH   Judge a recorded MCP JSONL session. Nothing is executed
  --scenario LIST     Comma list: credential,destructive,rag,escalation,exfil,all
"""

_FLAG_NEED = {
    "--report": "a path",
    "--policy": "a path",
    "--preset": "a name",
    "--url": "an endpoint",
    "--transcript": "a path",
    "--scenario": "a list",
}


def main(argv: list[str] | None = None) -> None:
    raise SystemExit(run(argv))


def run(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help"}:
        sys.stdout.write(USAGE)
        return 0
    command = args[0]
    if command in {"version", "--version", "-V"}:
        from harnis import __version__

        sys.stdout.write(__version__ + "\n")
        return 0
    if command == "init":
        return init_command(args[1:])
    if command == "status":
        return status_command(args[1:])
    if command == "scan":
        return scan_command(args[1:])
    if command == "demo":
        return demo_command(args[1:])
    if command == "mcp":
        return mcp_command(args[1:])
    if command == "protect":
        return protect(args[1:])
    if command == "probe":
        return probe_command(args[1:])
    if command == "hook":
        return hook_command(args[1:])
    sys.stderr.write(
        "harnis: unknown command. Use: harnis init\n"
        "                         or: harnis status\n"
        "                         or: harnis scan [mcp.json]\n"
        "                         or: harnis demo\n"
        "                         or: harnis mcp -- <server>\n"
        "                         or: harnis protect -- python agent.py\n"
        "                         or: harnis probe -- agent.py\n"
        "                         or: harnis hook\n"
    )
    return 2


def init_command(args: list[str]) -> int:
    from harnis.project import format_init, init_project

    if args and args[0] in {"-h", "--help"}:
        sys.stdout.write(USAGE)
        return 0
    apply = True
    hooks: bool | None = None
    for flag in args:
        if flag == "--no-apply":
            apply = False
            continue
        if flag == "--apply":
            apply = True
            continue
        if flag == "--hooks":
            hooks = True
            continue
        if flag == "--no-hooks":
            hooks = False
            continue
        return _error("usage: harnis init [--apply|--no-apply] [--hooks|--no-hooks]")
    try:
        report = init_project(apply=apply, hooks=hooks)
    except (OSError, ValueError) as exc:
        return _error(str(exc))
    sys.stdout.write(format_init(report))
    return 0


def status_command(args: list[str]) -> int:
    from harnis.project import format_status, status_report

    if args and args[0] in {"-h", "--help"}:
        sys.stdout.write(USAGE)
        return 0
    if args:
        return _error("usage: harnis status")
    report = status_report()
    sys.stdout.write(format_status(report))
    return 0 if report.ready else 1


def scan_command(args: list[str]) -> int:
    import json

    from harnis.scan import apply_wraps, scan_config, scan_files

    if args and args[0] in {"-h", "--help"}:
        sys.stdout.write(USAGE)
        return 0
    apply = False
    as_json = False
    path: Path | None = None
    for flag in args:
        if flag == "--apply":
            apply = True
            continue
        if flag == "--json":
            as_json = True
            continue
        if path is not None:
            return _error("usage: harnis scan [--apply] [--json] [mcp.json]")
        path = Path(flag)
    if apply and as_json:
        return _error("use --apply or --json, not both")
    try:
        findings = apply_wraps(path) if apply else scan_config(path)
    except (OSError, ValueError) as exc:
        return _error(str(exc))
    if not findings:
        if as_json:
            sys.stdout.write("[]\n")
            return 0
        files = scan_files(path)
        if not files or (path is not None and not path.is_file()):
            sys.stderr.write("harnis: no mcp.json found\n")
        else:
            listed = ", ".join(str(file) for file in files)
            sys.stderr.write(f"harnis: scanned {listed}; nothing to wrap\n")
        return 0
    if as_json:
        payload = [
            {
                "server": finding.server,
                "preset": finding.preset,
                "tool": finding.tool,
                "client": finding.client,
                "wrapable": finding.wrapable,
                "path": str(finding.path) if finding.path else None,
                "snippet": finding.snippet,
            }
            for finding in findings
        ]
        sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        return 1
    for finding in findings:
        sys.stdout.write(finding.sentence() + "\n")
        if apply and finding.path is not None:
            sys.stdout.write(f"wrapped {finding.server} in {finding.path}\n")
        elif finding.wrapable:
            sys.stdout.write(json.dumps(finding.snippet, indent=2) + "\n")
    return 0 if apply else 1


def hook_command(args: list[str]) -> int:
    import json

    from harnis.hook import handle_hook
    from harnis.policy import resolve_policy_path, rules_for

    opts, rest, err = _flags(args, "--policy", "--preset")
    if err == "help":
        sys.stdout.write(USAGE)
        return 0
    if err:
        return _error(err)
    if rest:
        return _error("usage: harnis hook [--policy PATH] [--preset NAME]")
    try:
        rules = rules_for(
            opts.get("--preset", "coding-agent"),
            resolve_policy_path(opts.get("--policy")),
        )
    except ValueError as exc:
        return _error(str(exc))
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return _error("hook stdin must be JSON")
    if not isinstance(event, dict):
        return _error("hook stdin must be a JSON object")
    payload = handle_hook(event, rules)
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    return 0


def demo_command(args: list[str]) -> int:
    if args and args[0] in {"-h", "--help"}:
        sys.stdout.write(USAGE)
        return 0
    if args:
        return _error("usage: harnis demo")
    from harnis.policy import judge_tool_call, rules_for
    from harnis.report import emit

    decision = judge_tool_call(
        "delete_file",
        {"owner": "acme", "repo": "app", "path": "secret.env", "branch": "main"},
        rules_for("github"),
    )
    emit(decision)
    return 0 if decision.allowed else 1


def mcp_command(args: list[str]) -> int:
    from harnis.mcp_proxy import proxy
    from harnis.policy import resolve_policy_path, rules_for

    opts, rest, err = _flags(args, "--report", "--policy", "--preset")
    if err == "help":
        sys.stdout.write(USAGE)
        return 0
    if err:
        return _error(err)
    if not rest:
        return _error("usage: harnis mcp -- <server command>")
    try:
        rules = rules_for(
            opts.get("--preset", "coding-agent"),
            resolve_policy_path(opts.get("--policy")),
        )
    except ValueError as exc:
        return _error(str(exc))
    report = Path(opts.get("--report", "harnis-mcp.html")).resolve()
    return proxy(rest, rules, report)


def protect(args: list[str]) -> int:
    from harnis.policy import resolve_policy_path

    opts, rest, err = _flags(args, "--report", "--policy")
    if err == "help":
        sys.stdout.write(USAGE)
        return 0
    if err:
        return _error(err)
    if not rest:
        return _error("usage: harnis protect -- python agent.py")
    report = Path(opts.get("--report", "harnis-report.html")).resolve()
    resolved = resolve_policy_path(opts.get("--policy"))
    policy = Path(resolved) if resolved else None
    if looks_like_python(rest[0]):
        if len(rest) < 2:
            return _error("python needs a script, -c, or -m")
        return _run_python(rest[0], rest[1:], report, policy)
    from harnis.linux_ptrace import available, supervise

    if available():
        return supervise(rest, report, policy)
    sys.stderr.write(
        "harnis: non-Python commands are enforced with ptrace on Linux x86_64.\n"
        "       On this machine run: harnis protect -- python agent.py\n"
    )
    return 2


def probe_command(args: list[str]) -> int:
    opts, rest, err = _flags(
        args, "--report", "--policy", "--url", "--transcript", "--preset", "--scenario"
    )
    if err == "help":
        sys.stdout.write(USAGE)
        return 0
    if err:
        return _error(err)

    from harnis.policy import resolve_policy_path, rules_for
    from harnis.probe import probe_script, probe_transcript, probe_url
    from harnis.report import emit_finding

    report = Path(opts.get("--report", "harnis-probe.html")).resolve()
    resolved = resolve_policy_path(opts.get("--policy"))
    policy = Path(resolved) if resolved else None
    preset = opts.get("--preset", "coding-agent")
    url = opts.get("--url")
    transcript = Path(opts["--transcript"]) if "--transcript" in opts else None
    if "--scenario" in opts:
        scenarios = tuple(part.strip() for part in opts["--scenario"].split(",") if part.strip())
        if not scenarios:
            return _error("--scenario needs at least one name")
    else:
        scenarios = ("credential", "destructive")

    try:
        if url is not None and (transcript is not None or rest):
            return _error("use one of --url, --transcript, or -- script.py")
        if transcript is not None and rest:
            return _error("use one of --url, --transcript, or -- script.py")
        if url is not None:
            findings = probe_url(url, report, policy, scenarios, preset)
        elif transcript is not None:
            findings = probe_transcript(
                transcript, report, rules_for(preset, str(policy) if policy else None)
            )
        else:
            if not rest:
                return _error("usage: harnis probe -- agent.py")
            agent_path = Path(rest[0])
            if not agent_path.is_file():
                return _error(f"agent script not found: {agent_path}")
            findings = probe_script(agent_path.resolve(), report, policy, scenarios, preset)
    except (OSError, ValueError) as exc:
        return _error(str(exc))
    for finding in findings:
        emit_finding(finding)
    return 1 if findings else 0


def _flags(
    args: list[str], *allowed: str
) -> tuple[dict[str, str], list[str], str | None]:
    """Parse options until `--`. Returns opts, argv after `--`, or an error."""
    opts: dict[str, str] = {}
    rest = list(args)
    allowed_set = set(allowed)
    while rest and rest[0] != "--":
        flag = rest[0]
        if flag in {"-h", "--help"}:
            return opts, rest, "help"
        if flag not in allowed_set:
            return opts, rest, f"unknown option {flag}"
        if len(rest) < 2:
            return opts, rest, f"{flag} needs {_FLAG_NEED[flag]}"
        opts[flag] = rest[1]
        rest = rest[2:]
    if not rest or rest[0] != "--":
        return opts, [], None
    return opts, rest[1:], None


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


def _error(message: str) -> int:
    sys.stderr.write(f"harnis: {message}\n")
    return 2
