"""Project-local Harnis files: policy, optional editor hooks, posture summary."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from harnis.hook import default_hooks_json
from harnis.policy import discover_policy
from harnis.scan import ConfigFinding, apply_wraps, scan_config

_DEFAULT_POLICY = {
    "empty_edit_limit": 5,
    "max_tool_calls": 300,
    "max_unique_paths": 80,
}
_HOOK_EVENTS = ("beforeShellExecution", "beforeMCPExecution", "preToolUse")


@dataclass(frozen=True)
class InitReport:
    hooks_path: Path | None
    hooks_action: str
    policy_path: Path
    policy_action: str
    applied: tuple[ConfigFinding, ...]


@dataclass(frozen=True)
class StatusReport:
    hooks: str
    policy: str
    policy_path: Path | None
    findings: tuple[ConfigFinding, ...]
    scanned: tuple[Path, ...]

    @property
    def ready(self) -> bool:
        open_wraps = any(finding.wrapable for finding in self.findings)
        return self.policy == "ok" and not open_wraps


def init_project(
    root: Path | None = None,
    *,
    apply: bool = True,
    hooks: bool | None = None,
) -> InitReport:
    """Install policy, wrap local MCP configs, optionally install editor hooks.

    hooks=None installs hooks only when `.cursor/` already exists.
    hooks=True always writes them; hooks=False never does.
    """
    base = Path.cwd() if root is None else Path(root)
    want_hooks = bool((base / ".cursor").is_dir()) if hooks is None else hooks
    hooks_path: Path | None = None
    hooks_action = "skipped"
    if want_hooks:
        hooks_path, hooks_action = _ensure_hooks(base)
    policy_path, policy_action = _ensure_policy(base)
    applied: list[ConfigFinding] = []
    if apply:
        for path in _project_mcp_paths(base):
            applied.extend(apply_wraps(path))
    return InitReport(
        hooks_path=hooks_path,
        hooks_action=hooks_action,
        policy_path=policy_path,
        policy_action=policy_action,
        applied=tuple(applied),
    )


def status_report(root: Path | None = None) -> StatusReport:
    base = Path.cwd() if root is None else Path(root)
    hooks_path = base / ".cursor" / "hooks.json"
    if _hooks_have_harnis(hooks_path):
        hooks = "ok"
    elif (base / ".cursor").is_dir():
        hooks = "optional"
    else:
        hooks = "n/a"
    policy_path = discover_policy(base)
    policy = "ok" if policy_path is not None else "missing"
    scanned = tuple(_project_mcp_paths(base))
    findings: list[ConfigFinding] = []
    for path in scanned:
        findings.extend(scan_config(path))
    return StatusReport(
        hooks=hooks,
        policy=policy,
        policy_path=policy_path,
        findings=tuple(findings),
        scanned=scanned,
    )


def format_init(report: InitReport) -> str:
    lines = [
        f"policy: {report.policy_action} ({report.policy_path})",
    ]
    if report.hooks_action != "skipped":
        where = report.hooks_path or ".cursor/hooks.json"
        lines.append(f"hooks: {report.hooks_action} ({where})")
    else:
        lines.append("hooks: skipped (optional — pass --hooks)")
    if report.applied:
        for finding in report.applied:
            where = finding.path or "mcp.json"
            lines.append(f"wrapped {finding.server} in {where}")
    else:
        lines.append("wraps: nothing new to apply")
    lines.append("next: npx -y harnis status")
    return "\n".join(lines) + "\n"


def format_status(report: StatusReport) -> str:
    lines = [
        f"policy: {report.policy}"
        + (f" ({report.policy_path})" if report.policy_path else ""),
        f"hooks: {report.hooks}",
    ]
    if report.scanned:
        listed = ", ".join(str(path) for path in report.scanned)
        lines.append(f"scanned: {listed}")
    else:
        lines.append("scanned: no local mcp.json found")
    wrapable = [finding for finding in report.findings if finding.wrapable]
    remotes = [finding for finding in report.findings if not finding.wrapable]
    if wrapable:
        for finding in wrapable:
            lines.append(f"unwrap: {finding.server} can call {finding.tool}")
    else:
        lines.append("unwrap: none")
    for finding in remotes:
        lines.append(f"remote: {finding.server} (url-only, not wrapable)")
    if report.ready:
        lines.append("posture: protected")
    else:
        lines.append("fix: npx -y harnis init")
    return "\n".join(lines) + "\n"


def _project_mcp_paths(base: Path) -> list[Path]:
    return [
        path
        for path in (
            base / "mcp.json",
            base / ".cursor" / "mcp.json",
            base / ".vscode" / "mcp.json",
        )
        if path.is_file()
    ]


def _ensure_policy(base: Path) -> tuple[Path, str]:
    existing = discover_policy(base)
    if existing is not None:
        return existing, "already ok"
    path = base / ".harnis" / "policy.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_DEFAULT_POLICY, indent=2) + "\n", encoding="utf-8")
    return path, "wrote"


def _ensure_hooks(base: Path) -> tuple[Path, str]:
    path = base / ".cursor" / "hooks.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    desired = default_hooks_json()
    if not path.is_file():
        path.write_text(json.dumps(desired, indent=2) + "\n", encoding="utf-8")
        return path, "wrote"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        path.write_text(json.dumps(desired, indent=2) + "\n", encoding="utf-8")
        return path, "repaired"
    if not isinstance(data, dict):
        path.write_text(json.dumps(desired, indent=2) + "\n", encoding="utf-8")
        return path, "repaired"
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        data["hooks"] = desired["hooks"]
        data["version"] = desired["version"]
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return path, "repaired"
    changed = False
    for event, entries in desired["hooks"].items():
        current = hooks.get(event)
        if not isinstance(current, list):
            hooks[event] = list(entries)
            changed = True
            continue
        if _harnis_hook_present(current):
            continue
        hooks[event] = list(current) + list(entries)
        changed = True
    data.setdefault("version", 1)
    if changed:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return path, "updated"
    return path, "already ok"


def _hooks_have_harnis(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    hooks = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        return False
    for event in _HOOK_EVENTS:
        entries = hooks.get(event)
        if isinstance(entries, list) and _harnis_hook_present(entries):
            return True
    return False


def _harnis_hook_present(entries: list) -> bool:
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        command = str(entry.get("command") or "").casefold()
        if "harnis" in command and "hook" in command:
            return True
    return False
