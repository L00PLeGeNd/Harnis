"""Editor agent hooks: stdin JSON in, permission JSON out.

Compatible with Cursor-style hook events; other editors can send the same shape.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from harnis.budget import EditBudget
from harnis.policy import Decision, Rules, judge, judge_tool_call, Action


def handle_hook(
    event: dict,
    rules: Rules,
    state_dir: Path | None = None,
) -> dict:
    """Judge one Cursor hook event and return its permission payload."""
    if not isinstance(event, dict):
        return _allow()
    name = str(event.get("hook_event_name") or event.get("event") or "")
    conversation = str(event.get("conversation_id") or event.get("session_id") or "default")
    state_path = _state_path(state_dir, conversation)
    budget = EditBudget.load(state_path, rules)

    decision: Decision | None = None
    if name == "beforeShellExecution":
        decision = judge(
            Action(kind="exec", command=_as_command(event.get("command"))),
            rules,
        )
        if decision.allowed:
            thrash = budget.judge("shell", {"command": event.get("command")})
            if thrash is not None:
                decision = thrash
    elif name in {"beforeMCPExecution", "preToolUse"}:
        tool, arguments = _tool_call(event)
        decision = judge_tool_call(tool, arguments, rules)
        if decision.allowed:
            thrash = budget.judge(tool, arguments)
            if thrash is not None:
                decision = thrash
    else:
        return _allow()

    budget.save(state_path)
    if decision is None or decision.allowed:
        return _allow()
    return {
        "permission": "deny",
        "user_message": decision.line(),
        "agent_message": decision.line(),
    }


def _tool_call(event: dict) -> tuple[str, dict]:
    raw_name = str(event.get("tool_name") or "")
    arguments = _arguments(event.get("tool_input"))
    mapped = _map_cursor_tool(raw_name, arguments)
    if mapped is not None:
        return mapped
    if raw_name.upper().startswith("MCP:"):
        return raw_name.split(":", 1)[1], arguments
    return raw_name, arguments


def _map_cursor_tool(name: str, arguments: dict) -> tuple[str, dict] | None:
    key = name.strip()
    if key == "Shell":
        return "shell", {"command": arguments.get("command") or arguments.get("cmd") or ""}
    if key == "Read":
        path = arguments.get("path") or arguments.get("file_path") or ""
        return "read_file", {"path": path}
    if key == "Write":
        path = arguments.get("path") or arguments.get("file_path") or ""
        content = arguments.get("contents") or arguments.get("content") or ""
        return "write_file", {"path": path, "content": content}
    if key == "Delete":
        path = arguments.get("path") or arguments.get("file_path") or ""
        return "write_file", {"path": path, "content": ""}
    return None


def _arguments(value) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def _as_command(value) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(str(part) for part in value)
    if isinstance(value, str):
        return (value,)
    return ()


def _state_path(state_dir: Path | None, conversation: str) -> Path:
    root = state_dir
    if root is None:
        root = Path(tempfile.gettempdir()) / "harnis-hooks"
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in conversation)[:80]
    return root / f"{safe or 'default'}.json"


def _allow() -> dict:
    return {"permission": "allow"}


def default_hooks_json() -> dict:
    command = "npx -y harnis hook"
    if os.name == "nt":
        command = "npx -y harnis hook"
    return {
        "version": 1,
        "hooks": {
            "beforeShellExecution": [{"command": command}],
            "beforeMCPExecution": [{"command": command, "failClosed": True}],
            "preToolUse": [{"command": command}],
        },
    }
