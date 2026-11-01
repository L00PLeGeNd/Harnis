"""Newline-delimited JSON-RPC proxy in front of an MCP stdio server.

A tools/call is judged before the server process sees it. A denial is
returned to the client as a tool error and is not forwarded.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path

from harnis.budget import EditBudget
from harnis.policy import Decision, Rules, judge_tool_call
from harnis.report import Session, emit


def handle_client_message(
    message: dict,
    rules: Rules | None = None,
    budget: EditBudget | None = None,
) -> dict | None:
    """Return a JSON-RPC response when the call must stop here."""
    decision = decision_for_message(message, rules, budget)
    if decision is None or decision.allowed:
        return None
    return {
        "jsonrpc": "2.0",
        "id": message.get("id"),
        "result": {
            "content": [{"type": "text", "text": decision.line()}],
            "isError": True,
        },
    }


def decision_for_message(
    message: dict,
    rules: Rules | None = None,
    budget: EditBudget | None = None,
) -> Decision | None:
    if not isinstance(message, dict) or message.get("method") != "tools/call":
        return None
    params = message.get("params") or {}
    if not isinstance(params, dict):
        return None
    name = str(params.get("name") or "")
    arguments = _arguments(params.get("arguments"))
    decision = judge_tool_call(name, arguments, rules)
    if not decision.allowed:
        return decision
    if budget is None:
        return decision
    thrash = budget.judge(name, arguments)
    return thrash if thrash is not None else decision


def proxy(command: list[str], rules: Rules, report: Path) -> int:
    """Sit between this process's stdin/stdout and the server command."""
    session = Session(report)
    budget = EditBudget.from_rules(rules)
    server = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,
    )
    assert server.stdin is not None and server.stdout is not None
    pump = threading.Thread(target=_copy_stdout, args=(server,), daemon=True)
    pump.start()
    try:
        for raw in iter(sys.stdin.buffer.readline, b""):
            _forward_or_block(raw, server, rules, session, budget)
    finally:
        _close_stdin(server)
        pump.join(timeout=15)
        code = server.wait(timeout=15)
        if session.blocked:
            session.write()
    return code


def _forward_or_block(
    raw: bytes,
    server: subprocess.Popen,
    rules: Rules,
    session: Session,
    budget: EditBudget,
) -> None:
    message = _parse(raw)
    decision = decision_for_message(message, rules, budget) if message is not None else None
    if decision is None or decision.allowed:
        assert server.stdin is not None
        server.stdin.write(raw if raw.endswith(b"\n") else raw + b"\n")
        server.stdin.flush()
        return
    if not session.already_recorded(decision):
        session.record(decision)
        emit(decision)
    response = {
        "jsonrpc": "2.0",
        "id": (message or {}).get("id"),
        "result": {
            "content": [{"type": "text", "text": decision.line()}],
            "isError": True,
        },
    }
    payload = json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n"
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def _copy_stdout(server: subprocess.Popen) -> None:
    assert server.stdout is not None
    try:
        for line in iter(server.stdout.readline, b""):
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()
    finally:
        server.stdout.close()


def _parse(raw: bytes) -> dict | None:
    text = raw.strip()
    if not text:
        return None
    try:
        message = json.loads(text.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(message, dict):
        return None
    return message


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


def _close_stdin(server: subprocess.Popen) -> None:
    if server.stdin is None:
        return
    try:
        server.stdin.close()
    except OSError:
        pass
