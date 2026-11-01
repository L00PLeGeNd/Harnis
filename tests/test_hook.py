"""Cursor agent hooks reuse Harnis policy and session budget."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from harnis.cli import run
from harnis.hook import handle_hook
from harnis.policy import rules_for


def test_before_shell_hook_blocks_credential_cat():
    result = handle_hook(
        {
            "hook_event_name": "beforeShellExecution",
            "conversation_id": "conv-1",
            "command": "cat ~/.ssh/id_rsa",
        },
        rules_for("coding-agent"),
    )
    assert result["permission"] == "deny"
    assert "no-credential-access" in result["agent_message"]


def test_before_mcp_hook_applies_edit_budget(tmp_path: Path):
    policy = tmp_path / "policy.json"
    policy.write_text('{"empty_edit_limit": 2}\n', encoding="utf-8")
    rules = rules_for("coding-agent", str(policy))
    state = tmp_path / "state"
    event = {
        "hook_event_name": "beforeMCPExecution",
        "conversation_id": "conv-budget",
        "tool_name": "write_file",
        "tool_input": {"path": "/work/a.py", "content": "x\n"},
    }
    assert handle_hook(event, rules, state_dir=state)["permission"] == "allow"
    second = handle_hook(event, rules, state_dir=state)
    assert second["permission"] == "deny"
    assert "no-edit-thrash" in second["agent_message"]


def test_pre_tool_use_write_respects_max_tool_calls(tmp_path: Path):
    policy = tmp_path / "policy.json"
    policy.write_text('{"max_tool_calls": 1}\n', encoding="utf-8")
    rules = rules_for("coding-agent", str(policy))
    state = tmp_path / "state"
    first = handle_hook(
        {
            "hook_event_name": "preToolUse",
            "conversation_id": "conv-calls",
            "tool_name": "Read",
            "tool_input": {"path": "/work/a.py"},
        },
        rules,
        state_dir=state,
    )
    second = handle_hook(
        {
            "hook_event_name": "preToolUse",
            "conversation_id": "conv-calls",
            "tool_name": "Read",
            "tool_input": {"path": "/work/b.py"},
        },
        rules,
        state_dir=state,
    )
    assert first["permission"] == "allow"
    assert second["permission"] == "deny"
    assert "no-tool-budget" in second["agent_message"]


def test_hook_cli_reads_stdin(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    event = json.dumps(
        {
            "hook_event_name": "beforeShellExecution",
            "conversation_id": "cli",
            "command": "echo hi",
        }
    )
    monkeypatch.setattr(sys, "stdin", __import__("io").StringIO(event))
    assert run(["hook"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["permission"] == "allow"
