"""harnis init wires hooks/policy; status shows the protection posture."""

from __future__ import annotations

import json
from pathlib import Path

from harnis.cli import run


def test_init_writes_hooks_and_policy(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".cursor").mkdir()
    config = tmp_path / ".cursor" / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "github": {
                        "command": "github-mcp-server",
                        "args": ["stdio"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    assert run(["init"]) == 0
    out = capsys.readouterr().out.casefold()
    assert "hooks" in out
    assert "policy" in out

    hooks = json.loads((tmp_path / ".cursor" / "hooks.json").read_text(encoding="utf-8"))
    assert any(
        "harnis hook" in entry.get("command", "")
        for group in hooks["hooks"].values()
        for entry in group
    )
    policy = json.loads((tmp_path / ".harnis" / "policy.json").read_text(encoding="utf-8"))
    assert policy["deny_tools"] == []
    assert policy["empty_edit_limit"] == 5
    assert policy["max_tool_calls"] == 300
    assert policy["max_unique_paths"] == 80

    data = json.loads(config.read_text(encoding="utf-8"))
    assert data["mcpServers"]["github"]["args"][1] == "harnis"


def test_init_is_idempotent_and_keeps_foreign_hooks(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cursor = tmp_path / ".cursor"
    cursor.mkdir()
    (cursor / "hooks.json").write_text(
        json.dumps(
            {
                "version": 1,
                "hooks": {
                    "stop": [{"command": "echo done"}],
                    "beforeShellExecution": [{"command": "npx -y harnis hook"}],
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".harnis").mkdir()
    (tmp_path / ".harnis" / "policy.json").write_text(
        '{"empty_edit_limit": 9}\n', encoding="utf-8"
    )

    assert run(["init", "--no-apply"]) == 0
    out = capsys.readouterr().out.casefold()
    hooks = json.loads((cursor / "hooks.json").read_text(encoding="utf-8"))
    assert hooks["hooks"]["stop"] == [{"command": "echo done"}]
    assert len(hooks["hooks"]["beforeShellExecution"]) == 1
    policy = json.loads((tmp_path / ".harnis" / "policy.json").read_text(encoding="utf-8"))
    assert policy["empty_edit_limit"] == 9
    assert "already ok" in out


def test_status_reports_hooks_policy_and_bare_servers(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cursor = tmp_path / ".cursor"
    cursor.mkdir()
    (cursor / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "github": {"command": "github-mcp-server", "args": ["stdio"]}
                }
            }
        ),
        encoding="utf-8",
    )

    assert run(["status"]) == 1
    first = capsys.readouterr().out.casefold()
    assert "hooks: optional" in first
    assert "github" in first

    assert run(["init", "--no-apply"]) == 0
    capsys.readouterr()
    assert run(["status"]) == 1
    second = capsys.readouterr().out.casefold()
    assert "hooks: ok" in second
    assert "policy: ok" in second
    assert "unwrap" in second or "github" in second


def test_resolve_policy_prefers_env(tmp_path: Path, monkeypatch):
    from harnis.policy import resolve_policy_path

    custom = tmp_path / "custom.json"
    custom.write_text('{"empty_edit_limit": 2}\n', encoding="utf-8")
    monkeypatch.setenv("HARNIS_POLICY", str(custom))
    assert resolve_policy_path(None, tmp_path) == str(custom)
    assert resolve_policy_path(str(tmp_path / "explicit.json"), tmp_path) == str(
        tmp_path / "explicit.json"
    )


def test_hook_auto_loads_project_policy(tmp_path: Path, monkeypatch):
    from harnis.hook import handle_hook
    from harnis.policy import discover_policy, resolve_policy_path, rules_for

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HARNIS_POLICY", raising=False)
    (tmp_path / ".harnis").mkdir()
    (tmp_path / ".harnis" / "policy.json").write_text(
        '{"empty_edit_limit": 2}\n', encoding="utf-8"
    )
    path = discover_policy(tmp_path)
    assert path is not None
    assert resolve_policy_path(None, tmp_path) == str(path)
    rules = rules_for("coding-agent", str(path))
    state = tmp_path / "state"
    event = {
        "hook_event_name": "beforeMCPExecution",
        "conversation_id": "auto-policy",
        "tool_name": "write_file",
        "tool_input": {"path": "/work/a.py", "content": "x\n"},
    }
    assert handle_hook(event, rules, state_dir=state)["permission"] == "allow"
    assert handle_hook(event, rules, state_dir=state)["permission"] == "deny"


def test_status_ready_ignores_url_only_servers(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".harnis").mkdir()
    (tmp_path / ".harnis" / "policy.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / ".cursor" / "hooks.json").write_text(
        json.dumps(
            {
                "version": 1,
                "hooks": {
                    "beforeShellExecution": [{"command": "npx -y harnis hook"}],
                    "beforeMCPExecution": [{"command": "npx -y harnis hook"}],
                    "preToolUse": [{"command": "npx -y harnis hook"}],
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".cursor" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"remote": {"url": "https://example.com/mcp"}}}),
        encoding="utf-8",
    )

    assert run(["status"]) == 0
    out = capsys.readouterr().out.casefold()
    assert "posture: protected" in out
    assert "remote:" in out


def test_init_then_status_is_ready(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "github": {"command": "github-mcp-server", "args": ["stdio"]}
                }
            }
        ),
        encoding="utf-8",
    )

    assert run(["init"]) == 0
    capsys.readouterr()
    assert run(["status"]) == 0
    out = capsys.readouterr().out.casefold()
    assert "posture: protected" in out
    assert "unwrap: none" in out


def test_vscode_only_init_skips_hooks_and_still_protects(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    vscode = tmp_path / ".vscode"
    vscode.mkdir()
    (vscode / "mcp.json").write_text(
        json.dumps(
            {
                "servers": {
                    "github": {"command": "github-mcp-server", "args": ["stdio"]}
                }
            }
        ),
        encoding="utf-8",
    )

    assert run(["init", "--no-hooks"]) == 0
    out = capsys.readouterr().out.casefold()
    assert "hooks: skipped" in out
    assert not (tmp_path / ".cursor" / "hooks.json").exists()
    assert run(["status"]) == 0
    status = capsys.readouterr().out.casefold()
    assert "posture: protected" in status
    assert "hooks: n/a" in status
