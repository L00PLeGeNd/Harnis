"""Each major MCP client shape can be scanned and wrapped in place."""

from __future__ import annotations

import json
from pathlib import Path

from harnis.scan import apply_wraps, scan_config


def _assert_wrapped(entry: dict) -> None:
    assert entry["command"] == "npx"
    assert entry["args"][:5] == ["-y", "harnis", "mcp", "--preset", "github"]


def test_vscode_servers_object_is_wrapped(tmp_path: Path):
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "servers": {
                    "github": {"command": "github-mcp-server", "args": ["stdio"]}
                }
            }
        ),
        encoding="utf-8",
    )

    assert len(apply_wraps(config)) == 1
    data = json.loads(config.read_text(encoding="utf-8"))
    _assert_wrapped(data["servers"]["github"])
    assert scan_config(config) == []


def test_continue_array_shape_is_wrapped(tmp_path: Path):
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": [
                    {
                        "name": "github",
                        "command": "github-mcp-server",
                        "args": ["stdio"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert len(apply_wraps(config)) == 1
    data = json.loads(config.read_text(encoding="utf-8"))
    entry = data["mcpServers"][0]
    assert entry["name"] == "github"
    _assert_wrapped(entry)
    assert scan_config(config) == []


def test_claude_desktop_and_windsurf_shapes_are_wrapped(tmp_path: Path):
    claude = tmp_path / "claude_desktop_config.json"
    windsurf = tmp_path / "mcp_config.json"
    payload = {
        "mcpServers": {
            "github": {"command": "npx", "args": ["-y", "@github/github-mcp-server"]}
        }
    }
    claude.write_text(json.dumps(payload), encoding="utf-8")
    windsurf.write_text(json.dumps(payload), encoding="utf-8")

    assert len(apply_wraps(claude)) == 1
    assert len(apply_wraps(windsurf)) == 1
    for path in (claude, windsurf):
        data = json.loads(path.read_text(encoding="utf-8"))
        _assert_wrapped(data["mcpServers"]["github"])
        assert scan_config(path) == []


def test_claude_code_mcp_json_is_wrapped(tmp_path: Path):
    config = tmp_path / ".mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "github": {"command": "github-mcp-server", "args": ["stdio"]}
                }
            }
        ),
        encoding="utf-8",
    )

    findings = scan_config(config)
    assert len(findings) == 1
    assert findings[0].client == "config"
    assert len(apply_wraps(config)) == 1
    _assert_wrapped(json.loads(config.read_text(encoding="utf-8"))["mcpServers"]["github"])


def test_claude_json_project_servers_are_scanned_and_wrapped(tmp_path: Path):
    config = tmp_path / ".claude.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "github": {"command": "github-mcp-server", "args": ["stdio"]}
                },
                "projects": {
                    str(tmp_path): {
                        "mcpServers": {
                            "db": {
                                "command": "npx",
                                "args": ["-y", "postgres-mcp"],
                            }
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    findings = {item.server: item for item in scan_config(config)}
    assert "github" in findings
    assert "db" in findings
    assert findings["db"].preset == "postgres"
    apply_wraps(config)
    data = json.loads(config.read_text(encoding="utf-8"))
    _assert_wrapped(data["mcpServers"]["github"])
    db = data["projects"][str(tmp_path)]["mcpServers"]["db"]
    assert db["args"][1] == "harnis"
    assert db["args"][4] == "postgres"


def test_codex_toml_mcp_servers_are_wrapped(tmp_path: Path):
    config = tmp_path / "config.toml"
    config.write_text(
        "\n".join(
            [
                'model = "gpt-5"',
                "",
                "[mcp_servers.github]",
                'command = "github-mcp-server"',
                'args = ["stdio"]',
                "",
            ]
        ),
        encoding="utf-8",
    )

    findings = scan_config(config)
    assert len(findings) == 1
    assert findings[0].preset == "github"
    assert len(apply_wraps(config)) == 1
    text = config.read_text(encoding="utf-8")
    assert 'command = "npx"' in text
    assert "harnis" in text
    assert 'model = "gpt-5"' in text
    assert scan_config(config) == []


def test_project_init_wraps_claude_code_and_codex(
    tmp_path: Path, monkeypatch
):
    from harnis.project import init_project, status_report

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "github": {"command": "github-mcp-server", "args": ["stdio"]}
                }
            }
        ),
        encoding="utf-8",
    )
    codex = tmp_path / ".codex"
    codex.mkdir()
    (codex / "config.toml").write_text(
        "\n".join(
            [
                "[mcp_servers.db]",
                'command = "npx"',
                'args = ["-y", "postgres-mcp"]',
                "",
            ]
        ),
        encoding="utf-8",
    )

    report = init_project(apply=True, hooks=False)
    assert len(report.applied) == 2
    status = status_report()
    assert status.ready
    assert status.hooks == "n/a"


def test_default_scan_lists_claude_before_codex(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.delenv("APPDATA", raising=False)

    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {"mcpServers": {"github": {"command": "github-mcp-server", "args": ["stdio"]}}}
        ),
        encoding="utf-8",
    )
    (home / ".codex").mkdir()
    (home / ".codex" / "config.toml").write_text(
        "[mcp_servers.db]\ncommand = \"npx\"\nargs = [\"-y\", \"postgres-mcp\"]\n",
        encoding="utf-8",
    )

    findings = scan_config(None)
    clients = [item.client for item in findings]
    assert "claude-code" in clients
    assert "codex" in clients
    assert clients.index("claude-code") < clients.index("codex")
