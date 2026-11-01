"""harnis scan reads an existing mcp.json and asks for a wrap."""

import json
import sys
from pathlib import Path

from harnis.cli import run
from harnis.scan import scan_config


def _write(path: Path, servers: dict) -> None:
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")


def test_bare_github_server_asks_for_the_github_preset(tmp_path: Path):
    config = tmp_path / "mcp.json"
    _write(
        config,
        {"github": {"command": "github-mcp-server", "args": ["stdio"]}},
    )

    findings = scan_config(config)

    assert len(findings) == 1
    assert findings[0].tool == "delete_file"
    assert findings[0].snippet["command"] == "npx"
    assert findings[0].snippet["args"] == [
        "-y",
        "harnis",
        "mcp",
        "--preset",
        "github",
        "--",
        "github-mcp-server",
        "stdio",
    ]
    assert "delete_file" in findings[0].sentence()


def test_wrapped_github_server_is_quiet(tmp_path: Path):
    config = tmp_path / "mcp.json"
    _write(
        config,
        {
            "github": {
                "command": "harnis",
                "args": ["mcp", "--preset", "github", "--", "github-mcp-server", "stdio"],
            }
        },
    )

    assert scan_config(config) == []


def test_npx_wrap_is_quiet(tmp_path: Path):
    config = tmp_path / "mcp.json"
    _write(
        config,
        {
            "github": {
                "command": "npx",
                "args": [
                    "-y",
                    "github:L00PLeGeNd/Harnis",
                    "mcp",
                    "--preset",
                    "github",
                    "--",
                    "github-mcp-server",
                    "stdio",
                ],
            }
        },
    )

    assert scan_config(config) == []


def test_python_module_wrap_is_quiet(tmp_path: Path):
    config = tmp_path / "mcp.json"
    _write(
        config,
        {
            "github": {
                "command": "python",
                "args": ["-m", "harnis", "mcp", "--preset", "github", "--", "github-mcp-server"],
            }
        },
    )

    assert scan_config(config) == []


def test_postgres_slack_and_shell_are_in_the_catalog(tmp_path: Path):
    config = tmp_path / "mcp.json"
    _write(
        config,
        {
            "db": {"command": "npx", "args": ["-y", "@microsoft/postgres-mcp"]},
            "chat": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-slack"]},
            "sh": {"command": "bash", "args": ["server.sh"]},
        },
    )

    findings = {item.server: item for item in scan_config(config)}

    assert findings["db"].preset == "postgres"
    assert findings["db"].tool == "postgres_mcp_modify"
    assert findings["chat"].preset == "slack"
    assert findings["sh"].preset == "coding-agent"
    assert findings["sh"].snippet["args"][-2:] == ["bash", "server.sh"]


def test_filesystem_server_is_quiet(tmp_path: Path):
    config = tmp_path / "mcp.json"
    _write(
        config,
        {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/work"],
            }
        },
    )

    assert scan_config(config) == []


def test_missing_config_is_quiet(tmp_path: Path):
    assert scan_config(tmp_path / "missing.json") == []


def test_official_github_image_keeps_its_env(tmp_path: Path):
    config = tmp_path / "mcp.json"
    _write(
        config,
        {
            "github": {
                "command": "docker",
                "args": [
                    "run",
                    "-i",
                    "--rm",
                    "-e",
                    "GITHUB_PERSONAL_ACCESS_TOKEN",
                    "ghcr.io/github/github-mcp-server:latest",
                ],
                "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "placeholder"},
            }
        },
    )

    findings = scan_config(config)

    assert len(findings) == 1
    assert findings[0].preset == "github"
    assert findings[0].snippet["args"][-1] == "ghcr.io/github/github-mcp-server:latest"
    assert findings[0].snippet["env"] == {"GITHUB_PERSONAL_ACCESS_TOKEN": "placeholder"}


def test_vscode_servers_key_is_seen(tmp_path: Path):
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "servers": {
                    "github": {
                        "command": "docker",
                        "args": ["run", "-i", "--rm", "ghcr.io/github/github-mcp-server"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    findings = scan_config(config)

    assert len(findings) == 1
    assert findings[0].tool == "delete_file"


def test_scan_defaults_to_the_cursor_config(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    config = tmp_path / ".cursor" / "mcp.json"
    config.parent.mkdir()
    _write(config, {"github": {"command": "github-mcp-server", "args": ["stdio"]}})

    findings = scan_config(None)

    assert len(findings) == 1
    assert findings[0].preset == "github"


def test_scan_reads_the_global_cursor_config_when_the_project_has_none(
    tmp_path: Path, monkeypatch
):
    project = tmp_path / "project"
    home = tmp_path / "home"
    project.mkdir()
    monkeypatch.chdir(project)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    config = home / ".cursor" / "mcp.json"
    config.parent.mkdir(parents=True)
    _write(config, {"github": {"command": "github-mcp-server", "args": ["stdio"]}})

    findings = scan_config(None)

    assert len(findings) == 1
    assert findings[0].preset == "github"


def test_scan_cli_exits_1_and_prints_the_snippet(tmp_path: Path, capsys):
    config = tmp_path / "mcp.json"
    _write(config, {"github": {"command": "github-mcp-server", "args": ["stdio"]}})

    assert run(["scan", str(config)]) == 1
    output = capsys.readouterr().out
    assert "delete_file" in output
    assert '"github"' in output
    assert run(["scan", str(tmp_path / "missing.json")]) == 0


def test_apply_wraps_the_github_server_and_keeps_a_backup(tmp_path: Path):
    from harnis.scan import apply_wraps

    config = tmp_path / "mcp.json"
    _write(config, {"github": {"command": "github-mcp-server", "args": ["stdio"]}})

    applied = apply_wraps(config)

    assert len(applied) == 1
    assert applied[0].tool == "delete_file"
    data = json.loads(config.read_text(encoding="utf-8"))
    entry = data["mcpServers"]["github"]
    assert entry["command"] == "npx"
    assert entry["args"][:5] == [
        "-y",
        "harnis",
        "mcp",
        "--preset",
        "github",
    ]
    assert entry["args"][-2:] == ["github-mcp-server", "stdio"]
    backup = json.loads((tmp_path / "mcp.json.bak").read_text(encoding="utf-8"))
    assert backup["mcpServers"]["github"]["command"] == "github-mcp-server"
    assert scan_config(config) == []


def test_apply_cli_rewrites_and_exits_0(tmp_path: Path, capsys):
    config = tmp_path / "mcp.json"
    _write(config, {"github": {"command": "github-mcp-server", "args": ["stdio"]}})

    assert run(["scan", "--apply", str(config)]) == 0
    output = capsys.readouterr().out
    assert "delete_file" in output
    assert "wrote" in output.casefold() or "wrapped" in output.casefold()
    assert scan_config(config) == []
    assert run(["scan", "--apply", str(config)]) == 0


def test_quiet_scan_names_the_files_it_checked(tmp_path: Path, capsys):
    config = tmp_path / "mcp.json"
    _write(
        config,
        {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/work"],
            }
        },
    )

    assert run(["scan", str(config)]) == 0
    err = capsys.readouterr().err
    assert "mcp.json" in err
    assert "no writable catalog server" in err.casefold() or "nothing to wrap" in err.casefold()


def test_scan_json_prints_findings_as_json(tmp_path: Path, capsys):
    config = tmp_path / "mcp.json"
    _write(config, {"github": {"command": "github-mcp-server", "args": ["stdio"]}})

    assert run(["scan", "--json", str(config)]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["server"] == "github"
    assert payload[0]["tool"] == "delete_file"
    assert payload[0]["snippet"]["args"][1] == "harnis"


def test_claude_desktop_config_is_scanned_by_default(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    if sys.platform == "win32":
        monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))
        config = tmp_path / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
    else:
        config = tmp_path / "home" / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    config.parent.mkdir(parents=True)
    _write(config, {"github": {"command": "github-mcp-server", "args": ["stdio"]}})

    findings = scan_config(None)

    assert len(findings) == 1
    assert findings[0].preset == "github"


def test_extra_github_and_postgres_package_names_are_seen(tmp_path: Path):
    config = tmp_path / "mcp.json"
    _write(
        config,
        {
            "gh": {
                "command": "npx",
                "args": ["-y", "@github/github-mcp-server"],
            },
            "db": {
                "command": "npx",
                "args": ["-y", "@crystaldba/postgres-mcp"],
            },
        },
    )

    findings = {item.server: item for item in scan_config(config)}

    assert findings["gh"].preset == "github"
    assert findings["db"].preset == "postgres"


def test_browser_and_email_package_names_are_seen(tmp_path: Path):
    config = tmp_path / "mcp.json"
    _write(
        config,
        {
            "web": {
                "command": "npx",
                "args": ["-y", "@playwright/mcp"],
            },
            "mail": {
                "command": "npx",
                "args": ["-y", "@gongrzhe/server-gmail-autoauth-mcp"],
            },
        },
    )

    findings = {item.server: item for item in scan_config(config)}

    assert findings["web"].preset == "browser"
    assert findings["web"].tool == "browser_evaluate"
    assert findings["mail"].preset == "email"
    assert findings["mail"].tool == "send_email"


def test_windsurf_cline_and_continue_configs_are_scanned(
    tmp_path: Path, monkeypatch
):
    from harnis.scan import apply_wraps

    home = tmp_path / "home"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.delenv("APPDATA", raising=False)

    windsurf = home / ".codeium" / "windsurf" / "mcp_config.json"
    windsurf.parent.mkdir(parents=True)
    _write(windsurf, {"github": {"command": "github-mcp-server", "args": ["stdio"]}})

    cline = home / ".cline" / "data" / "settings" / "cline_mcp_settings.json"
    cline.parent.mkdir(parents=True)
    _write(cline, {"db": {"command": "npx", "args": ["-y", "postgres-mcp"]}})

    continue_cfg = home / ".continue" / "config.json"
    continue_cfg.parent.mkdir(parents=True)
    continue_cfg.write_text(
        json.dumps(
            {
                "mcpServers": [
                    {
                        "name": "slack",
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-slack"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = scan_config(None)
    by_client = {(f.client, f.server): f for f in findings}

    assert ("windsurf", "github") in by_client
    assert ("cline", "db") in by_client
    assert ("continue", "slack") in by_client

    applied = apply_wraps(None)
    assert len(applied) == 3
    cont = json.loads(continue_cfg.read_text(encoding="utf-8"))
    assert cont["mcpServers"][0]["command"] == "npx"
    assert cont["mcpServers"][0]["name"] == "slack"
    assert cont["mcpServers"][0]["args"][1] == "harnis"


def test_url_only_server_is_reported_but_not_applied(tmp_path: Path):
    from harnis.scan import apply_wraps

    config = tmp_path / "mcp.json"
    _write(
        config,
        {
            "remote": {"url": "https://example.com/mcp"},
            "github": {"command": "github-mcp-server", "args": ["stdio"]},
        },
    )

    findings = scan_config(config)
    assert any(f.server == "remote" and f.wrapable is False for f in findings)
    assert any(f.server == "github" and f.wrapable for f in findings)

    apply_wraps(config)
    data = json.loads(config.read_text(encoding="utf-8"))
    assert data["mcpServers"]["remote"] == {"url": "https://example.com/mcp"}
    assert data["mcpServers"]["github"]["args"][1] == "harnis"
