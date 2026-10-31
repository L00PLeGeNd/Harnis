"""MCP stdio proxy judges tools/call before the server sees it."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

SERVER = r"""
import json, sys
log = open(sys.argv[1], "a", encoding="utf-8")
for line in sys.stdin:
    if not line.strip():
        continue
    message = json.loads(line)
    log.write(json.dumps(message.get("params")) + "\n")
    log.flush()
    response = {
        "jsonrpc": "2.0",
        "id": message.get("id"),
        "result": {"content": [{"type": "text", "text": "server-saw-it"}], "isError": False},
    }
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()
"""


def test_blocked_tool_call_never_reaches_the_server(tmp_path: Path):
    from harnis.mcp_proxy import handle_client_message
    from harnis.policy import Rules

    message = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "read_text_file",
            "arguments": {"path": "/home/agent/.ssh/id_rsa"},
        },
    }

    response = handle_client_message(message, Rules())

    assert response is not None
    assert response["id"] == 7
    assert response["result"]["isError"] is True
    text = response["result"]["content"][0]["text"]
    assert "no-credential-access" in text
    assert "BLOCKED" in text


def test_workspace_read_is_forwarded():
    from harnis.mcp_proxy import handle_client_message
    from harnis.policy import Rules

    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_text_file", "arguments": {"path": "/work/main.py"}},
    }

    assert handle_client_message(message, Rules()) is None


def test_readonly_preset_blocks_a_normal_write():
    from harnis.mcp_proxy import handle_client_message
    from harnis.policy import rules_for

    message = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "/work/notes.txt"}},
    }

    response = handle_client_message(message, rules_for("readonly"))

    assert response is not None
    assert response["result"]["isError"] is True
    assert "readonly" in response["result"]["content"][0]["text"]


def test_ci_preset_blocks_a_shell_that_coding_agent_allows():
    from harnis.mcp_proxy import handle_client_message
    from harnis.policy import rules_for

    message = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {"name": "shell", "arguments": {"command": "echo hello"}},
    }

    blocked = handle_client_message(message, rules_for("ci"))
    assert blocked is not None
    assert "ci-no-shell" in blocked["result"]["content"][0]["text"]
    assert handle_client_message(message, rules_for("coding-agent")) is None


def test_filesystem_server_cannot_list_a_credential_directory():
    from harnis.mcp_proxy import handle_client_message
    from harnis.policy import Rules

    listing = {
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "list_directory",
            "arguments": {"path": "/home/agent/.ssh"},
        },
    }
    workspace = {
        "jsonrpc": "2.0",
        "id": 12,
        "method": "tools/call",
        "params": {"name": "list_directory", "arguments": {"path": "/work"}},
    }
    info = {
        "jsonrpc": "2.0",
        "id": 13,
        "method": "tools/call",
        "params": {
            "name": "get_file_info",
            "arguments": {"path": "/home/agent/.ssh/id_rsa"},
        },
    }

    blocked = handle_client_message(listing, Rules())
    assert blocked is not None
    assert "no-credential-access" in blocked["result"]["content"][0]["text"]
    assert handle_client_message(workspace, Rules()) is None
    info_blocked = handle_client_message(info, Rules())
    assert info_blocked is not None
    assert "no-credential-access" in info_blocked["result"]["content"][0]["text"]


def test_coding_agent_preset_allows_a_normal_write():
    from harnis.mcp_proxy import handle_client_message
    from harnis.policy import rules_for

    message = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "/work/notes.txt"}},
    }

    assert handle_client_message(message, rules_for("coding-agent")) is None


def test_proxy_process_hides_a_secret_read_from_the_server(tmp_path: Path):
    log = tmp_path / "seen.jsonl"
    script = tmp_path / "server.py"
    script.write_text(SERVER, encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUTF8"] = "1"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "harnis",
            "mcp",
            "--report",
            str(tmp_path / "mcp.html"),
            "--",
            sys.executable,
            str(script),
            str(log),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    assert proc.stdin is not None and proc.stdout is not None
    secret = {
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "/home/agent/.ssh/id_rsa"},
        },
    }
    ordinary = {
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/work/main.py"}},
    }
    proc.stdin.write((json.dumps(secret) + "\n").encode("utf-8"))
    proc.stdin.write((json.dumps(ordinary) + "\n").encode("utf-8"))
    proc.stdin.close()
    stdout, stderr = proc.communicate(timeout=15)

    blocked = json.loads(stdout.splitlines()[0].decode("utf-8"))
    allowed = json.loads(stdout.splitlines()[1].decode("utf-8"))
    assert blocked["result"]["isError"] is True
    assert "no-credential-access" in blocked["result"]["content"][0]["text"]
    assert allowed["result"]["content"][0]["text"] == "server-saw-it"
    seen = log.read_text(encoding="utf-8")
    assert "id_rsa" not in seen
    assert "main.py" in seen
    assert "no-credential-access" in stderr.decode("utf-8")
    page = (tmp_path / "mcp.html").read_text(encoding="utf-8")
    assert "no-credential-access" in page
