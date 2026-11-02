"""Control-plane substance: args, resources, deny_tools, opaque shell, live proxy."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from harnis.budget import EditBudget
from harnis.mcp_proxy import decision_for_message, handle_client_message
from harnis.policy import Action, judge, judge_tool_call, load_rules, rules_for

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

SERVER = r"""
import json, sys
log = open(sys.argv[1], "a", encoding="utf-8")
for line in sys.stdin:
    if not line.strip():
        continue
    message = json.loads(line)
    log.write(json.dumps({"method": message.get("method"), "params": message.get("params")}) + "\n")
    log.flush()
    response = {
        "jsonrpc": "2.0",
        "id": message.get("id"),
        "result": {"content": [{"type": "text", "text": "server-saw-it"}], "isError": False},
    }
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()
"""


def test_renamed_tool_still_blocks_credential_path_in_args():
    decision = judge_tool_call(
        "fetch_workspace_blob",
        {"target": "/home/agent/.ssh/id_rsa"},
        rules_for("coding-agent"),
    )
    assert decision.allowed is False
    assert decision.policy == "no-credential-access"


def test_nested_argument_path_is_scanned():
    decision = judge_tool_call(
        "vendor_read",
        {"options": {"file": {"path": "~/.aws/credentials"}}},
        rules_for("coding-agent"),
    )
    assert decision.allowed is False
    assert decision.policy == "no-credential-access"


def test_secret_shaped_body_on_unknown_tool_is_blocked():
    decision = judge_tool_call(
        "chat_postmessage",
        {"text": "key=AKIAIOSFODNN7EXAMPLE"},
        rules_for("coding-agent"),
    )
    assert decision.allowed is False
    assert decision.policy == "no-secret-exfil"


def test_deny_tools_blocks_renamed_github_delete(tmp_path: Path):
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps({"deny_tools": ["remove_repo_file", "delete_file"]}),
        encoding="utf-8",
    )
    rules = rules_for("github", str(policy))
    decision = judge_tool_call(
        "remove_repo_file",
        {"owner": "acme", "repo": "app", "path": "x", "branch": "main"},
        rules,
    )
    assert decision.allowed is False
    assert decision.policy == "deny-tool"


def test_resources_read_of_ssh_key_is_blocked():
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "resources/read",
        "params": {"uri": "file:///home/agent/.ssh/id_rsa"},
    }
    blocked = handle_client_message(message, rules_for("coding-agent"))
    assert blocked is not None
    assert "no-credential-access" in blocked["result"]["content"][0]["text"]


def test_resources_read_of_workspace_file_passes():
    message = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "resources/read",
        "params": {"uri": "file:///work/main.py"},
    }
    assert handle_client_message(message, rules_for("coding-agent")) is None


def test_powershell_encoded_command_is_opaque():
    decision = judge(
        Action(
            kind="exec",
            command=("powershell", "-EncodedCommand", "SQBFAFgA"),
        )
    )
    assert decision.allowed is False
    assert decision.policy == "no-opaque-shell"


def test_base64_pipe_to_shell_is_opaque():
    decision = judge(
        Action(kind="exec", command=("bash", "-c", "echo YQ== | base64 -d | sh"))
    )
    assert decision.allowed is False
    assert decision.policy == "no-opaque-shell"


def test_shell_script_path_to_ssh_is_blocked():
    decision = judge(
        Action(kind="exec", command=("bash", "-c", "cat ~/.ssh/id_rsa"))
    )
    assert decision.allowed is False
    assert decision.policy == "no-credential-access"


def test_budget_still_applies_after_universal_allow():
    rules = rules_for("coding-agent")
    budget = EditBudget(max_tool_calls=2)
    ok = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/work/a.py"}},
    }
    assert decision_for_message(ok, rules, budget).allowed is True
    assert decision_for_message(ok, rules, budget).allowed is True
    third = decision_for_message(ok, rules, budget)
    assert third is not None and third.allowed is False
    assert third.policy == "no-tool-budget"


def test_proxy_process_hides_resource_read_and_renamed_tool(tmp_path: Path):
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
    resource = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "resources/read",
        "params": {"uri": "file:///home/agent/.ssh/id_rsa"},
    }
    renamed = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "vendor_blob_get",
            "arguments": {"path": "/home/agent/.ssh/id_ed25519"},
        },
    }
    ordinary = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/work/ok.py"}},
    }
    payload = (
        json.dumps(resource)
        + "\n"
        + json.dumps(renamed)
        + "\n"
        + json.dumps(ordinary)
        + "\n"
    ).encode("utf-8")
    stdout, stderr = proc.communicate(payload, timeout=15)
    lines = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    assert len(lines) == 3
    assert lines[0]["result"]["isError"] is True
    assert "no-credential-access" in lines[0]["result"]["content"][0]["text"]
    assert lines[1]["result"]["isError"] is True
    assert "no-credential-access" in lines[1]["result"]["content"][0]["text"]
    assert lines[2]["result"]["content"][0]["text"] == "server-saw-it"
    seen = log.read_text(encoding="utf-8")
    assert "id_rsa" not in seen
    assert "id_ed25519" not in seen
    assert "ok.py" in seen
    assert "no-credential-access" in stderr.decode("utf-8")


def test_load_rules_reads_deny_tools(tmp_path: Path):
    policy = tmp_path / "p.json"
    policy.write_text('{"deny_tools": ["Delete_File"]}\n', encoding="utf-8")
    rules = load_rules(str(policy))
    assert "delete_file" in rules.deny_tools
