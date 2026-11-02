"""Session edit budget stops thrashing writes with no substantive change."""

from __future__ import annotations


def _write(path: str, content: str, call_id: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": path, "content": content},
        },
    }


def test_five_empty_rewrites_of_the_same_file_are_blocked():
    from harnis.budget import EditBudget
    from harnis.mcp_proxy import handle_client_message
    from harnis.policy import Rules

    budget = EditBudget(empty_edit_limit=5)
    rules = Rules()
    path = "/work/app.py"
    body = "def main():\n    return 1\n"

    for index in range(4):
        assert handle_client_message(_write(path, body, index), rules, budget) is None

    blocked = handle_client_message(_write(path, body, 5), rules, budget)
    assert blocked is not None
    assert blocked["result"]["isError"] is True
    text = blocked["result"]["content"][0]["text"]
    assert "no-edit-thrash" in text
    assert "5 times" in text
    assert "limit 5" in text
    assert "BLOCKED" in text


def test_a_substantive_rewrite_resets_the_empty_edit_counter():
    from harnis.budget import EditBudget
    from harnis.mcp_proxy import handle_client_message
    from harnis.policy import Rules

    budget = EditBudget(empty_edit_limit=3)
    rules = Rules()
    path = "/work/app.py"

    assert handle_client_message(_write(path, "v1\n", 1), rules, budget) is None
    assert handle_client_message(_write(path, "v1\n", 2), rules, budget) is None
    assert handle_client_message(_write(path, "version two with real work\n", 3), rules, budget) is None
    assert handle_client_message(_write(path, "version two with real work\n", 4), rules, budget) is None
    blocked = handle_client_message(_write(path, "version two with real work\n", 5), rules, budget)
    assert blocked is not None
    assert "no-edit-thrash" in blocked["result"]["content"][0]["text"]


def test_whitespace_only_change_counts_as_empty():
    from harnis.budget import EditBudget
    from harnis.mcp_proxy import handle_client_message
    from harnis.policy import Rules

    budget = EditBudget(empty_edit_limit=2)
    rules = Rules()
    path = "/work/app.py"

    assert handle_client_message(_write(path, "x = 1\n", 1), rules, budget) is None
    blocked = handle_client_message(_write(path, "x = 1\n\n", 2), rules, budget)
    assert blocked is not None
    assert "no-edit-thrash" in blocked["result"]["content"][0]["text"]


def test_other_files_do_not_share_the_counter():
    from harnis.budget import EditBudget
    from harnis.mcp_proxy import handle_client_message
    from harnis.policy import Rules

    budget = EditBudget(empty_edit_limit=2)
    rules = Rules()

    assert handle_client_message(_write("/work/a.py", "a\n", 1), rules, budget) is None
    blocked_a = handle_client_message(_write("/work/a.py", "a\n", 2), rules, budget)
    assert blocked_a is not None
    assert handle_client_message(_write("/work/b.py", "a\n", 3), rules, budget) is None
    blocked_b = handle_client_message(_write("/work/b.py", "a\n", 4), rules, budget)
    assert blocked_b is not None


def test_policy_file_sets_empty_edit_limit(tmp_path):
    from harnis.budget import EditBudget
    from harnis.mcp_proxy import handle_client_message
    from harnis.policy import rules_for

    policy = tmp_path / "policy.json"
    policy.write_text('{"empty_edit_limit": 2}\n', encoding="utf-8")
    rules = rules_for("coding-agent", str(policy))
    budget = EditBudget.from_rules(rules)

    assert handle_client_message(_write("/work/a.py", "x\n", 1), rules, budget) is None
    blocked = handle_client_message(_write("/work/a.py", "x\n", 2), rules, budget)
    assert blocked is not None
    assert "no-edit-thrash" in blocked["result"]["content"][0]["text"]


def test_max_tool_calls_stops_a_runaway_session():
    from harnis.budget import EditBudget
    from harnis.mcp_proxy import handle_client_message
    from harnis.policy import Rules

    budget = EditBudget(max_tool_calls=2)
    rules = Rules()
    read = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/work/a.py"}},
    }

    assert handle_client_message({**read, "id": 1}, rules, budget) is None
    assert handle_client_message({**read, "id": 2}, rules, budget) is None
    blocked = handle_client_message({**read, "id": 3}, rules, budget)
    assert blocked is not None
    assert "no-tool-budget" in blocked["result"]["content"][0]["text"]


def test_policy_file_sets_max_tool_calls(tmp_path):
    from harnis.budget import EditBudget
    from harnis.mcp_proxy import handle_client_message
    from harnis.policy import rules_for

    policy = tmp_path / "policy.json"
    policy.write_text('{"max_tool_calls": 1}\n', encoding="utf-8")
    rules = rules_for("coding-agent", str(policy))
    budget = EditBudget.from_rules(rules)
    read = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/work/a.py"}},
    }

    assert handle_client_message(read, rules, budget) is None
    blocked = handle_client_message({**read, "id": 2}, rules, budget)
    assert blocked is not None
    assert "no-tool-budget" in blocked["result"]["content"][0]["text"]


def test_max_unique_paths_stops_directory_wandering():
    from harnis.budget import EditBudget
    from harnis.mcp_proxy import handle_client_message
    from harnis.policy import Rules

    budget = EditBudget(max_unique_paths=2)
    rules = Rules()

    def read(path: str, call_id: int) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": call_id,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": path}},
        }

    assert handle_client_message(read("/work/a.py", 1), rules, budget) is None
    assert handle_client_message(read("/work/b.py", 2), rules, budget) is None
    assert handle_client_message(read("/work/a.py", 3), rules, budget) is None
    blocked = handle_client_message(read("/work/c.py", 4), rules, budget)
    assert blocked is not None
    assert "no-path-wander" in blocked["result"]["content"][0]["text"]
