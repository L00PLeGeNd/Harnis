"""Server presets deny mutating tool calls and leave ordinary reads alone."""

from harnis.policy import judge_tool_call, rules_for


def test_github_preset_blocks_delete_and_default_branch_writes():
    rules = rules_for("github")

    read = judge_tool_call(
        "get_file_contents",
        {"owner": "acme", "repo": "app", "path": "README.md"},
        rules,
    )
    deleted = judge_tool_call(
        "delete_file",
        {"owner": "acme", "repo": "app", "path": "README.md", "branch": "main"},
        rules,
    )
    onto_main = judge_tool_call(
        "push_files",
        {"owner": "acme", "repo": "app", "branch": "main", "files": []},
        rules,
    )
    omitted_branch = judge_tool_call(
        "create_or_update_file",
        {"owner": "acme", "repo": "app", "path": "README.md", "content": "x"},
        rules,
    )
    onto_feature = judge_tool_call(
        "push_files",
        {"owner": "acme", "repo": "app", "branch": "feature", "files": []},
        rules,
    )
    merge = judge_tool_call("merge_pull_request", {"owner": "acme", "repo": "app"}, rules)

    assert read.allowed
    assert deleted.allowed is False
    assert deleted.policy == "github-delete"
    assert onto_main.allowed is False
    assert onto_main.policy == "github-default-branch"
    assert omitted_branch.allowed is False
    assert omitted_branch.policy == "github-default-branch"
    assert onto_feature.allowed
    assert merge.allowed


def test_coding_agent_does_not_treat_delete_file_as_a_github_denial():
    decision = judge_tool_call(
        "delete_file",
        {"path": "/work/notes.txt"},
        rules_for("coding-agent"),
    )

    assert decision.allowed


def test_postgres_preset_blocks_writes_and_allows_a_select():
    rules = rules_for("postgres")

    select = judge_tool_call("postgres_mcp_query", {"sql": "SELECT id FROM users"}, rules)
    deleted_at = judge_tool_call(
        "query",
        {"sql": "SELECT deleted_at FROM users"},
        rules,
    )
    drop = judge_tool_call("postgres_mcp_query", {"sql": "DROP TABLE users"}, rules)
    modify = judge_tool_call("postgres_mcp_modify", {"sql": "SELECT 1"}, rules)

    assert select.allowed
    assert deleted_at.allowed
    assert drop.allowed is False
    assert drop.policy == "postgres-modify"
    assert modify.allowed is False
    assert modify.policy == "postgres-modify"


def test_slack_preset_blocks_a_post_that_carries_a_token():
    rules = rules_for("slack")
    token = "ghp_" + ("a" * 36)

    hello = judge_tool_call("slack_post_message", {"text": "hello"}, rules)
    leaked = judge_tool_call("slack_post_message", {"text": token}, rules)
    chat = judge_tool_call("chat_postMessage", {"text": token}, rules)

    assert hello.allowed
    assert leaked.allowed is False
    assert leaked.policy == "no-secret-exfil"
    assert chat.allowed is False


def test_github_preset_blocks_deleting_a_repository():
    rules = rules_for("github")
    decision = judge_tool_call(
        "delete_repository",
        {"owner": "acme", "repo": "app"},
        rules,
    )
    assert decision.allowed is False
    assert decision.policy == "github-delete"


def test_postgres_preset_accepts_execute_sql_alias():
    rules = rules_for("postgres")
    select = judge_tool_call("execute_sql", {"query": "SELECT 1"}, rules)
    drop = judge_tool_call("execute_sql", {"query": "DROP TABLE t"}, rules)
    assert select.allowed
    assert drop.allowed is False
