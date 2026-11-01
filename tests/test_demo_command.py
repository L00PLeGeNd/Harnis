"""harnis demo prints a BLOCKED line without talking to a live MCP server."""

from harnis.cli import run


def test_demo_prints_a_blocked_github_delete(capsys):
    assert run(["demo"]) == 1
    err = capsys.readouterr().err
    assert "BLOCKED" in err
    assert "delete a file on GitHub" in err
    assert "github-delete" in err
