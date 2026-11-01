# Examples

Prove Harnis without a live MCP server:

```bash
npx -y harnis demo
npx -y harnis probe --transcript examples/blocked-session.jsonl --preset github
```

`policy.json` is a starter project policy (`empty_edit_limit`, `max_tool_calls`, `max_unique_paths`).
`hooks.json` is optional editor-hook wiring for clients that support it.
