# Harnis

Local **stdio MCP seatbelt**: judge `tools/call` and path-like `resources/read` before the server sees them. A denial never reaches the child process.

```bash
npx -y github:L00PLeGeNd/Harnis mcp --preset github -- github-mcp-server stdio
```

```text
🚨 BLOCKED: agent attempted to delete a file on GitHub — … (policy: github-delete)
```

Thirty-second wrap of a config you already have:

```bash
npx -y github:L00PLeGeNd/Harnis init
npx -y github:L00PLeGeNd/Harnis status
```

**Python 3.11+.** `npx` only clones this repo and runs `python -m harnis`. Install comes from **GitHub** (tracks `main`); the npm name may lag and is optional.

Read the [threat model](THREAT_MODEL.md) before treating this as a sandbox. URL MCP, unresolvable symlinks, renamed tools with no credential args, and anything that never passes through `harnis mcp` are out of scope.

---

## What it does

| Piece | Role |
| --- | --- |
| `harnis mcp` | Stdio JSON-RPC proxy; blocks matched `tools/call` / `resources/read` |
| `harnis init` / `status` | Project policy + wrap local MCP configs |
| `harnis scan [--apply]` | Find bare catalog servers; optional in-place wrap |
| `harnis hook` | Optional editor hook adapter (same policy) |
| `harnis protect` / `probe` | Best-effort Python / transcript checks — see threat model |

Primary presets:

| Preset | Denies (examples) |
| --- | --- |
| `coding-agent` (default) | Credential paths (any tool args), opaque/encoded shell, `rm -rf`, secret-shaped text |
| `github` | `delete_file` / `delete_repository`; writes to default branch |
| `readonly` | Writes, shell, outbound sends |
| `ci` | Every shell call |

Extra presets (`postgres`, `slack`, `browser`, `email`) remain in code for experiments; they are not the product.

Session budgets (optional, via `.harnis/policy.json`): `empty_edit_limit`, `max_tool_calls`, `max_unique_paths`.

`scan` understands Claude Code / Desktop first, then Codex (`config.toml`), then common editor MCP files. Remote `url` servers are reported and **not** wrapped.

---

## Policy file

```json
{
  "deny_path_parts": ["vault"],
  "deny_file_names": ["token.txt"],
  "allow_path_parts": ["fixtures"],
  "deny_tools": ["remove_repo_file"],
  "empty_edit_limit": 5,
  "max_tool_calls": 200,
  "max_unique_paths": 80
}
```

`deny_tools` is how a project closes renamed-tool gaps that presets miss. Credential paths and secret-shaped strings are scanned in **every** `tools/call` argument tree regardless of tool name.

```bash
npx -y github:L00PLeGeNd/Harnis mcp --policy .harnis/policy.json --preset coding-agent -- <server>
```

---

## Develop

```bash
python -m pip install -e . pytest
python -m pytest -q
python -m pytest tests/test_adversarial.py tests/test_control_plane.py -q
```

MIT.
