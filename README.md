# Harnis

[![npm](https://img.shields.io/npm/v/harnis.svg)](https://www.npmjs.com/package/harnis)
[![CI](https://github.com/L00PLeGeNd/Harnis/actions/workflows/ci.yml/badge.svg)](https://github.com/L00PLeGeNd/Harnis/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Install once. Stay protected while the agent works.

```bash
npx -y harnis init
npx -y harnis status
```

If the npm latest lag behind GitHub, use the repo directly:

```bash
npx -y github:L00PLeGeNd/Harnis init
```

If the npm latest lag behind GitHub, use the repo directly:

```bash
npx -y github:L00PLeGeNd/Harnis init
```

```text
hooks: wrote (.cursor/hooks.json)
policy: wrote (.harnis/policy.json)
wrapped github in .cursor/mcp.json
next: npx -y harnis status
```

`init` wires Cursor hooks, drops a project policy (edit thrash + tool-call budget), and wraps dangerous MCP servers behind Harnis. `status` is the daily check: hooks, policy, anything still bare.

```bash
npx -y harnis demo
```

```text
🚨 BLOCKED: agent attempted to delete a file on GitHub (policy: github-delete)
```

Python 3.11+. Filesystem servers stay alone. `scan --apply` still works alone; `--json` is for scripts. Scans Cursor, VS Code, Claude Desktop, Windsurf, Continue, Cline, and Roo. URL-only MCP servers are reported but not wrapped.

```yaml
- uses: L00PLeGeNd/Harnis/.github/actions/scan@main
- uses: L00PLeGeNd/Harnis/.github/actions/status@main
```

---

## Proxy

Judges `tools/call` before the server sees it. A denial never reaches the server — the client gets a tool error, the terminal prints one line, and `harnis-mcp.html` records it. `initialize` and `tools/list` pass through.

Within one proxy session, near-identical rewrites of the same file (including whitespace-only churn) are denied after five hits (`no-edit-thrash`). Set `empty_edit_limit` and optional `max_tool_calls` in the policy file to tune the session budget.

`harnis init` writes `.cursor/hooks.json` for you (`beforeShellExecution`, `beforeMCPExecution`, `preToolUse`). Session budget state lives under the temp dir, keyed by `conversation_id`. Project policy is auto-loaded from `.harnis/policy.json` (or `HARNIS_POLICY`).

```bash
npx -y harnis mcp --preset github -- github-mcp-server stdio
```

```text
🚨 BLOCKED: agent attempted to delete a file on GitHub (policy: github-delete)
```

| Preset | Allows | Denies |
| --- | --- | --- |
| `github` | File and issue reads, feature-branch writes, `merge_pull_request` | `delete_file`, `delete_repository`; writes to `main` / `master` / omitted branch |
| `postgres` | `SELECT` / `WITH` / `EXPLAIN` / `SHOW` | `postgres_mcp_modify` / `modify`; mutating SQL via `query` / `execute_sql` / … |
| `slack` | Ordinary posts | Posts (`slack_post_message`, `chat_postMessage`, …) that carry a key or token |
| `browser` | Clicks, screenshots, `https` navigation | `browser_evaluate` / page JS; `file://` navigation |
| `email` | List / read mail | `send_email`, `create_draft`, and other send tools |
| `coding-agent` | Workspace read and write | Credential paths, `rm -rf`, unbounded / opaque shell, secret bodies |
| `readonly` | Non-credential reads | Writes, shell, outbound sends |
| `ci` | Same file rules as coding-agent | Every shell call |

The wrap keeps the server's `env`. Remote `url` entries stay as-is.

---

## Policy

| Action | Policy |
| --- | --- |
| `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, private keys, `.env` | `no-credential-access` |
| `rm -rf` (including `bash -c` / `os.system`) | `no-destructive-exec` |
| Shell with no script (`cmd`, `powershell`, `bash`) | `no-unbounded-shell` |
| Path hidden with `%VAR%`, `^`, `[char]`, base64 | `no-opaque-shell` |
| `ctypes` resolving `CreateFileW`, `open`, `execve`, … | `no-ctypes-bypass` |
| HTTP / socket body with a private key, `AKIA…`, or `ghp_…` | `no-secret-exfil` |

On a filesystem server, `list_directory`, `directory_tree`, `search_files`, and `get_file_info` count as reads — listing `~/.ssh` is denied, listing `/work` is allowed. `create_directory` is a write.

```json
{
  "deny_path_parts": ["vault"],
  "deny_file_names": ["token.txt"],
  "allow_path_parts": ["fixtures"],
  "empty_edit_limit": 5,
  "max_tool_calls": 200
}
```

```bash
harnis mcp --policy policy.json -- npx -y @modelcontextprotocol/server-filesystem /work
```

`allow_path_parts` wins when a path segment matches.

---

## Probe

Same `tools/call` decision as the proxy. Reports the call. Does not run it. Does not attack other systems.

```bash
harnis probe --transcript session.jsonl
harnis probe -- examples/leaky_agent.py
harnis probe --scenario rag -- examples/rag_agent.py
harnis probe --url http://127.0.0.1:8765/v1/chat --scenario credential,destructive
```

Scenarios: `credential`, `destructive`, `rag`, `escalation`, `exfil`, `all`. Findings → `harnis-probe.html`.

```yaml
- uses: L00PLeGeNd/Harnis/.github/actions/probe@main
  with:
    agent: examples/leaky_agent.py
```

---

## Protect

In-process guard for a Python agent. Denial raises `PermissionError` before the call returns. Exit is non-zero if anything was blocked — even if the agent catches it. Report → `harnis-report.html`.

```bash
harnis protect -- python examples/curious_agent.py
```

```text
🚨 BLOCKED: agent attempted to run rm -rf /tmp/harnis-scratch (policy: no-destructive-exec)
🚨 BLOCKED: agent attempted to send secrets to https://collect.example/upload (policy: no-secret-exfil)
```

Covers CPython `open`, `subprocess`, `os.system`, `urllib`, `http.client`, `ssl.SSLSocket.send`, and child Python processes. Linux x86_64 non-Python commands use ptrace. On Windows, use the Python form.

```python
from harnis import judge_tool_call

decision = judge_tool_call("read_file", {"path": "/home/me/.ssh/id_rsa"})
decision.allowed  # False
decision.line()
```

---

## Limits

Raw-address `ctypes` is outside the audit hook. `shell=True` children are not re-injected. Probe does not generate exploits.

## Development

```bash
pip install -e .
python -m pytest
```

MIT · [LICENSE](LICENSE)
