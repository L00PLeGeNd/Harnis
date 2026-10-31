# Harnis

Harnis reads the MCP config you already have. A GitHub, Postgres, Slack, or shell server that is not wrapped gets one sentence and a block you can paste back. A filesystem server is left alone.

Requires Python 3.11+.

```bash
npx -y github:L00PLeGeNd/Harnis scan
```

With no path it reads `.cursor/mcp.json`. Pass a path to read another file. A missing file exits 0. A bare catalog server exits 1.

```text
github can call delete_file.
{
  "command": "npx",
  "args": ["-y", "github:L00PLeGeNd/Harnis", "mcp", "--preset", "github", "--", "github-mcp-server", "stdio"]
}
```

In GitHub Actions a missing config succeeds and a bare catalog server fails the job:

```yaml
- uses: L00PLeGeNd/Harnis/.github/actions/scan@main
```

## In front of a server

The pasted block is a stdio proxy. It judges `tools/call` before the server runs it. A denied call never reaches the server: the client gets a tool error, and the terminal prints one line. That line is also written to `harnis-mcp.html`. `initialize` and `tools/list` pass through unchanged.

```bash
npx -y github:L00PLeGeNd/Harnis mcp --preset github -- github-mcp-server stdio
```

```text
🚨 BLOCKED: agent attempted to delete a file on GitHub (policy: github-delete)
```

| Preset | What it does |
| --- | --- |
| `github` | Reads of files and issues stay open. `delete_file` is denied. Writes to `main`, `master`, or an omitted branch are denied |
| `postgres` | Read-only SQL stays open. `postgres_mcp_modify`, `DROP`, `TRUNCATE`, and `DELETE` are denied |
| `slack` | Ordinary posts stay open. A post carrying a key or token is denied |
| `coding-agent` | Default for other servers. Workspace read and write stay open. Credential paths, `rm -rf`, an unbounded or opaque shell, and a body carrying a key or token are denied |
| `readonly` | Reads that are not credentials. Writes, shell, and outbound sends are denied |
| `ci` | The coding-agent file rules, plus every shell call |

```bash
harnis mcp --preset readonly -- npx -y @modelcontextprotocol/server-filesystem /work
```

## What gets denied

| Action | Policy |
| --- | --- |
| Read or write `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, private key files, `.env` | `no-credential-access` |
| `rm -rf`, including through `bash -c` and `os.system` | `no-destructive-exec` |
| A shell with no script (`cmd`, `powershell`, `bash`). The next command could come from stdin | `no-unbounded-shell` |
| A shell script that hides the path with variables, `^`, `[char]`, or base64 | `no-opaque-shell` |
| `ctypes` resolving file or process APIs such as `CreateFileW`, `open`, or `execve` | `no-ctypes-bypass` |
| An HTTP body, header, or socket send carrying a private key, an `AKIA…` key, or a `ghp_…` token | `no-secret-exfil` |

On the filesystem server, `list_directory`, `directory_tree`, `search_files`, and `get_file_info` count as reads. Listing `~/.ssh` is denied. Listing `/work` is allowed. `create_directory` counts as a write.

Add names on top of the defaults with `--policy`. `allow_path_parts` wins when a path segment matches, so a fixture directory can keep a realistic name.

```json
{
  "deny_path_parts": ["vault"],
  "deny_file_names": ["token.txt"],
  "allow_path_parts": ["fixtures"]
}
```

```bash
harnis mcp --policy policy.json -- npx -y @modelcontextprotocol/server-filesystem /work
```

## Check a session without running it

`harnis probe` uses the same `tools/call` decision as the proxy. It reports the call. It does not run it, and it does not attack other systems.

A recorded session, one JSON-RPC message per line:

```bash
harnis probe --transcript session.jsonl
```

A local agent that exports `build_agent()`, or an HTTP endpoint that accepts `{"messages":[...]}` and returns `{"role","content","tool_calls":[{"name","arguments"}]}`:

```bash
harnis probe -- examples/leaky_agent.py
harnis probe --scenario rag -- examples/rag_agent.py
harnis probe --url http://127.0.0.1:8765/v1/chat --scenario credential,destructive
```

Scenarios: `credential`, `destructive`, `rag`, `escalation`, `exfil`, or `all`. Findings go to `harnis-probe.html`.

In GitHub Actions:

```yaml
- uses: L00PLeGeNd/Harnis/.github/actions/probe@main
  with:
    agent: examples/leaky_agent.py
```

## Python agents

`harnis protect` is the in-process guard for a Python program. A denial raises `PermissionError` before the call returns. The process exits non-zero if anything was blocked, including when the agent catches the error. The page is `harnis-report.html`.

```bash
harnis protect -- python examples/curious_agent.py
```

```text
🚨 BLOCKED: agent attempted to run rm -rf /tmp/harnis-scratch (policy: no-destructive-exec)
🚨 BLOCKED: agent attempted to send secrets to https://collect.example/upload (policy: no-secret-exfil)
```

The hook covers CPython `open`, `subprocess`, `os.system`, `urllib`, `http.client`, and `ssl.SSLSocket.send`, including a child Python the agent starts. On Linux x86_64, a non-Python command is supervised with ptrace (`open`, `openat`, `execve`, `execveat`). On Windows, use the Python form.

From your own code, the same decision:

```python
from harnis import judge_tool_call

decision = judge_tool_call("read_file", {"path": "/home/me/.ssh/id_rsa"})
decision.allowed  # False
decision.line()
```

## Limits

A `ctypes` call through a raw address is outside the audit hook. A shell started with `shell=True` is not re-injected. Harnis reports the denied action, the policy, and the time. Probe does not generate an exploit.

## Development

```bash
pip install -e .
python -m pytest
```

MIT. See [LICENSE](LICENSE).
