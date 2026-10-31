# Harnis

A stdio proxy that judges MCP `tools/call` before the server runs it.
A denied call never reaches the server. The client gets a tool error, and the terminal prints one line.

```bash
pip install -e .
harnis mcp -- npx -y @modelcontextprotocol/server-filesystem /work
```

```text
🚨 BLOCKED: agent attempted to read ~/.ssh/id_rsa (policy: no-credential-access)
```

Cursor or Claude Desktop, in `mcp.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "harnis",
      "args": ["mcp", "--preset", "coding-agent", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/work"]
    }
  }
}
```

## Presets

| Preset | What it allows |
| --- | --- |
| `coding-agent` | Workspace read and write. Still denies credential paths, `rm -rf`, an unbounded or opaque shell, and a body that carries a key or token |
| `readonly` | Reads that are not credentials. Writes, shell, and outbound HTTP or sockets are denied |
| `ci` | The coding-agent file rules, and every shell call is denied |

```bash
harnis mcp --preset readonly -- npx -y @modelcontextprotocol/server-filesystem /work
```

A blocked call is recorded in `harnis-mcp.html`. Other JSON-RPC messages, including `initialize` and `tools/list`, are forwarded unchanged.

## Also: protect and probe

`protect` is the in-process guard for a Python agent. `probe` asks your own agent for tool calls and reports the ones this proxy would refuse. Probe does not execute the call and does not attack third parties.

```bash
harnis protect -- python examples/curious_agent.py
harnis probe -- examples/leaky_agent.py
```

```text
🚨 BLOCKED: agent attempted to run rm -rf /tmp/harnis-scratch (policy: no-destructive-exec)
🚨 BLOCKED: agent attempted to send secrets to https://collect.example/upload (policy: no-secret-exfil)
FINDING: agent offered to read /home/agent/.ssh/id_rsa (policy: no-credential-access)
```

Runtime denials go to `harnis-report.html`. Probe findings go to `harnis-probe.html`.

In GitHub Actions:

```yaml
- uses: L00PLeGeNd/Harnis/.github/actions/probe@main
  with:
    agent: examples/leaky_agent.py
```

## What the default policy stops

| Action | Policy |
| --- | --- |
| Read or write `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, private key files, `.env` | `no-credential-access` |
| `rm -rf`, including `bash -c` and `os.system` | `no-destructive-exec` |
| A shell with no script in its arguments (`cmd`, `powershell`, `bash`). It could read the next command from stdin | `no-unbounded-shell` |
| A shell script that hides the path: variable assembly, `^` escapes, `[char]`, or base64 | `no-opaque-shell` |
| `ctypes` resolving file or process APIs such as `CreateFileW`, `open`, or `execve` | `no-ctypes-bypass` |
| HTTP body or header, or a socket send, carrying a private key, an `AKIA…` cloud key, or a `ghp_…` token | `no-secret-exfil` |

A denied call raises `PermissionError` inside the agent. The process exits non-zero if anything was blocked, including when the agent catches the error. Ordinary reads, a single-file `rm`, and HTTP without secret material are left alone.

Add paths without replacing the defaults. `policy.json`:

```json
{
  "deny_path_parts": ["vault"],
  "deny_file_names": ["token.txt"],
  "allow_path_parts": ["fixtures"]
}
```

`allow_path_parts` wins for matching path segments, so test fixtures under that name are readable even if they look like credentials.

```bash
harnis protect --policy policy.json -- python agent.py
```

## Same rules for tool calls

Agent frameworks can ask before they run a tool. The answer is the syscall policy, not a second list.

```python
from harnis import judge_tool_call

decision = judge_tool_call("read_file", {"path": "/home/me/.ssh/id_rsa"})
decision = judge_tool_call("shell", {"command": "rm -rf /tmp/scratch"})
```

`decision.allowed` is false, and `decision.line()` is the sentence above.

## Probe your own agent

`harnis probe` loads a script that exports `build_agent()`, or posts to `--url` with this JSON contract:

```json
{"messages":[{"role":"user","content":"..."}]}
```

```json
{"role":"assistant","content":"...","tool_calls":[{"name":"read_file","arguments":{"path":"..."}}]}
```

Scenarios: `credential`, `destructive`, `rag`, `escalation`, `exfil`, or `all`. Findings include the full replay. Tool calls are judged, not executed.

```bash
harnis probe -- examples/leaky_agent.py
harnis probe --scenario rag -- examples/rag_agent.py
harnis probe --scenario destructive -- examples/shell_agent.py
python examples/http_echo_agent.py
harnis probe --url http://127.0.0.1:8765/v1/chat --scenario credential,destructive
```

## Two layers, one policy

`harnis protect -- python …` installs a CPython audit hook on `open`, `subprocess`, `os.system`, `urllib`, and `http.client`. The check is in-process, on the calling thread, before the call returns. That is the fast path, and it works on Windows and Linux.

For a command that is not Python, Linux x86_64 uses ptrace. `open`, `openat`, `execve`, and `execveat` in the process and its children are judged with the same rules. A denial returns `EPERM` and the process keeps running. This path is covered by the Linux smoke script and CI.

```bash
harnis protect -- bash agent.sh
```

On Windows that form exits with a short message. ptrace is the optional Linux backend. eBPF is not part of this release.

## Limits

The audit hook sees CPython's own file, process, and HTTP APIs. A child Python started by the agent is launched under the same hook. A shell command that names a credential path is denied before the shell starts. A shell with no script in its arguments is denied, and so is a script that hides the path with variables, `^`, `[char]`, or base64. Resolving `CreateFileW`, `open`, `execve`, and the other file or process entry points through `ctypes` is denied. Plain `socket` sends and `ssl.SSLSocket.send` are scanned for the same secret patterns as HTTP.

Harnis does not see a `ctypes` call through a raw address, or a binary that is not Python. On Linux, the ptrace supervisor covers `open`, `openat`, and `execve` for that process. `urllib` and `http.client` (including `requests`) are inspected before the bytes are sent.

Harnis reports a reproducible denial: the action, the policy, the time. It does not produce an exploit.

## Tests

```bash
python -m pytest
```
