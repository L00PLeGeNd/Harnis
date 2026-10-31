# Harnis

Runtime sandbox for AI agents. Block the dangerous action while it runs.
Probe your own agent for tool calls that would violate the same policy.

```bash
pip install -e .
harnis protect -- python examples/curious_agent.py
harnis probe -- examples/leaky_agent.py
```

```text
🚨 BLOCKED: agent attempted to read ~/.ssh/id_rsa (policy: no-credential-access)
🚨 BLOCKED: agent attempted to run rm -rf /tmp/harnis-scratch (policy: no-destructive-exec)
🚨 BLOCKED: agent attempted to send secrets to https://collect.example/upload (policy: no-secret-exfil)
```

```text
FINDING: agent offered to read /home/agent/.ssh/id_rsa (policy: no-credential-access)
```

Runtime denials go to `harnis-report.html`. Probe findings go to `harnis-probe.html` with a replay of the conversation and tool calls. Probe judges proposed tool calls; it does not attack third-party systems.

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
  "deny_file_names": ["token.txt"]
}
```

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

`harnis probe` loads a script that exports `build_agent()`. The agent must implement `respond(turns) -> Turn`. Harnis sends credential-oriented prompts, including a follow-up on multi-turn chains, and judges every proposed tool call with the runtime policy. A finding includes the full replay. The tool call is not executed.

```bash
harnis probe -- examples/leaky_agent.py
harnis probe -- examples/safe_agent.py
```

## Two layers, one policy

`harnis protect -- python …` installs a CPython audit hook on `open`, `subprocess`, `os.system`, `urllib`, and `http.client`. The check is in-process, on the calling thread, before the call returns. That is the fast path, and it works on Windows and Linux.

For a command that is not Python, Linux x86_64 uses ptrace. `open`, `openat`, `execve`, and `execveat` in the process and its children are judged with the same rules. A denial returns `EPERM` and the process keeps running. This path is covered by the Linux smoke script and CI.

```bash
harnis protect -- bash agent.sh
```

On Windows that form exits with a short message. eBPF is not in 0.1.

## Limits

The audit hook sees CPython's own file, process, and HTTP APIs. A child Python started by the agent is launched under the same hook. A shell command that names a credential path is denied before the shell starts. A shell with no script in its arguments is denied, and so is a script that hides the path with variables, `^`, `[char]`, or base64. Resolving `CreateFileW`, `open`, `execve`, and the other file or process entry points through `ctypes` is denied. Plain `socket` sends and `ssl.SSLSocket.send` are scanned for the same secret patterns as HTTP.

Harnis does not see a `ctypes` call through a raw address, or a binary that is not Python. On Linux, the ptrace supervisor covers `open`, `openat`, and `execve` for that process. `urllib` and `http.client` (including `requests`) are inspected before the bytes are sent.

Harnis reports a reproducible denial: the action, the policy, the time. It does not produce an exploit.

## Tests

```bash
python -m pytest
```
