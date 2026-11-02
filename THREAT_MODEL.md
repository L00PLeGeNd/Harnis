# Threat model

Harnis is a **seatbelt for local stdio MCP**, not a sandbox and not a distributed control plane.

## Sell

Wrap a local stdio MCP server so judged traffic is decided **before** the child process sees it. A denial is returned to the client and is not forwarded.

```bash
npx -y harnis mcp --preset github -- <server>
```

`npx` only launches the Python package (`python -m harnis`). The product is Python.

## In scope (what we try to stop)

| Control | Mechanism | Limit |
| --- | --- | --- |
| Dangerous MCP tools on wrapped stdio servers | Name/args heuristics + presets + optional `deny_tools` | Intent without matching name/args still slips |
| Credential path strings on **any** `tools/call` args | Deep string walk + path denylist + best-effort `Path.resolve()` | Broken/uncreated links; TOCTOU; Windows privilege for some symlinks |
| `resources/read` of `file:` / path-like URIs | Same path rules as file tools | Non-file schemes; opaque custom URI templates |
| Obvious destructive / opaque shell | `rm -rf`, EncodedCommand, base64→shell, expansion+reader | Novel encodings, other languages |
| Session thrash / wander / call caps | In-proxy counters | Per process (or hook state file); not cross-host |
| Secret-shaped bodies / tool text | Marker scan (PEM, AKIA…, ghp_…) | Easy to fragment or encrypt |

## Out of scope (do not market as covered)

- **URL / HTTP / SSE MCP** — reported by `scan`, never wrapped.
- **Unresolvable or racing symlinks** — we follow when `Path.resolve()` works; we do not claim kernel-enforced containment.
- **MCP `prompts/*`, custom methods, most `resources/*` schemes** — only `tools/call` and path-like `resources/read` are judged.
- **Renamed vendor tools with no credential/secret args** outside presets / `deny_tools`.
- **Servers the client starts without going through `harnis mcp`**.
- **Native binaries / non-CPython** on Windows `protect` (Linux x86_64 ptrace is best-effort).
- **Attacker who edits `mcp.json` to remove the wrap**.
- **Model persuasion** that never calls a tool.

## Trust boundary

```
client  --stdio JSON-RPC-->  harnis mcp  --stdio-->  MCP server
                                 ^
                    judge tools/call + resources/read (file/path)
```

Anything that never enters this process is unconstrained.

## Bypass matrix (known)

| Bypass | Result today |
| --- | --- |
| Remote `url` MCP | Not wrapped |
| Symlink to `~/.ssh` named `/work/data` | Blocked when resolve succeeds; allowed if link missing/unresolvable |
| Junction/reparse tricks resolve() misses | May still bypass |
| Tool renamed (`delete_file` → `remove_repo_file`) with no secret args | GitHub preset miss unless `deny_tools` lists it |
| Renamed tool that still passes `~/.ssh/...` | Blocked (universal arg sweep) |
| Client talks to server without Harnis | No enforcement |
| Hook-less editor local Write | No MCP proxy involvement |
| Fragmented / encoded secret exfil | May miss `no-secret-exfil` |
| `prompts/get` carrying a path | Not judged |

Adversarial tests in `tests/test_adversarial.py` lock gaps as **documented**, not accidental greens. Control-plane coverage lives in `tests/test_control_plane.py`.

## Design stance

Prefer an honest narrow seatbelt over a denylist theater that implies “safe agent.” New features must either harden an in-scope row or expand this file.
