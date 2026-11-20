# Harnis

This repo is the **stdio seatbelt** that ships with [Witnis](https://github.com/L00PLeGeNd/Witnis) (search **witnis-dev**, not witnis.se).

Install the product, not this repo:

```bash
uvx --from git+https://github.com/L00PLeGeNd/Witnis.git witnis loop-init
```

That writes MCP wrap + policy. Cursor / Claude see one server named `witnis`. Harnis sits on stdio and judges `tools/call` before Witnis sees it. Do not treat Harnis as a second brand.

```json
{
  "mcpServers": {
    "witnis": {
      "command": "npx",
      "args": [
        "-y", "harnis", "mcp", "--preset", "coding-agent", "--",
        "uvx", "--from", "git+https://github.com/L00PLeGeNd/Witnis.git",
        "witnis", "mcp"
      ]
    }
  }
}
```

```text
BLOCKED: agent attempted to delete a file on GitHub — … (policy: github-delete)
```

Not an OS sandbox. Traffic that never hits `harnis mcp` is out of scope. [THREAT_MODEL.md](THREAT_MODEL.md).

---

## If you already have an MCP config

```bash
npx -y harnis init
npx -y harnis status
```

**Python 3.11+.** The npm package only spawns `python -m harnis`.

| Piece | Role |
| --- | --- |
| `harnis mcp` | Stdio JSON-RPC proxy; blocks matched `tools/call` / `resources/read` |
| `harnis init` / `status` | Project policy + wrap local MCP configs |
| `harnis scan [--apply]` | Find bare catalog servers; optional in-place wrap |

![Harnis seatbelt: client → harnis mcp (judge) → MCP server; denies return to client only](docs/assets/seatbelt.svg)

Primary presets: `coding-agent` (default), `github`, `readonly`, `ci`. Extra presets stay in code for experiments.

Credential paths and secret-shaped strings are scanned in **every** `tools/call` argument tree.

MIT.
