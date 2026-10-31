"""Find MCP servers in a client config that should sit behind Harnis."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

_PACKAGES: tuple[tuple[str, str, str], ...] = (
    ("github-mcp-server", "github", "delete_file"),
    ("@modelcontextprotocol/server-github", "github", "delete_file"),
    ("@microsoft/postgres-mcp", "postgres", "postgres_mcp_modify"),
    ("@modelcontextprotocol/server-postgres", "postgres", "postgres_mcp_modify"),
    ("postgres-mcp", "postgres", "postgres_mcp_modify"),
    ("@modelcontextprotocol/server-slack", "slack", "slack_post_message"),
)
_SHELLS = frozenset({
    "bash",
    "sh",
    "cmd",
    "powershell",
    "bash.exe",
    "sh.exe",
    "cmd.exe",
    "powershell.exe",
})
_NPX = frozenset({"npx", "npx.cmd", "npx.exe"})
_LAUNCH = "github:L00PLeGeNd/Harnis"
_HARNIS_PACKAGES = frozenset({"harnis", _LAUNCH.casefold()})


@dataclass(frozen=True)
class ConfigFinding:
    server: str
    preset: str
    tool: str
    snippet: dict

    def sentence(self) -> str:
        return f"{self.server} can call {self.tool}."


def scan_config(path: Path | None = None) -> list[ConfigFinding]:
    """Return one finding per catalog server that is not wrapped with its preset."""
    files = [Path(path)] if path is not None else _default_files()
    findings: list[ConfigFinding] = []
    seen: set[str] = set()
    for file in files:
        for finding in _scan_file(file):
            key = json.dumps(finding.snippet, sort_keys=True, ensure_ascii=False)
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
    return findings


def _default_files() -> list[Path]:
    candidates = [
        Path(".cursor/mcp.json"),
        Path(".vscode/mcp.json"),
        Path.home() / ".cursor" / "mcp.json",
    ]
    return [path for path in candidates if path.is_file()]


def _scan_file(file: Path) -> list[ConfigFinding]:
    if not file.is_file():
        return []
    data = json.loads(file.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return []
    findings: list[ConfigFinding] = []
    for _name, entry in _servers(data).items():
        if not isinstance(entry, dict):
            continue
        hit = _catalog_hit(_argv(entry))
        if hit is None:
            continue
        preset, tool = hit
        if _wrapped(entry, preset):
            continue
        command, args = _server_argv(entry)
        snippet = {
            "command": "npx",
            "args": ["-y", _LAUNCH, "mcp", "--preset", preset, "--", command, *args],
        }
        env = entry.get("env")
        if isinstance(env, dict):
            snippet["env"] = env
        findings.append(
            ConfigFinding(
                server=str(_name),
                preset=preset,
                tool=tool,
                snippet=snippet,
            )
        )
    return findings


def _servers(data: dict) -> dict:
    found: dict = {}
    for key in ("mcpServers", "servers"):
        value = data.get(key)
        if isinstance(value, dict):
            found.update(value)
    return found


def _catalog_hit(tokens: list[str]) -> tuple[str, str] | None:
    for package, preset, tool in _PACKAGES:
        if any(_token_is(token, package) for token in tokens):
            return preset, tool
    if tokens and Path(tokens[0]).name.casefold() in _SHELLS:
        return "coding-agent", "shell"
    return None


def _token_is(token: str, package: str) -> bool:
    folded = package.casefold()
    return any(candidate.casefold() == folded for candidate in _token_names(token))


def _token_names(token: str) -> list[str]:
    name = _without_digest(token.replace("\\", "/").strip())
    bare = name.split(":", 1)[0]
    leaf = bare.rsplit("/", 1)[-1]
    if leaf.casefold().endswith(".exe"):
        leaf = leaf[:-4]
    return [name, bare, leaf]


def _without_digest(name: str) -> str:
    marker = "@sha256:"
    index = name.casefold().find(marker)
    if index >= 0:
        return name[:index]
    return name


def _argv(entry: dict) -> list[str]:
    command = str(entry.get("command") or "")
    args = entry.get("args") or []
    if not isinstance(args, list):
        args = []
    return [command, *[str(arg) for arg in args]]


def _wrapped(entry: dict, preset: str) -> bool:
    head, _tail = _split(_argv(entry))
    if not _is_harnis(head):
        return False
    if "--preset" not in head:
        return False
    index = head.index("--preset")
    return index + 1 < len(head) and head[index + 1] == preset


def _is_harnis(head: list[str]) -> bool:
    if not head:
        return False
    command = Path(head[0]).name.casefold()
    folded = [part.casefold() for part in head]
    if command in {"harnis", "harnis.exe"}:
        return True
    if command.startswith("python") and "-m" in folded and "harnis" in folded:
        return True
    if command in _NPX:
        return any(part in _HARNIS_PACKAGES for part in folded[1:])
    return False


def _server_argv(entry: dict) -> tuple[str, list[str]]:
    tokens = _argv(entry)
    head, tail = _split(tokens)
    if _is_harnis(head) and tail:
        return tail[0], tail[1:]
    if not tokens:
        return "", []
    return tokens[0], tokens[1:]


def _split(tokens: list[str]) -> tuple[list[str], list[str]]:
    if "--" not in tokens:
        return tokens, []
    index = tokens.index("--")
    return tokens[:index], tokens[index + 1 :]
