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
    file = Path(".cursor/mcp.json") if path is None else Path(path)
    if not file.is_file():
        return []
    data = json.loads(file.read_text(encoding="utf-8"))
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        return []
    findings: list[ConfigFinding] = []
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            continue
        hit = _catalog_hit(_argv(entry))
        if hit is None:
            continue
        preset, tool = hit
        if _wrapped(entry, preset):
            continue
        command, args = _server_argv(entry)
        findings.append(
            ConfigFinding(
                server=str(name),
                preset=preset,
                tool=tool,
                snippet={
                    "command": "npx",
                    "args": ["-y", _LAUNCH, "mcp", "--preset", preset, "--", command, *args],
                },
            )
        )
    return findings


def _catalog_hit(tokens: list[str]) -> tuple[str, str] | None:
    for package, preset, tool in _PACKAGES:
        if any(_token_is(token, package) for token in tokens):
            return preset, tool
    if tokens and Path(tokens[0]).name.casefold() in _SHELLS:
        return "coding-agent", "shell"
    return None


def _token_is(token: str, package: str) -> bool:
    name = token.replace("\\", "/").rstrip("/")
    leaf = name.rsplit("/", 1)[-1]
    folded = package.casefold()
    return name.casefold() == folded or leaf.casefold() == folded


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
