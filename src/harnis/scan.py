"""Find MCP servers in client configs that should sit behind Harnis."""

from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

_PACKAGES: tuple[tuple[str, str, str], ...] = (
    ("github-mcp-server", "github", "delete_file"),
    ("@modelcontextprotocol/server-github", "github", "delete_file"),
    ("@github/github-mcp-server", "github", "delete_file"),
    ("@microsoft/postgres-mcp", "postgres", "postgres_mcp_modify"),
    ("@modelcontextprotocol/server-postgres", "postgres", "postgres_mcp_modify"),
    ("@crystaldba/postgres-mcp", "postgres", "postgres_mcp_modify"),
    ("postgres-mcp", "postgres", "postgres_mcp_modify"),
)
_SHELLS = frozenset(
    name
    for base in ("bash", "sh", "cmd", "powershell")
    for name in (base, f"{base}.exe")
)
_NPX = frozenset({"npx", "npx.cmd", "npx.exe"})
_LAUNCH = "harnis"
_HARNIS_PACKAGES = frozenset({"harnis", "github:l00plegend/harnis"})


@dataclass(frozen=True)
class ConfigFinding:
    server: str
    preset: str
    tool: str
    snippet: dict
    path: Path | None = None
    client: str = "config"
    wrapable: bool = True

    def sentence(self) -> str:
        if not self.wrapable:
            return f"{self.server} is a remote MCP URL; Harnis cannot wrap it."
        return f"{self.server} can call {self.tool}."


def scan_files(path: Path | None = None) -> list[Path]:
    """Config files a scan would read. Missing explicit paths are still listed."""
    if path is not None:
        return [Path(path)]
    return [file for _client, file in _default_targets()]


def scan_config(path: Path | None = None) -> list[ConfigFinding]:
    """Return findings for catalog servers and remote URL servers."""
    findings: list[ConfigFinding] = []
    seen: set[str] = set()
    targets = [(None, Path(path))] if path is not None else _default_targets()
    for client, file in targets:
        if path is not None and not file.is_file():
            continue
        label = client or "config"
        for finding in _scan_file(file, label):
            key = json.dumps(
                {
                    "client": finding.client,
                    "server": finding.server,
                    "wrapable": finding.wrapable,
                    "snippet": finding.snippet,
                    "path": str(finding.path) if finding.path else None,
                },
                sort_keys=True,
                ensure_ascii=False,
            )
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
    return findings


def apply_wraps(path: Path | None = None) -> list[ConfigFinding]:
    """Rewrite bare catalog servers in place. Keep a .bak next to each changed file."""
    by_file: dict[Path, list[ConfigFinding]] = {}
    for finding in scan_config(path):
        if finding.path is None or not finding.wrapable:
            continue
        by_file.setdefault(finding.path, []).append(finding)
    applied: list[ConfigFinding] = []
    for file, findings in by_file.items():
        _apply_file(file, findings)
        applied.extend(findings)
    return applied


def _default_targets() -> list[tuple[str, Path]]:
    home = Path.home()
    appdata = os.environ.get("APPDATA")
    # Claude first (Code + Desktop), then GPT/Codex, then other editors.
    candidates: list[tuple[str, Path]] = [
        ("claude-code", Path(".mcp.json")),
        ("claude-code", home / ".claude.json"),
        ("claude-desktop", home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"),
        ("claude-desktop", home / ".config" / "Claude" / "claude_desktop_config.json"),
        ("codex", Path(".codex/config.toml")),
        ("codex", home / ".codex" / "config.toml"),
        ("cursor", Path(".cursor/mcp.json")),
        ("vscode", Path(".vscode/mcp.json")),
        ("cursor", home / ".cursor" / "mcp.json"),
        ("windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
        ("continue", home / ".continue" / "config.json"),
        ("cline", home / ".cline" / "data" / "settings" / "cline_mcp_settings.json"),
        ("cline", home / ".cline" / "mcp.json"),
    ]
    if appdata:
        base = Path(appdata)
        candidates.extend(
            [
                ("claude-desktop", base / "Claude" / "claude_desktop_config.json"),
                (
                    "cline",
                    base
                    / "Code"
                    / "User"
                    / "globalStorage"
                    / "saoudrizwan.claude-dev"
                    / "settings"
                    / "cline_mcp_settings.json",
                ),
                (
                    "cline",
                    base
                    / "Code - Insiders"
                    / "User"
                    / "globalStorage"
                    / "saoudrizwan.claude-dev"
                    / "settings"
                    / "cline_mcp_settings.json",
                ),
                (
                    "cline",
                    base
                    / "Cursor"
                    / "User"
                    / "globalStorage"
                    / "saoudrizwan.claude-dev"
                    / "settings"
                    / "cline_mcp_settings.json",
                ),
                (
                    "roo",
                    base
                    / "Code"
                    / "User"
                    / "globalStorage"
                    / "rooveterinaryinc.roo-cline"
                    / "settings"
                    / "mcp_settings.json",
                ),
                (
                    "roo",
                    base
                    / "Cursor"
                    / "User"
                    / "globalStorage"
                    / "rooveterinaryinc.roo-cline"
                    / "settings"
                    / "mcp_settings.json",
                ),
            ]
        )
    else:
        config = home / ".config"
        candidates.extend(
            [
                (
                    "cline",
                    config
                    / "Code"
                    / "User"
                    / "globalStorage"
                    / "saoudrizwan.claude-dev"
                    / "settings"
                    / "cline_mcp_settings.json",
                ),
                (
                    "roo",
                    config
                    / "Code"
                    / "User"
                    / "globalStorage"
                    / "rooveterinaryinc.roo-cline"
                    / "settings"
                    / "mcp_settings.json",
                ),
            ]
        )

    seen: set[Path] = set()
    found: list[tuple[str, Path]] = []
    for client, path in candidates:
        if not path.is_file():
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        found.append((client, path))
    return found


def _scan_file(file: Path, client: str) -> list[ConfigFinding]:
    if not file.is_file():
        return []
    data = _load_config(file)
    if data is None:
        return []
    findings: list[ConfigFinding] = []
    for name, entry in _servers(data).items():
        if not isinstance(entry, dict):
            continue
        if _is_remote(entry):
            findings.append(
                ConfigFinding(
                    server=str(name),
                    preset="",
                    tool="",
                    snippet={},
                    path=file,
                    client=client,
                    wrapable=False,
                )
            )
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
                server=str(name),
                preset=preset,
                tool=tool,
                snippet=snippet,
                path=file,
                client=client,
                wrapable=True,
            )
        )
    return findings


def _is_remote(entry: dict) -> bool:
    if entry.get("command"):
        return False
    url = entry.get("url")
    return isinstance(url, str) and bool(url.strip())


def _apply_file(file: Path, findings: list[ConfigFinding]) -> None:
    original = file.read_text(encoding="utf-8")
    data = _load_config(file)
    if data is None:
        raise ValueError(f"{file}: not a supported MCP config object")
    by_name = {finding.server: finding.snippet for finding in findings if finding.wrapable}
    _apply_server_maps(data, by_name)
    backup = file.with_name(file.name + ".bak")
    backup.write_text(original, encoding="utf-8")
    if _is_toml(file):
        file.write_text(_dump_toml(data), encoding="utf-8")
    else:
        file.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _apply_server_maps(data: dict, by_name: dict[str, dict]) -> None:
    for key in ("mcpServers", "servers", "mcp_servers"):
        value = data.get(key)
        if isinstance(value, dict):
            for name, snippet in by_name.items():
                if name in value:
                    value[name] = dict(snippet)
        elif isinstance(value, list):
            for index, entry in enumerate(value):
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("name") or "")
                if name in by_name:
                    updated = dict(by_name[name])
                    updated["name"] = name
                    value[index] = updated
    projects = data.get("projects")
    if isinstance(projects, dict):
        for body in projects.values():
            if isinstance(body, dict):
                _apply_server_maps(body, by_name)


def _load_config(file: Path) -> dict | None:
    raw = file.read_text(encoding="utf-8")
    if _is_toml(file):
        try:
            data = tomllib.loads(raw)
        except tomllib.TOMLDecodeError:
            return None
        return data if isinstance(data, dict) else None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _is_toml(file: Path) -> bool:
    return file.suffix.casefold() == ".toml"


def _servers(data: dict) -> dict:
    found: dict = {}
    for key in ("mcpServers", "servers", "mcp_servers"):
        value = data.get(key)
        if isinstance(value, dict):
            found.update(value)
        elif isinstance(value, list):
            for index, entry in enumerate(value):
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name") or f"server-{index}"
                found[str(name)] = entry
    projects = data.get("projects")
    if isinstance(projects, dict):
        for body in projects.values():
            if not isinstance(body, dict):
                continue
            nested = body.get("mcpServers")
            if isinstance(nested, dict):
                found.update(nested)
    return found


def _dump_toml(data: dict) -> str:
    """Serialize a limited TOML subset for Codex-style MCP configs."""
    lines: list[str] = []
    scalars = {key: value for key, value in data.items() if not isinstance(value, dict)}
    tables = {key: value for key, value in data.items() if isinstance(value, dict)}
    for key, value in scalars.items():
        lines.append(f"{key} = {_toml_atom(value)}")
    if scalars and tables:
        lines.append("")
    for key, value in tables.items():
        _dump_toml_table(lines, key, value)
    return "\n".join(lines).rstrip() + "\n"


def _dump_toml_table(lines: list[str], name: str, table: dict) -> None:
    nested = {key: value for key, value in table.items() if isinstance(value, dict)}
    plain = {key: value for key, value in table.items() if not isinstance(value, dict)}
    if plain or not nested:
        if lines and lines[-1] != "":
            lines.append("")
        lines.append(f"[{name}]")
        for key, value in plain.items():
            lines.append(f"{key} = {_toml_atom(value)}")
    for key, value in nested.items():
        _dump_toml_table(lines, f"{name}.{key}", value)


def _toml_atom(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(value, list):
        return "[" + ", ".join(_toml_atom(item) for item in value) + "]"
    raise TypeError(f"unsupported TOML value: {type(value)!r}")


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
