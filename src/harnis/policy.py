"""Decides whether one agent action is allowed.

The hot path is pure: no I/O, no locks, no policy reloads. Callers in an
audit hook or a ptrace stop should be able to judge and return.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

_CREDENTIAL_DIRS = frozenset({
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
})
_CREDENTIAL_FILES = frozenset({
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "credentials",
    "credentials.json",
    "secrets.json",
    ".netrc",
    ".pgpass",
    ".npmrc",
    ".pypirc",
})
_SHELLS = frozenset({
    "sh",
    "bash",
    "zsh",
    "dash",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
})
_READERS = frozenset({
    "type",
    "more",
    "cat",
    "head",
    "tail",
    "less",
    "copy",
    "xcopy",
    "robocopy",
    "get-content",
    "gc",
    "curl",
    "wget",
    "iwr",
    "invoke-webrequest",
    "invoke-restmethod",
})
_EXPANSION = re.compile(r"%[^%\s]{1,64}%|\$env:|\$\{|\$[A-Za-z_]", re.IGNORECASE)
_OBFUSCATION = re.compile(
    r"\[char\]|frombase64string|invoke-expression|\biex\b",
    re.IGNORECASE,
)
_ENCODED_FLAGS = frozenset({"-encodedcommand", "-enc", "-ec"})
_BASE64_PIPE = re.compile(
    r"base64\s+(-d|--decode)|frombase64string|\|\s*sh\b|\|\s*bash\b|\|\s*zsh\b",
    re.IGNORECASE,
)
_SECRET_MARKERS = (
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
)
_RAW_SYMBOLS = frozenset({
    "open",
    "open64",
    "fopen",
    "freopen",
    "openat",
    "_open",
    "_wopen",
    "createfilea",
    "createfilew",
    "createfile2",
    "ntcreatefile",
    "zwcreatefile",
    "deletefilea",
    "deletefilew",
    "system",
    "_wsystem",
    "popen",
    "_popen",
    "execve",
    "execv",
    "execvp",
    "fexecve",
    "createprocessa",
    "createprocessw",
    "winexec",
    "shellexecutea",
    "shellexecutew",
    "shellexecuteexw",
})


@dataclass(frozen=True)
class Action:
    kind: str
    path: str = ""
    command: tuple[str, ...] = ()
    url: str = ""
    body: bytes = b""
    headers: tuple[tuple[str, str], ...] = ()
    symbol: str = ""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    policy: str | None
    phrase: str

    def line(self) -> str:
        body = f"🚨 BLOCKED: agent attempted to {self.phrase}"
        if self.policy == "no-unbounded-shell":
            body += " — shell has no script argument and can read stdin"
        elif self.policy == "no-edit-thrash":
            body += " — stop and rethink instead of rewriting the same bytes"
        elif self.policy == "no-path-wander":
            body += " — stay inside the files already opened this session"
        elif self.policy == "no-tool-budget":
            body += " — session tool-call budget exhausted"
        elif self.policy == "deny-tool":
            body += " — tool is listed in deny_tools"
        return f"{body} (policy: {self.policy})"


@dataclass(frozen=True)
class Rules:
    """Optional additions on top of the built-in default policy."""

    deny_path_parts: frozenset[str] = frozenset()
    deny_file_names: frozenset[str] = frozenset()
    allow_path_parts: frozenset[str] = frozenset()
    deny_tools: frozenset[str] = frozenset()
    preset: str = "coding-agent"
    empty_edit_limit: int = 5
    max_tool_calls: int | None = None
    max_unique_paths: int | None = None


def discover_policy(root: Path | None = None) -> Path | None:
    """Return `.harnis/policy.json` (or sibling names) under root/cwd when present."""
    base = Path.cwd() if root is None else Path(root)
    for candidate in (
        base / ".harnis" / "policy.json",
        base / "harnis.policy.json",
        base / "policy.harnis.json",
    ):
        if candidate.is_file():
            return candidate
    return None


def resolve_policy_path(path: str | None = None, root: Path | None = None) -> str | None:
    """Explicit path wins, then HARNIS_POLICY, then a project policy file."""
    if path:
        return path
    env = os.environ.get("HARNIS_POLICY")
    if env:
        return env
    found = discover_policy(root)
    return str(found) if found is not None else None


def load_rules(path: str | None) -> Rules:
    if not path:
        return Rules()
    file = Path(path)
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"policy file is not valid JSON: {file}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"policy file must be a JSON object: {file}")
    return Rules(
        deny_path_parts=_string_set(data.get("deny_path_parts", []), "deny_path_parts"),
        deny_file_names=_string_set(data.get("deny_file_names", []), "deny_file_names"),
        allow_path_parts=_string_set(data.get("allow_path_parts", []), "allow_path_parts"),
        deny_tools=_tool_name_set(data.get("deny_tools", []), "deny_tools"),
        empty_edit_limit=_optional_positive_int(
            data.get("empty_edit_limit", 5), "empty_edit_limit", default=5
        ),
        max_tool_calls=_optional_positive_int(
            data.get("max_tool_calls"), "max_tool_calls", default=None
        ),
        max_unique_paths=_optional_positive_int(
            data.get("max_unique_paths"), "max_unique_paths", default=None
        ),
    )


PRESETS = frozenset({
    "coding-agent",
    "readonly",
    "ci",
    "github",
    "postgres",
    "slack",
    "browser",
    "email",
})
_DEFAULT_BRANCHES = frozenset({"main", "master"})
_READ_SQL = frozenset({"select", "with", "explain", "show"})
_WRITE_SQL = frozenset({"drop", "truncate", "delete"})
_SQL_STRING = re.compile(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"")
_SQL_COMMENT = re.compile(r"/\*.*?\*/|--.*?$", re.DOTALL | re.MULTILINE)


def rules_for(preset: str, path: str | None = None) -> Rules:
    """Built-in posture. A policy file only adds path names on top."""
    if preset not in PRESETS:
        names = ", ".join(sorted(PRESETS))
        raise ValueError(f"unknown preset {preset!r}. Use: {names}")
    loaded = load_rules(path)
    return Rules(
        deny_path_parts=loaded.deny_path_parts,
        deny_file_names=loaded.deny_file_names,
        allow_path_parts=loaded.allow_path_parts,
        deny_tools=loaded.deny_tools,
        preset=preset,
        empty_edit_limit=loaded.empty_edit_limit,
        max_tool_calls=loaded.max_tool_calls,
        max_unique_paths=loaded.max_unique_paths,
    )


def _string_set(value, field: str) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a list of strings")
    return frozenset(item.casefold() for item in value if item)


def _tool_name_set(value, field: str) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a list of strings")
    return frozenset(_normalize_tool_name(item) for item in value if item)


def _normalize_tool_name(name: str) -> str:
    return name.strip().lower().replace("-", "_")


def _optional_positive_int(value, field: str, default: int | None) -> int | None:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field} must be a positive integer")
    return value


def judge(action: Action, rules: Rules | None = None) -> Decision:
    rules = rules or Rules()
    if action.kind in {"file_read", "file_write"}:
        decision = _judge_path(action, rules)
    elif action.kind == "exec":
        decision = _judge_exec(action, rules)
    elif action.kind == "http":
        decision = _judge_http(action)
    elif action.kind == "ctypes":
        decision = _judge_ctypes(action)
    elif action.kind == "socket":
        decision = _judge_socket(action)
    else:
        decision = Decision(True, None, action.kind)
    return _apply_preset(decision, action, rules)


def _apply_preset(decision: Decision, action: Action, rules: Rules) -> Decision:
    if not decision.allowed:
        return decision
    if rules.preset == "readonly" and action.kind in {"file_write", "exec", "http", "socket"}:
        return Decision(False, "readonly", decision.phrase)
    if rules.preset == "ci" and action.kind == "exec":
        return Decision(False, "ci-no-shell", decision.phrase)
    return decision


def _judge_socket(action: Action) -> Decision:
    if carries_secret(action.body, action.headers):
        return Decision(False, "no-secret-exfil", "send secrets over a socket")
    return Decision(True, None, "send over a socket")


def _judge_ctypes(action: Action) -> Decision:
    symbol = action.symbol or "(unknown)"
    phrase = f"resolve {symbol}"
    if action.symbol.casefold() in _RAW_SYMBOLS:
        return Decision(False, "no-ctypes-bypass", phrase)
    return Decision(True, None, phrase)


def _judge_path(action: Action, rules: Rules) -> Decision:
    verb = "write" if action.kind == "file_write" else "read"
    phrase = f"{verb} {display_path(action.path)}"
    if credential_path(action.path, rules):
        return Decision(False, "no-credential-access", phrase)
    return Decision(True, None, phrase)


def credential_path(path: str, rules: Rules | None = None) -> bool:
    """True if the path string or its resolved target looks like a credential."""
    rules = rules or Rules()
    if _credential_path_string(path, rules):
        return True
    resolved = _resolve_path(path)
    if resolved and resolved.casefold() != str(path).replace("\\", "/").casefold():
        return _credential_path_string(resolved, rules)
    return False


def _credential_path_string(path: str, rules: Rules) -> bool:
    parts = _parts(path)
    if not parts:
        return False
    folded = [part.casefold() for part in parts]
    if rules.allow_path_parts and any(part in rules.allow_path_parts for part in folded):
        return False
    dirs = folded[:-1]
    name = folded[-1]
    if any(part in _CREDENTIAL_DIRS or part in rules.deny_path_parts for part in dirs):
        return True
    if name in _CREDENTIAL_DIRS or name in rules.deny_path_parts or name in rules.deny_file_names:
        return True
    if name in _CREDENTIAL_FILES:
        return True
    if name == ".env" or name.startswith(".env."):
        return True
    return False


def _resolve_path(path: str) -> str | None:
    """Best-effort realpath. Missing targets still normalize when possible."""
    from pathlib import Path

    text = str(path).strip()
    if not text:
        return None
    try:
        return str(Path(text).expanduser().resolve()).replace("\\", "/")
    except (OSError, RuntimeError, ValueError):
        return None


def display_path(path: str) -> str:
    collapsed = str(path).replace("\\", "/")
    home = _home_collapsed()
    folded = collapsed.casefold()
    home_folded = home.casefold()
    if folded == home_folded:
        return "~"
    prefix = home_folded + "/"
    if folded.startswith(prefix):
        return "~/" + collapsed[len(home) + 1 :]
    return collapsed


def _home_collapsed() -> str:
    from pathlib import Path

    return str(Path.home()).replace("\\", "/")


def _parts(path: str) -> list[str]:
    collapsed = str(path).replace("\\", "/")
    return [part for part in collapsed.split("/") if part not in {"", "."}]


def _judge_exec(action: Action, rules: Rules) -> Decision:
    rendered = " ".join(action.command).strip() or "(empty)"
    phrase = f"run {rendered}"
    if destructive_command(action.command):
        return Decision(False, "no-destructive-exec", phrase)
    if command_mentions_credential(action.command, rules):
        return Decision(False, "no-credential-access", phrase)
    if unbounded_shell(action.command):
        return Decision(False, "no-unbounded-shell", phrase)
    if opaque_shell(action.command):
        return Decision(False, "no-opaque-shell", phrase)
    return Decision(True, None, phrase)


def command_mentions_credential(command: tuple[str, ...], rules: Rules | None = None) -> bool:
    """True only for argv pieces that look like paths, not bare search tokens."""
    rules = rules or Rules()
    for part in command:
        text = part.replace("\\", "/")
        if not _looks_like_path(text):
            continue
        if credential_path(text, rules):
            return True
    blob = " ".join(command).replace("\\", "/")
    if _looks_like_path(blob) and credential_path(blob, rules):
        return True
    if command and _basename(command[0]) in _SHELLS:
        script = _shell_script(command[1:])
        if script and _script_mentions_credential(script, rules):
            return True
    return False


def _script_mentions_credential(script: str, rules: Rules) -> bool:
    try:
        tokens = shlex.split(script, posix=True)
    except ValueError:
        tokens = script.split()
    for token in tokens:
        text = token.replace("\\", "/")
        if _looks_like_path(text) and credential_path(text, rules):
            return True
    return False


def _looks_like_path(text: str) -> bool:
    if not text or "://" in text:
        return False
    if text.startswith("~") or text.startswith("/") or text.startswith("./") or text.startswith("../"):
        return True
    if len(text) >= 3 and text[1] == ":" and text[2] == "/":
        return True
    return "/" in text


def opaque_shell(command: tuple[str, ...]) -> bool:
    """A shell script that hides the path is not a fixed command."""
    if not command or _basename(command[0]) not in _SHELLS:
        return False
    if any(arg.casefold() in _ENCODED_FLAGS for arg in command[1:]):
        return True
    script = _shell_script(command[1:])
    if not script:
        return False
    if _OBFUSCATION.search(script):
        return True
    if _BASE64_PIPE.search(script):
        return True
    if _EXPANSION.search(script) is None:
        return False
    return _script_reads(script)


def _script_reads(script: str) -> bool:
    normalized = script.replace("^", "")
    for piece in re.split(r"[&|\n;]", normalized):
        words = piece.split()
        if not words:
            continue
        name = _basename(words[0].strip("\"'")).casefold()
        if name in _READERS:
            return True
    return False


def unbounded_shell(command: tuple[str, ...]) -> bool:
    """A shell with no script in argv can read the next command from stdin."""
    if not command:
        return False
    exe = _basename(command[0])
    if exe not in _SHELLS:
        return False
    return not _bounded_script(exe, command[1:])


def _bounded_script(exe: str, args: tuple[str, ...]) -> bool:
    if exe in {"cmd", "cmd.exe"}:
        return _flag_has_argument(args, {"/c", "-c"})
    if exe in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
        return _flag_has_argument(args, {"-command", "-c"} | _ENCODED_FLAGS)
    if _flag_has_argument(args, {"-c"}) or _cluster_has_argument(args):
        return True
    return _posix_shell_script_path(args)


def _posix_shell_script_path(args: tuple[str, ...]) -> bool:
    """bash deploy.sh is bounded; bare bash / bash -i are not."""
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return index + 1 < len(args) and bool(args[index + 1].strip())
        if arg.startswith("-") and not arg.startswith("--"):
            index += 1
            continue
        if arg.startswith("--"):
            index += 1
            continue
        return bool(arg.strip())
    return False


def _flag_has_argument(args: tuple[str, ...], flags: set[str]) -> bool:
    for index, arg in enumerate(args):
        if arg.casefold() in flags and index + 1 < len(args) and args[index + 1].strip():
            return True
    return False


def _cluster_has_argument(args: tuple[str, ...]) -> bool:
    """bash -lc 'echo hi' puts the command after a flag cluster that contains c."""
    for index, arg in enumerate(args):
        if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
            return index + 1 < len(args) and args[index + 1].strip() != ""
    return False


def destructive_command(command: tuple[str, ...]) -> bool:
    if not command:
        return False
    argv = tuple(command)
    if _is_rm_rf(argv):
        return True
    exe = _basename(argv[0])
    if exe in _SHELLS:
        script = _shell_script(argv[1:])
        if script and _script_runs_rm_rf(script):
            return True
    return False


def _is_rm_rf(argv: tuple[str, ...]) -> bool:
    if _basename(argv[0]) not in {"rm", "rm.exe"}:
        return False
    return _recursive_and_force(argv[1:])


def _recursive_and_force(args: tuple[str, ...]) -> bool:
    recursive = False
    force = False
    for arg in args:
        if arg == "--":
            break
        if arg == "--recursive":
            recursive = True
            continue
        if arg == "--force":
            force = True
            continue
        if arg.startswith("-") and not arg.startswith("--"):
            letters = arg[1:]
            if "r" in letters or "R" in letters:
                recursive = True
            if "f" in letters:
                force = True
    return recursive and force


def _shell_script(args: tuple[str, ...]) -> str:
    """Return the command string from `sh -c`, `cmd /c`, or similar."""
    tokens = list(args)
    while tokens:
        head = tokens[0]
        folded = head.casefold()
        if folded in {"-c", "/c", "-command"} | _ENCODED_FLAGS:
            tokens = tokens[1:]
            break
        if folded in {"-lc", "-cl"}:
            tokens = tokens[1:]
            break
        break
    return " ".join(tokens)


def _script_runs_rm_rf(script: str) -> bool:
    try:
        tokens = shlex.split(script, posix=True)
    except ValueError:
        tokens = script.split()
    for index, token in enumerate(tokens):
        if _basename(token) in {"rm", "rm.exe"}:
            if _recursive_and_force(tuple(tokens[index + 1 :])):
                return True
    return False


def _basename(token: str) -> str:
    name = token.replace("\\", "/").rsplit("/", 1)[-1]
    return name.casefold()


def _judge_http(action: Action) -> Decision:
    target = _http_target(action.url)
    phrase = f"send secrets to {target}"
    if carries_secret(action.body, action.headers):
        return Decision(False, "no-secret-exfil", phrase)
    return Decision(True, None, f"send to {target}")


def carries_secret(body: bytes, headers: tuple[tuple[str, str], ...]) -> bool:
    haystack = body if isinstance(body, (bytes, bytearray)) else b""
    if _bytes_have_secret(haystack):
        return True
    for name, value in headers:
        blob = f"{name}: {value}".encode("utf-8", "surrogateescape")
        if _bytes_have_secret(blob):
            return True
    return False


def _bytes_have_secret(data: bytes) -> bool:
    if not data:
        return False
    if b"-----BEGIN " in data and any(marker in data for marker in _SECRET_MARKERS):
        return True
    if _has_aws_access_key(data):
        return True
    if _has_github_pat(data):
        return True
    return False


def _has_aws_access_key(data: bytes) -> bool:
    start = 0
    while True:
        found = data.find(b"AKIA", start)
        if found < 0:
            return False
        suffix = data[found + 4 : found + 20]
        if len(suffix) == 16 and all(_aws_key_byte(byte) for byte in suffix):
            return True
        start = found + 4


def _aws_key_byte(byte: int) -> bool:
    return (48 <= byte <= 57) or (65 <= byte <= 90)


def _has_github_pat(data: bytes) -> bool:
    start = 0
    prefix = b"ghp_"
    while True:
        found = data.find(prefix, start)
        if found < 0:
            return False
        token = data[found + 4 : found + 4 + 36]
        if len(token) == 36 and all(_github_pat_byte(byte) for byte in token):
            return True
        start = found + 4


def _github_pat_byte(byte: int) -> bool:
    return (48 <= byte <= 57) or (65 <= byte <= 90) or (97 <= byte <= 122)


def _http_target(url: str) -> str:
    if not url:
        return "(unknown destination)"
    return url.split("?", 1)[0]


_FILE_READS = frozenset({
    "read_file",
    "read_text_file",
    "read_media_file",
    "read_multiple_files",
    "read",
    "open_file",
    "cat",
    "fetch_file",
    "list_directory",
    "list_directory_with_sizes",
    "directory_tree",
    "search_files",
    "get_file_info",
})
_FILE_WRITES = frozenset({
    "write_file",
    "edit_file",
    "create_directory",
    "write",
    "save_file",
})


def judge_tool_call(name: str, arguments: dict, rules: Rules | None = None) -> Decision:
    """Map an agent tool call onto the same rules as a syscall."""
    rules = rules or Rules()
    normalized = _normalize_tool_name(name)
    if normalized in rules.deny_tools:
        return Decision(False, "deny-tool", f"call {name}")
    decision = _dispatch_tool(name, normalized, arguments, rules)
    if not decision.allowed:
        return decision
    leaked = _arguments_leak(arguments, rules)
    if leaked is not None:
        return leaked
    return _server_preset(normalized, arguments, rules) or decision


def judge_resource_read(uri: str, rules: Rules | None = None) -> Decision:
    """Judge an MCP resources/read URI the same way as a file read when path-like."""
    rules = rules or Rules()
    path = _uri_to_path(uri)
    if path is None:
        return Decision(True, None, f"read resource {uri or '(empty)'}")
    return judge(Action(kind="file_read", path=path), rules)


def _uri_to_path(uri: str) -> str | None:
    text = str(uri or "").strip()
    if not text:
        return None
    if text.casefold().startswith("file:"):
        from urllib.parse import unquote, urlparse

        parsed = urlparse(text)
        path = unquote(parsed.path or "")
        if parsed.netloc and parsed.netloc not in {"localhost", "127.0.0.1"}:
            # file://hostname/path — keep host in the path string for heuristics
            path = f"/{parsed.netloc}{path}"
        if os.name == "nt" and len(path) >= 3 and path[0] == "/" and path[2] == ":":
            path = path[1:]
        return path.replace("\\", "/") or None
    if _looks_like_path(text.replace("\\", "/")):
        return text
    return None


def _arguments_leak(arguments: dict, rules: Rules) -> Decision | None:
    """Catch renamed tools that still pass credential paths or secret-shaped text."""
    if not isinstance(arguments, dict):
        return None
    strings: list[str] = []
    _collect_strings(arguments, strings)
    for text in strings:
        collapsed = text.replace("\\", "/")
        if _looks_like_path(collapsed) and credential_path(collapsed, rules):
            return Decision(
                False,
                "no-credential-access",
                f"read {display_path(collapsed)}",
            )
    for text in strings:
        if carries_secret(text.encode("utf-8", "surrogateescape"), ()):
            return Decision(False, "no-secret-exfil", "send secrets in tool arguments")
    return None


def _collect_strings(value, out: list[str], depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(value, str):
        if value:
            out.append(value)
        return
    if isinstance(value, dict):
        for item in value.values():
            _collect_strings(item, out, depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _collect_strings(item, out, depth + 1)


def _dispatch_tool(name: str, normalized: str, arguments: dict, rules: Rules) -> Decision:
    if normalized in _FILE_READS:
        return _judge_paths("file_read", arguments, rules)
    if normalized in _FILE_WRITES:
        return _judge_paths("file_write", arguments, rules)
    if normalized == "move_file":
        source = str(arguments.get("source") or arguments.get("path") or "")
        destination = str(arguments.get("destination") or arguments.get("dest") or "")
        read = judge(Action(kind="file_read", path=source), rules)
        if not read.allowed:
            return read
        return judge(Action(kind="file_write", path=destination), rules)
    if normalized in {"shell", "bash", "exec", "run", "command"}:
        command = arguments.get("command", arguments.get("cmd", ()))
        return judge(Action(kind="exec", command=_as_command(command)), rules)
    if normalized in {"http", "fetch", "curl", "request", "post", "get"}:
        body = arguments.get("body", b"")
        if isinstance(body, str):
            body = body.encode("utf-8")
        headers = arguments.get("headers") or {}
        if isinstance(headers, dict):
            header_items = tuple((str(key), str(value)) for key, value in headers.items())
        else:
            header_items = tuple(headers)
        return judge(
            Action(
                kind="http",
                url=str(arguments.get("url", "")),
                body=body,
                headers=header_items,
            ),
            rules,
        )
    return Decision(True, None, f"call {name}")


def _server_preset(name: str, arguments: dict, rules: Rules) -> Decision | None:
    if rules.preset == "github":
        return _github_preset(name, arguments)
    if rules.preset == "postgres":
        return _postgres_preset(name, arguments)
    if rules.preset == "slack":
        return _slack_preset(arguments, name)
    if rules.preset == "browser":
        return _browser_preset(name, arguments)
    if rules.preset == "email":
        return _email_preset(name)
    return None


def _github_preset(name: str, arguments: dict) -> Decision | None:
    if name in {"delete_file", "delete_repository"}:
        target = "a repository on GitHub" if name == "delete_repository" else "a file on GitHub"
        return Decision(False, "github-delete", f"delete {target}")
    if name in {"push_files", "create_or_update_file"} and _on_default_branch(arguments):
        return Decision(False, "github-default-branch", "write the default branch on GitHub")
    return None


def _on_default_branch(arguments: dict) -> bool:
    branch = arguments.get("branch")
    if branch in (None, ""):
        return True
    return str(branch).casefold() in _DEFAULT_BRANCHES


_POSTGRES_WRITE = frozenset({"postgres_mcp_modify", "modify"})
_POSTGRES_QUERY = frozenset({
    "postgres_mcp_query",
    "query",
    "execute_sql",
    "run_query",
    "execute",
})


def _postgres_preset(name: str, arguments: dict) -> Decision | None:
    if name in _POSTGRES_WRITE:
        return Decision(False, "postgres-modify", "modify the database")
    if name in _POSTGRES_QUERY and not _sql_is_read(_sql_text(arguments)):
        return Decision(False, "postgres-modify", "modify the database")
    return None


def _sql_text(arguments: dict) -> str:
    for key in ("sql", "query"):
        value = arguments.get(key)
        if isinstance(value, str):
            return value
    return ""


def _sql_is_read(sql: str) -> bool:
    words = _sql_words(sql)
    if not words or words[0] not in _READ_SQL:
        return False
    return not any(word in _WRITE_SQL for word in words)


def _sql_words(sql: str) -> list[str]:
    without_strings = _SQL_STRING.sub(" ", sql)
    without_comments = _SQL_COMMENT.sub(" ", without_strings)
    return re.findall(r"[a-z_]+", without_comments.casefold())


_SLACK_POST = frozenset({
    "slack_post_message",
    "post_message",
    "chat_postmessage",
    "conversations_add_message",
})


def _slack_preset(arguments: dict, name: str) -> Decision | None:
    if name not in _SLACK_POST:
        return None
    for key in ("text", "message", "content"):
        value = arguments.get(key)
        if isinstance(value, str) and carries_secret(value.encode("utf-8"), ()):
            return Decision(False, "no-secret-exfil", "send secrets in a Slack message")
    return None


_BROWSER_EVAL = frozenset({
    "browser_evaluate",
    "evaluate",
    "evaluate_script",
    "run_js",
    "execute_javascript",
    "puppeteer_evaluate",
})
_BROWSER_NAV = frozenset({
    "browser_navigate",
    "navigate",
    "goto",
    "puppeteer_navigate",
    "playwright_navigate",
})


def _browser_preset(name: str, arguments: dict) -> Decision | None:
    if name in _BROWSER_EVAL:
        return Decision(False, "browser-evaluate", "run page JavaScript")
    if name in _BROWSER_NAV:
        url = str(arguments.get("url") or arguments.get("uri") or "")
        if url.casefold().startswith("file:"):
            return Decision(False, "browser-local-file", "open a local file URL in the browser")
    return None


_EMAIL_SEND = frozenset({
    "send_email",
    "send_message",
    "send_mail",
    "create_draft",
    "gmail_send",
    "draft_send",
})


def _email_preset(name: str) -> Decision | None:
    if name in _EMAIL_SEND:
        return Decision(False, "email-send", "send email")
    return None


def _judge_paths(kind: str, arguments: dict, rules: Rules | None) -> Decision:
    paths = _argument_paths(arguments) or [""]
    chosen = judge(Action(kind=kind, path=paths[0]), rules)
    if not chosen.allowed:
        return chosen
    for path in paths[1:]:
        decision = judge(Action(kind=kind, path=path), rules)
        if not decision.allowed:
            return decision
        chosen = decision
    return chosen


def _argument_paths(arguments: dict) -> list[str]:
    found: list[str] = []
    for key in (
        "path",
        "file_path",
        "file",
        "uri",
        "target",
        "directory",
        "source",
        "destination",
        "dest",
        "filename",
        "key_path",
    ):
        value = arguments.get(key)
        if value not in (None, ""):
            found.append(str(value))
    listed = arguments.get("paths")
    if isinstance(listed, list):
        found.extend(str(item) for item in listed)
    return found


def _as_command(command) -> tuple[str, ...]:
    if isinstance(command, str):
        try:
            return tuple(shlex.split(command, posix=True))
        except ValueError:
            return tuple(command.split())
    return tuple(str(part) for part in command)
