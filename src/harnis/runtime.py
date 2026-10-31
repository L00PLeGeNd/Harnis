"""In-process enforcement for CPython agents.

The audit hook runs on the same thread as the call it is judging. A denial
raises before open(), process creation, or the HTTP send returns.
"""

from __future__ import annotations

import os
import re
import runpy
import shlex
import subprocess
import sys
import threading
import traceback
from collections.abc import Callable
from pathlib import Path

from harnis.policy import Action, Decision, Rules, judge, load_rules
from harnis.report import Session, emit

_HANDLED = frozenset({
    "open",
    "subprocess.Popen",
    "os.system",
    "urllib.Request",
    "http.client.send",
    "ctypes.dlsym",
})


BOOTSTRAP = "from harnis.runtime import main; raise SystemExit(main())"
_PYTHON = re.compile(r"python\d*(\.\d+)*w?$")
_popen_patched = False


class Blocked(PermissionError):
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(decision.line())


def main() -> int:
    report = Path(os.environ.get("HARNIS_REPORT", "harnis-report.html"))
    try:
        rules = load_rules(os.environ.get("HARNIS_POLICY"))
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"harnis: {exc}\n")
        return 2
    args = sys.argv[1:]
    if not args:
        sys.stderr.write("harnis: missing agent script\n")
        return 2
    if args[0] == "-c":
        code = args[1] if len(args) > 1 else ""
        return execute(rules, report, lambda: _exec_code(code), ["-c", *args[2:]])
    if args[0] == "-m":
        if len(args) < 2:
            sys.stderr.write("harnis: python -m needs a module name\n")
            return 2
        module = args[1]
        return execute(
            rules,
            report,
            lambda: runpy.run_module(module, run_name="__main__"),
            [module, *args[2:]],
        )
    script = args[0]
    return execute(
        rules,
        report,
        lambda: runpy.run_path(script, run_name="__main__"),
        list(args),
    )


def execute(rules: Rules, report: Path, runner: Callable[[], object], argv: list[str]) -> int:
    log = os.environ.get("HARNIS_LOG")
    session = Session(report, Path(log) if log else None)
    install(session, rules)
    sys.argv = list(argv)
    code = 0
    try:
        runner()
    except SystemExit as exc:
        code = _exit_code(exc.code)
    except Blocked:
        code = 1
    except Exception:
        traceback.print_exc()
        code = 1
    finally:
        try:
            session.write()
        except Exception:
            traceback.print_exc()
    if session.blocked and code == 0:
        return 1
    return code


def install(session: Session, rules: Rules) -> None:
    os.environ["HARNIS_ENFORCED"] = "1"
    os.environ["HARNIS_REPORT"] = str(session.path.resolve())
    os.environ["HARNIS_LOG"] = str(session.log_path.resolve())
    report = os.path.normcase(os.path.abspath(session.path))
    temporary = os.path.normcase(os.path.abspath(session.path.with_suffix(session.path.suffix + ".tmp")))
    log_file = os.path.normcase(os.path.abspath(session.log_path))
    exempt = {report, temporary, log_file}
    _patch_popen()
    _patch_socket(session, rules)
    local = threading.local()

    def hook(event: str, args) -> None:
        if event not in _HANDLED or getattr(local, "busy", False):
            return
        local.busy = True
        try:
            _handle(event, args, session, rules, exempt)
        finally:
            local.busy = False

    sys.addaudithook(hook)


def looks_like_python(token: str) -> bool:
    name = Path(token).name.lower()
    stem = name[:-4] if name.endswith(".exe") else name
    if _PYTHON.fullmatch(stem):
        return True
    try:
        return os.path.samefile(token, sys.executable)
    except OSError:
        return False


def _patch_popen() -> None:
    global _popen_patched
    if _popen_patched:
        return
    original = subprocess.Popen.__init__

    def init(self, args, bufsize=-1, executable=None, stdin=None, stdout=None, stderr=None,
             preexec_fn=None, close_fds=True, shell=False, cwd=None, env=None, **kwargs):
        if not shell:
            args, executable, env = _reinject(args, executable, env)
        return original(
            self, args, bufsize, executable, stdin, stdout, stderr,
            preexec_fn, close_fds, shell, cwd, env, **kwargs,
        )

    subprocess.Popen.__init__ = init
    _popen_patched = True


def _patch_socket(session: Session, rules: Rules) -> None:
    import socket as socketmod

    if getattr(socketmod, "_harnis_send", False):
        return
    original_send = socketmod.socket.send
    original_sendall = socketmod.socket.sendall

    def send(self, data, *args, **kwargs):
        _judge_or_raise(session, rules, Action(kind="socket", body=_body_bytes(data)))
        return original_send(self, data, *args, **kwargs)

    def sendall(self, data, *args, **kwargs):
        _judge_or_raise(session, rules, Action(kind="socket", body=_body_bytes(data)))
        return original_sendall(self, data, *args, **kwargs)

    socketmod.socket.send = send
    socketmod.socket.sendall = sendall
    _patch_tls_send(session, rules)
    socketmod._harnis_send = True


def _patch_tls_send(session: Session, rules: Rules) -> None:
    import ssl

    original_send = ssl.SSLSocket.send
    original_sendall = ssl.SSLSocket.sendall

    def send(self, data, flags=0):
        _judge_or_raise(session, rules, Action(kind="socket", body=_body_bytes(data)))
        return original_send(self, data, flags)

    def sendall(self, data, flags=0):
        _judge_or_raise(session, rules, Action(kind="socket", body=_body_bytes(data)))
        return original_sendall(self, data, flags)

    ssl.SSLSocket.send = send
    ssl.SSLSocket.sendall = sendall


def _reinject(args, executable, env):
    parts = _command_parts(args, executable)
    if len(parts) < 2 or not looks_like_python(parts[0]):
        return args, executable, env
    if len(parts) >= 3 and parts[1] == "-c" and parts[2] == BOOTSTRAP:
        return args, executable, env
    merged = os.environ.copy() if env is None else {str(key): str(value) for key, value in env.items()}
    root = str(Path(__file__).resolve().parent.parent)
    merged["PYTHONPATH"] = root + os.pathsep + merged.get("PYTHONPATH", "")
    merged["PYTHONUTF8"] = merged.get("PYTHONUTF8") or "1"
    merged["HARNIS_ENFORCED"] = "1"
    for key in ("HARNIS_REPORT", "HARNIS_LOG", "HARNIS_POLICY"):
        if key in os.environ:
            merged[key] = os.environ[key]
    return [parts[0], "-c", BOOTSTRAP, *parts[1:]], None, merged


def _command_parts(args, executable) -> list[str]:
    if isinstance(args, (list, tuple)):
        parts = [_text(part) for part in args]
    elif isinstance(args, (str, bytes)):
        parts = list(_split_command(_text(args)))
    else:
        parts = []
    if executable and (not parts or not looks_like_python(parts[0])):
        if looks_like_python(_text(executable)):
            parts = [_text(executable), *parts]
    return parts


def popen_command(executable, args) -> tuple[str, ...]:
    if isinstance(args, (list, tuple)):
        command = [_text(part) for part in args]
    elif isinstance(args, (str, bytes)):
        command = list(_split_command(_text(args)))
    else:
        command = []
    if executable and not command:
        command = [_text(executable)]
    return tuple(command)


def _handle(event, args, session: Session, rules: Rules, exempt: set[str]) -> None:
    if event == "open":
        _handle_open(args, session, rules, exempt)
        return
    if event == "subprocess.Popen":
        executable, argv, _cwd, _env = args[:4]
        _judge_or_raise(session, rules, Action(kind="exec", command=popen_command(executable, argv)))
        return
    if event == "os.system":
        command = args[0] if args else ""
        _judge_or_raise(session, rules, Action(kind="exec", command=_system_command(_text(command))))
        return
    if event == "urllib.Request":
        url = args[0] if args else ""
        data = args[1] if len(args) > 1 else b""
        headers = args[2] if len(args) > 2 else None
        _judge_or_raise(
            session,
            rules,
            Action(
                kind="http",
                url=str(url),
                body=_body_bytes(data),
                headers=_header_pairs(headers),
            ),
        )
        return
    if event == "http.client.send":
        connection = args[0] if args else None
        data = args[1] if len(args) > 1 else b""
        _judge_or_raise(
            session,
            rules,
            Action(kind="http", url=_connection_url(connection), body=_body_bytes(data)),
        )
        return
    if event == "ctypes.dlsym":
        name = args[1] if len(args) > 1 else ""
        if isinstance(name, bytes):
            name = name.decode("utf-8", "replace")
        if not isinstance(name, str):
            return
        _judge_or_raise(session, rules, Action(kind="ctypes", symbol=name))


def _handle_open(args, session: Session, rules: Rules, exempt: set[str]) -> None:
    path, mode, flags = (args + (None, None, None))[:3]
    text = _path_text(path)
    if text is None:
        return
    try:
        normalized = os.path.normcase(os.path.abspath(text))
    except (TypeError, ValueError):
        return
    if normalized in exempt:
        return
    kind = "file_write" if _is_write(mode, flags) else "file_read"
    _judge_or_raise(session, rules, Action(kind=kind, path=text))


def _judge_or_raise(session: Session, rules: Rules, action: Action) -> None:
    decision = judge(action, rules)
    if decision.allowed:
        return
    session.record(decision)
    session.write()
    emit(decision)
    raise Blocked(decision)


def _path_text(path) -> str | None:
    if isinstance(path, int):
        return None
    if isinstance(path, bytes):
        return os.fsdecode(path)
    if isinstance(path, os.PathLike):
        return os.fspath(path)
    if isinstance(path, str):
        return path
    return None


def _is_write(mode, flags) -> bool:
    if isinstance(mode, str) and any(mark in mode for mark in "wxa+"):
        return True
    if isinstance(flags, int) and (flags & 3) in {1, 2}:
        return True
    return False


def _system_command(command: str) -> tuple[str, ...]:
    if os.name == "nt":
        shell = os.environ.get("COMSPEC", "cmd.exe")
        return (shell, "/c", command)
    return ("/bin/sh", "-c", command)


def _split_command(text: str) -> list[str]:
    if os.name == "nt":
        return _split_windows(text)
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()


def _split_windows(text: str) -> list[str]:
    import ctypes
    from ctypes import wintypes

    argc = ctypes.c_int()
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell32.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    shell32.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    parsed = shell32.CommandLineToArgvW(text, ctypes.byref(argc))
    if not parsed:
        return text.split()
    try:
        return [parsed[index] for index in range(argc.value)]
    finally:
        kernel32.LocalFree(parsed)


def _text(value) -> str:
    if isinstance(value, bytes):
        return os.fsdecode(value)
    return str(value)


def _body_bytes(data) -> bytes:
    if data is None:
        return b""
    if isinstance(data, str):
        return data.encode("utf-8", "surrogateescape")
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    return b""


def _header_pairs(headers) -> tuple[tuple[str, str], ...]:
    if not headers:
        return ()
    if isinstance(headers, dict):
        pairs = headers.items()
    elif hasattr(headers, "items"):
        pairs = headers.items()
    else:
        return ()
    return tuple((str(key), str(value)) for key, value in pairs)


def _connection_url(connection) -> str:
    if connection is None:
        return ""
    host = getattr(connection, "host", "") or ""
    if not host:
        return ""
    secure = type(connection).__name__.lower().startswith("https")
    scheme = "https" if secure else "http"
    return f"{scheme}://{host}"


def _exec_code(code: str) -> None:
    compiled = compile(code, "<harnis>", "exec")
    exec(compiled, {"__name__": "__main__"})


def _exit_code(value) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    return 1
