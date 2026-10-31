"""Ptrace supervisor for Linux x86_64.

Same policy as the CPython hook, applied to open, openat, execve, and
execveat in the traced process and its children. A denied call returns
EPERM and the process keeps running. This module imports on any OS;
supervise() is only callable where available() is true.
"""

from __future__ import annotations

import ctypes
import os
import platform
import signal
import sys
from pathlib import Path

from harnis.policy import Action, Rules, judge, load_rules
from harnis.report import Session, emit

SYS_OPEN = 2
SYS_EXECVE = 59
SYS_OPENAT = 257
SYS_EXECVEAT = 322

PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_TRACESYSGOOD = 1
PTRACE_O_TRACEFORK = 2
PTRACE_O_TRACEVFORK = 4
PTRACE_O_TRACECLONE = 8
PTRACE_O_TRACEEXEC = 16
PTRACE_O_EXITKILL = 0x00100000
_OPTIONS = (
    PTRACE_O_TRACESYSGOOD
    | PTRACE_O_TRACEFORK
    | PTRACE_O_TRACEVFORK
    | PTRACE_O_TRACECLONE
    | PTRACE_O_TRACEEXEC
    | PTRACE_O_EXITKILL
)
_EPERM = 13
AT_FDCWD = -100


def available() -> bool:
    if sys.platform != "linux":
        return False
    return platform.machine().lower() in {"x86_64", "amd64"}


def action_for_syscall(
    number: int,
    *,
    path: str = "",
    argv: tuple[str, ...] = (),
    flags: int = 0,
) -> Action | None:
    if number in {SYS_OPEN, SYS_OPENAT}:
        kind = "file_write" if (flags & 3) in {1, 2} else "file_read"
        return Action(kind=kind, path=path)
    if number in {SYS_EXECVE, SYS_EXECVEAT}:
        return Action(kind="exec", command=tuple(argv))
    return None


class _Regs(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


def supervise(command: list[str], report: Path, policy: Path | None) -> int:
    if not available():
        raise OSError("ptrace supervisor requires Linux x86_64")
    rules = load_rules(str(policy) if policy is not None else None)
    session = Session(report)
    pid = os.fork()
    if pid == 0:
        _traceme_and_exec(command)
    code = _trace(pid, rules, session)
    session.write()
    if session.blocked and code == 0:
        return 1
    return code


def _traceme_and_exec(command: list[str]) -> None:
    try:
        libc = _libc()
        if libc.ptrace(PTRACE_TRACEME, 0, None, None) < 0:
            os._exit(127)
        # Stop before execve so the parent can arm PTRACE_O_TRACE* and
        # syscall stops. Without this, the first execve finishes untraced.
        os.kill(os.getpid(), signal.SIGSTOP)
        os.execvp(command[0], list(command))
    finally:
        os._exit(127)


def _trace(root: int, rules: Rules, session: Session) -> int:
    libc = _libc()
    entering: dict[int, bool] = {}
    denied: dict[int, bool] = {}
    armed: set[int] = set()
    root_code = 1
    while True:
        try:
            wpid, status = os.waitpid(-1, 0)
        except ChildProcessError:
            break
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            entering.pop(wpid, None)
            denied.pop(wpid, None)
            if wpid == root:
                root_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1
            continue
        if not os.WIFSTOPPED(status):
            continue
        if wpid not in armed:
            libc.ptrace(PTRACE_SETOPTIONS, wpid, None, ctypes.c_void_p(_OPTIONS))
            armed.add(wpid)
        injected = _on_stop(libc, wpid, status, entering, denied, rules, session)
        libc.ptrace(PTRACE_SYSCALL, wpid, None, ctypes.c_void_p(injected))
    return root_code


def _on_stop(libc, pid: int, status: int, entering, denied, rules: Rules, session: Session) -> int:
    sig = os.WSTOPSIG(status)
    event = status >> 16
    if sig != (signal.SIGTRAP | 0x80):
        if event or sig == signal.SIGTRAP:
            return 0
        return sig
    is_entry = not entering.get(pid, False)
    entering[pid] = is_entry
    if is_entry:
        _on_entry(libc, pid, denied, rules, session)
    elif denied.get(pid):
        regs = _getregs(libc, pid)
        regs.rax = _unsigned(-_EPERM)
        _setregs(libc, pid, regs)
        denied[pid] = False
    return 0


def _on_entry(libc, pid: int, denied, rules: Rules, session: Session) -> None:
    regs = _getregs(libc, pid)
    action = _action_from_regs(libc, pid, regs)
    denied[pid] = False
    if action is None:
        return
    decision = judge(action, rules)
    if decision.allowed:
        return
    regs.orig_rax = _unsigned(-1)
    _setregs(libc, pid, regs)
    denied[pid] = True
    if session.already_recorded(decision):
        return
    session.record(decision)
    session.write()
    emit(decision)


def _action_from_regs(libc, pid: int, regs: _Regs) -> Action | None:
    number = int(regs.orig_rax)
    if number == SYS_OPEN:
        path = _resolve(pid, _read_cstring(libc, pid, int(regs.rdi)), AT_FDCWD)
        return action_for_syscall(number, path=path, flags=int(regs.rsi))
    if number == SYS_OPENAT:
        path = _resolve(pid, _read_cstring(libc, pid, int(regs.rsi)), _signed(int(regs.rdi)))
        return action_for_syscall(number, path=path, flags=int(regs.rdx))
    if number == SYS_EXECVE:
        argv = _read_argv(libc, pid, int(regs.rsi))
        if not argv:
            argv = (_read_cstring(libc, pid, int(regs.rdi)),)
        return action_for_syscall(number, argv=argv)
    if number == SYS_EXECVEAT:
        argv = _read_argv(libc, pid, int(regs.rdx))
        if not argv:
            argv = (_read_cstring(libc, pid, int(regs.rsi)),)
        return action_for_syscall(number, argv=argv)
    return None


def _resolve(pid: int, path: str, dirfd: int) -> str:
    if not path or path.startswith("/"):
        return path
    if dirfd == AT_FDCWD:
        try:
            base = os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            return path
        return os.path.join(base, path)
    try:
        base = os.readlink(f"/proc/{pid}/fd/{dirfd}")
    except OSError:
        return path
    return os.path.join(base, path)


def _read_argv(libc, pid: int, address: int, limit: int = 32) -> tuple[str, ...]:
    if not address:
        return ()
    values = []
    for index in range(limit):
        try:
            pointer = _peek(libc, pid, address + index * 8)
        except OSError:
            break
        if pointer == 0:
            break
        values.append(_read_cstring(libc, pid, pointer, limit=512))
    return tuple(values)


def _read_cstring(libc, pid: int, address: int, limit: int = 4096) -> str:
    if not address:
        return ""
    chunks = []
    read = 0
    while read < limit:
        try:
            word = _peek(libc, pid, address + read)
        except OSError:
            break
        buf = word.to_bytes(8, "little")
        if b"\x00" in buf:
            chunks.append(buf.split(b"\x00", 1)[0])
            break
        chunks.append(buf)
        read += 8
    return b"".join(chunks).decode("utf-8", "surrogateescape")


def _peek(libc, pid: int, address: int) -> int:
    ctypes.set_errno(0)
    word = libc.ptrace(PTRACE_PEEKDATA, pid, ctypes.c_void_p(address), None)
    if word == -1 and ctypes.get_errno():
        raise OSError(ctypes.get_errno(), "ptrace peek")
    return word & ((1 << 64) - 1)


def _getregs(libc, pid: int) -> _Regs:
    regs = _Regs()
    if libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.cast(ctypes.byref(regs), ctypes.c_void_p)) < 0:
        raise OSError(ctypes.get_errno(), "ptrace getregs")
    return regs


def _setregs(libc, pid: int, regs: _Regs) -> None:
    if libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.cast(ctypes.byref(regs), ctypes.c_void_p)) < 0:
        raise OSError(ctypes.get_errno(), "ptrace setregs")


def _libc():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    libc.ptrace.restype = ctypes.c_long
    return libc


def _unsigned(value: int) -> int:
    return value & ((1 << 64) - 1)


def _signed(value: int) -> int:
    if value >= (1 << 63):
        return value - (1 << 64)
    return value
