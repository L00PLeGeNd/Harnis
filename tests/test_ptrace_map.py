"""Syscall numbers map onto the same decisions as the audit hook."""

import os
from subprocess import list2cmdline

from harnis.linux_ptrace import SYS_EXECVE, SYS_OPENAT, action_for_syscall, available
from harnis.policy import judge
from harnis.runtime import popen_command


def test_ptrace_is_unavailable_off_linux():
    if os.name == "nt":
        assert available() is False


def test_openat_of_ssh_key_uses_credential_policy():
    action = action_for_syscall(SYS_OPENAT, path="/home/agent/.ssh/id_rsa", flags=0)

    decision = judge(action)

    assert decision is not None
    assert decision.allowed is False
    assert decision.policy == "no-credential-access"


def test_execve_of_rm_rf_uses_destructive_policy():
    action = action_for_syscall(SYS_EXECVE, argv=("rm", "-rf", "/tmp/agent-scratch"))

    decision = judge(action)

    assert decision.allowed is False
    assert decision.policy == "no-destructive-exec"


def test_windows_command_line_roundtrip_for_rm_rf():
    if os.name != "nt":
        return
    line = list2cmdline(["rm", "-rf", r"C:\temp\agent scratch"])

    assert popen_command(None, line) == ("rm", "-rf", r"C:\temp\agent scratch")
