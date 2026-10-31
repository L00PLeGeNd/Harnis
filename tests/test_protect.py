"""The protect command is the public seam for a running agent."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def _protect(tmp_path: Path, script: str, *extra: str) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "agent.py"
    path.write_text(script, encoding="utf-8")
    report = tmp_path / "report.html"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "harnis",
            "protect",
            "--report",
            str(report),
            "--",
            sys.executable,
            str(path),
            *extra,
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_protect_blocks_ssh_key_read_and_writes_report(tmp_path: Path):
    key = tmp_path / ".ssh" / "id_rsa"
    key.parent.mkdir()
    key.write_text("not-a-real-key\n", encoding="utf-8")
    script = (
        "from pathlib import Path\n"
        f"print(Path(r'{key}').read_text(encoding='utf-8'))\n"
    )

    result = _protect(tmp_path, script)

    assert result.returncode != 0
    assert "BLOCKED" in result.stderr
    assert "no-credential-access" in result.stderr
    assert "not-a-real-key" not in result.stdout
    assert "not-a-real-key" not in result.stderr
    report = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "BLOCKED" in report
    assert "no-credential-access" in report
    assert "not-a-real-key" not in report


def test_a_caught_denial_still_fails_the_process(tmp_path: Path):
    key = tmp_path / ".ssh" / "id_rsa"
    key.parent.mkdir()
    key.write_text("not-a-real-key\n", encoding="utf-8")
    script = (
        "from pathlib import Path\n"
        "try:\n"
        f"    Path(r'{key}').read_text(encoding='utf-8')\n"
        "except PermissionError:\n"
        "    print('caught')\n"
    )

    result = _protect(tmp_path, script)

    assert result.returncode != 0
    assert result.stdout.strip() == "caught"
    assert "no-credential-access" in result.stderr


def test_protect_blocks_os_system_rm_rf(tmp_path: Path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep\n", encoding="utf-8")
    script = (
        "import os\n"
        f"os.system('rm -rf ' + {str(victim)!r})\n"
        "print('ran')\n"
    )

    result = _protect(tmp_path, script)

    assert "no-destructive-exec" in result.stderr
    assert victim.read_text(encoding="utf-8") == "keep\n"


def test_protect_allows_an_ordinary_script(tmp_path: Path):
    note = tmp_path / "notes.txt"
    note.write_text("hello\n", encoding="utf-8")
    script = f"print(open(r'{note}', encoding='utf-8').read(), end='')"

    result = _protect(tmp_path, script)

    assert result.returncode == 0
    assert result.stdout == "hello\n"
    assert "BLOCKED" not in result.stderr


def test_a_child_python_cannot_read_the_key(tmp_path: Path):
    key = tmp_path / ".ssh" / "id_rsa"
    key.parent.mkdir()
    key.write_text("not-a-real-key\n", encoding="utf-8")
    child = tmp_path / "child.py"
    child.write_text(
        "from pathlib import Path\n"
        f"print(Path({str(key)!r}).read_text(encoding='utf-8'), end='')\n",
        encoding="utf-8",
    )
    script = (
        "import subprocess, sys\n"
        f"subprocess.run([sys.executable, {str(child)!r}])\n"
    )

    result = _protect(tmp_path, script)

    assert result.returncode != 0
    assert "not-a-real-key" not in result.stdout
    assert "not-a-real-key" not in result.stderr
    assert "no-credential-access" in result.stderr
    report = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "no-credential-access" in report
    assert "not-a-real-key" not in report


def test_an_ordinary_child_python_still_runs(tmp_path: Path):
    child = tmp_path / "child.py"
    child.write_text("print('child-ok')\n", encoding="utf-8")
    script = (
        "import subprocess, sys\n"
        f"subprocess.run([sys.executable, {str(child)!r}])\n"
    )

    result = _protect(tmp_path, script)

    assert result.returncode == 0
    assert "child-ok" in result.stdout
    assert "BLOCKED" not in result.stderr


def test_ctypes_cannot_resolve_a_file_api(tmp_path: Path):
    if os.name == "nt":
        script = "import ctypes\nctypes.WinDLL('kernel32').CreateFileW\nprint('resolved')\n"
    else:
        script = "import ctypes\nctypes.CDLL(None).open\nprint('resolved')\n"

    result = _protect(tmp_path, script)

    assert "resolved" not in result.stdout
    assert "no-ctypes-bypass" in result.stderr


def test_raw_socket_send_of_a_private_key_is_blocked(tmp_path: Path):
    import socket
    import threading

    received = bytearray()
    gate = threading.Event()
    holder: dict[str, int] = {}

    def serve() -> None:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(5)
        holder["port"] = server.getsockname()[1]
        gate.set()
        try:
            conn, _addr = server.accept()
        except TimeoutError:
            server.close()
            return
        conn.settimeout(2)
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                received.extend(chunk)
        except TimeoutError:
            pass
        conn.close()
        server.close()

    thread = threading.Thread(target=serve)
    thread.start()
    assert gate.wait(2)
    script = (
        "import socket, sys\n"
        "sock = socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=3)\n"
        "sock.sendall(b'-----BEGIN OPENSSH PRIVATE KEY-----\\nexample-not-a-key\\n')\n"
        "print('sent')\n"
    )

    result = _protect(tmp_path, script, str(holder["port"]))
    thread.join(5)

    assert b"example-not-a-key" not in received
    assert b"BEGIN OPENSSH PRIVATE KEY" not in received
    assert "sent" not in result.stdout
    assert "no-secret-exfil" in result.stderr


def test_raw_socket_send_of_ordinary_text_is_allowed(tmp_path: Path):
    import socket
    import threading

    received = bytearray()
    gate = threading.Event()
    holder: dict[str, int] = {}

    def serve() -> None:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(5)
        holder["port"] = server.getsockname()[1]
        gate.set()
        try:
            conn, _addr = server.accept()
        except TimeoutError:
            server.close()
            return
        conn.settimeout(2)
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                received.extend(chunk)
        except TimeoutError:
            pass
        conn.close()
        server.close()

    thread = threading.Thread(target=serve)
    thread.start()
    assert gate.wait(2)
    script = (
        "import socket, sys\n"
        "sock = socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=3)\n"
        "sock.sendall(b'hello-plain')\n"
        "sock.close()\n"
        "print('sent')\n"
    )

    result = _protect(tmp_path, script, str(holder["port"]))
    thread.join(5)

    assert bytes(received) == b"hello-plain"
    assert result.returncode == 0
    assert "BLOCKED" not in result.stderr


def test_tls_send_of_a_private_key_is_blocked(tmp_path: Path):
    script = (
        "import socket, ssl\n"
        "raw = socket.socket()\n"
        "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
        "wrapped = ctx.wrap_socket(raw, server_hostname='localhost')\n"
        "wrapped.send(b'-----BEGIN OPENSSH PRIVATE KEY-----\\nexample-not-a-key\\n')\n"
        "print('sent')\n"
    )

    result = _protect(tmp_path, script)

    assert "sent" not in result.stdout
    assert "example-not-a-key" not in result.stdout
    assert "no-secret-exfil" in result.stderr


def test_ctypes_can_still_query_the_process_id(tmp_path: Path):
    if os.name == "nt":
        script = "import ctypes\nprint(ctypes.WinDLL('kernel32').GetCurrentProcessId())\n"
    else:
        script = "import ctypes\nprint(ctypes.sizeof(ctypes.c_int))\n"

    result = _protect(tmp_path, script)

    assert result.returncode == 0
    assert result.stdout.strip().isdigit()
    assert "BLOCKED" not in result.stderr


def test_interactive_shell_is_blocked_before_it_reads_stdin(tmp_path: Path):
    if os.name == "nt":
        script = (
            "import os, subprocess\n"
            "proc = subprocess.Popen([os.environ['COMSPEC']], stdin=subprocess.PIPE,\n"
            "    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)\n"
            "out, _err = proc.communicate('echo leaked\\n')\n"
            "print(out)\n"
        )
    else:
        script = (
            "import subprocess\n"
            "proc = subprocess.Popen(['sh'], stdin=subprocess.PIPE,\n"
            "    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)\n"
            "out, _err = proc.communicate('echo leaked\\n')\n"
            "print(out)\n"
        )

    result = _protect(tmp_path, script)

    assert "leaked" not in result.stdout
    assert "no-unbounded-shell" in result.stderr


def test_shell_that_assembles_the_key_path_cannot_read_it(tmp_path: Path):
    key = tmp_path / ".ssh" / "id_rsa"
    key.parent.mkdir()
    key.write_text("not-a-real-key\n", encoding="utf-8")
    parent = str(tmp_path)
    if os.name == "nt":
        script = (
            "import os, subprocess\n"
            f"parent = {parent!r}\n"
            "cmd = 'set A=id_& set B=rsa& set D=.ss& set H=h& type ' + parent + '\\\\%D%%H%\\\\%A%%B%'\n"
            "subprocess.run([os.environ['COMSPEC'], '/c', cmd])\n"
        )
    else:
        script = (
            "import subprocess\n"
            f"parent = {parent!r}\n"
            "cmd = 'a=id_; b=rsa; d=.ss; h=h; cat \"' + parent + '/$d$h/$a$b\"'\n"
            "subprocess.run(['sh', '-c', cmd])\n"
        )

    result = _protect(tmp_path, script)

    assert "not-a-real-key" not in result.stdout
    assert "not-a-real-key" not in result.stderr
    assert "no-opaque-shell" in result.stderr


def test_shell_command_that_names_a_key_is_blocked(tmp_path: Path):
    key = tmp_path / ".ssh" / "id_rsa"
    key.parent.mkdir()
    key.write_text("not-a-real-key\n", encoding="utf-8")
    if os.name == "nt":
        script = (
            "import os, subprocess\n"
            f"subprocess.run([os.environ['COMSPEC'], '/c', 'type ' + {str(key)!r}])\n"
        )
    else:
        script = (
            "import subprocess\n"
            f"subprocess.run(['sh', '-c', 'cat ' + {str(key)!r}])\n"
        )

    result = _protect(tmp_path, script)

    assert "not-a-real-key" not in result.stdout
    assert "not-a-real-key" not in result.stderr
    assert "no-credential-access" in result.stderr


def test_char_code_shell_cannot_read_the_key(tmp_path: Path):
    if os.name != "nt":
        return
    key = tmp_path / ".ssh" / "id_rsa"
    key.parent.mkdir()
    key.write_text("not-a-real-key\n", encoding="utf-8")
    script = (
        "import subprocess\n"
        "subprocess.run(['powershell.exe', '-Command',\n"
        "    \"Get-Content ([char]46+'ssh'+'\\\\id_rsa')\"],\n"
        f"    cwd={str(tmp_path)!r})\n"
    )

    result = _protect(tmp_path, script)

    assert "not-a-real-key" not in result.stdout
    assert "not-a-real-key" not in result.stderr
    assert "no-opaque-shell" in result.stderr


def test_protect_blocks_rm_rf_before_it_runs(tmp_path: Path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep\n", encoding="utf-8")
    script = (
        "import subprocess\n"
        f"subprocess.run(['rm', '-rf', r'{victim}'], check=False)\n"
        "print('ran')\n"
    )

    result = _protect(tmp_path, script)

    assert "no-destructive-exec" in result.stderr
    assert "BLOCKED" in result.stderr
    assert victim.read_text(encoding="utf-8") == "keep\n"
    assert "ran" not in result.stdout


def test_protect_blocks_http_post_of_a_private_key(tmp_path: Path):
    script = """
import urllib.request
body = b"-----BEGIN OPENSSH PRIVATE KEY-----\\nexample\\n"
request = urllib.request.Request(
    "http://127.0.0.1:9/collect",
    data=body,
    method="POST",
)
urllib.request.urlopen(request, timeout=1)
print("sent")
"""

    result = _protect(tmp_path, script)

    assert "no-secret-exfil" in result.stderr
    assert "BLOCKED" in result.stderr
    assert "sent" not in result.stdout
    assert "collect" in result.stderr
