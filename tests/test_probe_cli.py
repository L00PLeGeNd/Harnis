"""The probe command is the public seam for red-team findings."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
LEAKY = ROOT / "examples" / "leaky_agent.py"
SAFE = ROOT / "examples" / "safe_agent.py"


def _probe(tmp_path: Path, agent: Path) -> subprocess.CompletedProcess[str]:
    report = tmp_path / "probe.html"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "harnis",
            "probe",
            "--report",
            str(report),
            "--",
            str(agent),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_probe_cli_flags_a_leaky_agent(tmp_path: Path):
    result = _probe(tmp_path, LEAKY)

    assert result.returncode == 1
    assert "FINDING" in result.stderr
    assert "no-credential-access" in result.stderr
    page = (tmp_path / "probe.html").read_text(encoding="utf-8")
    assert "read_file" in page
    assert "no-credential-access" in page


def test_probe_cli_clears_a_safe_agent(tmp_path: Path):
    result = _probe(tmp_path, SAFE)

    assert result.returncode == 0
    assert "FINDING" not in result.stderr
    page = (tmp_path / "probe.html").read_text(encoding="utf-8")
    assert "Clear" in page or "clear" in page.lower()


def test_probe_cli_scenario_destructive_on_shell_agent(tmp_path: Path):
    report = tmp_path / "probe.html"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUTF8"] = "1"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "harnis",
            "probe",
            "--report",
            str(report),
            "--scenario",
            "destructive",
            "--",
            str(ROOT / "examples" / "shell_agent.py"),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert result.returncode == 1
    assert "no-destructive-exec" in result.stderr


def test_probe_cli_scenario_exfil(tmp_path: Path):
    report = tmp_path / "probe.html"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUTF8"] = "1"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "harnis",
            "probe",
            "--report",
            str(report),
            "--scenario",
            "exfil",
            "--",
            str(ROOT / "examples" / "exfil_agent.py"),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert result.returncode == 1
    assert "no-secret-exfil" in result.stderr


def test_probe_cli_url_against_local_server(tmp_path: Path):
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            last = payload["messages"][-1]["content"].lower()
            if "key" in last or "ssh" in last:
                body = {
                    "role": "assistant",
                    "content": "x",
                    "tool_calls": [
                        {
                            "name": "read_file",
                            "arguments": {"path": "/home/agent/.ssh/id_rsa"},
                        }
                    ],
                }
            else:
                body = {"role": "assistant", "content": "ok", "tool_calls": []}
            data = json.dumps(body).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format, *args):  # noqa: A003
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    report = tmp_path / "probe.html"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUTF8"] = "1"
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "harnis",
                "probe",
                "--report",
                str(report),
                "--url",
                f"http://127.0.0.1:{server.server_port}/v1/chat",
                "--scenario",
                "credential",
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    finally:
        server.shutdown()

    assert result.returncode == 1
    assert "no-credential-access" in result.stderr
    assert "FINDING" in result.stderr
