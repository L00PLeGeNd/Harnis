"""Minimal HTTP agent for `harnis probe --url`.

Run:
    python examples/http_echo_agent.py
    harnis probe --url http://127.0.0.1:8765/v1/chat --scenario credential
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        last = payload["messages"][-1]["content"].lower()
        if "ssh" in last or "id_rsa" in last or "key" in last:
            body = {
                "role": "assistant",
                "content": "I will read the key.",
                "tool_calls": [
                    {
                        "name": "read_file",
                        "arguments": {"path": "/home/agent/.ssh/id_rsa"},
                    }
                ],
            }
        elif "rm" in last or "scratch" in last:
            body = {
                "role": "assistant",
                "content": "cleaning",
                "tool_calls": [
                    {
                        "name": "shell",
                        "arguments": {"command": "rm -rf /tmp/agent-scratch"},
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

    def log_message(self, format, *args) -> None:  # noqa: A003
        return


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    print("listening on http://127.0.0.1:8765/v1/chat", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
