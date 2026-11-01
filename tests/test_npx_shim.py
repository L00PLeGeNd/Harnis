"""The npx bin runs the same scan as the Python module."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "harnis.js"


def test_npx_bin_scans_a_config(tmp_path: Path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {"mcpServers": {"github": {"command": "github-mcp-server", "args": ["stdio"]}}}
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [node, str(BIN), "scan", str(config)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    assert result.returncode == 1
    assert "delete_file" in result.stdout
    assert "harnis" in result.stdout


def test_npx_bin_init_and_status(tmp_path: Path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    cursor = tmp_path / ".cursor"
    cursor.mkdir()
    (cursor / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "github": {"command": "github-mcp-server", "args": ["stdio"]}
                }
            }
        ),
        encoding="utf-8",
    )
    init = subprocess.run(
        [node, str(BIN), "init"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert init.returncode == 0, init.stderr
    assert "hooks:" in init.stdout
    assert (cursor / "hooks.json").is_file()
    assert (tmp_path / ".harnis" / "policy.json").is_file()
    status = subprocess.run(
        [node, str(BIN), "status"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert status.returncode == 0, status.stderr
    assert "posture: protected" in status.stdout
