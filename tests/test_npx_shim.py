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
    assert "github:L00PLeGeNd/Harnis" in result.stdout
