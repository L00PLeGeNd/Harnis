#!/usr/bin/env node
"use strict";

const { spawn, spawnSync } = require("child_process");
const path = require("path");

const src = path.resolve(__dirname, "..", "src");
const names = process.platform === "win32" ? ["py", "python", "python3"] : ["python3", "python"];
const probe = "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)";

function python() {
  for (const name of names) {
    const result = spawnSync(name, ["-c", probe], { stdio: "ignore" });
    if (result.status === 0) {
      return name;
    }
  }
  return "";
}

const executable = python();
if (!executable) {
  process.stderr.write("harnis: Python 3.11 or newer is required\n");
  process.exit(1);
}

const env = Object.assign({}, process.env, { PYTHONUTF8: "1" });
env.PYTHONPATH = env.PYTHONPATH ? src + path.delimiter + env.PYTHONPATH : src;

const child = spawn(executable, ["-m", "harnis"].concat(process.argv.slice(2)), {
  stdio: "inherit",
  env: env,
  windowsHide: true,
});

child.on("error", function () {
  process.stderr.write("harnis: Python 3.11 or newer is required\n");
  process.exit(1);
});

child.on("exit", function (code, signal) {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code === null ? 1 : code);
});
