// SPDX-License-Identifier: Apache-2.0

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const {
  missingBinaryError,
  normalizeArgs,
  platformAssetName,
  platformBinaryName,
  platformTarget,
  releaseDownloadUrl,
  resolveBinary,
  run
} = require("../lib/agent-audit");

test("normalizeArgs keeps explicit subcommands and flags", () => {
  assert.deepEqual(normalizeArgs(["scan", "."]), ["scan", "."]);
  assert.deepEqual(normalizeArgs(["--help"]), ["--help"]);
  assert.deepEqual(normalizeArgs(["-h"]), ["-h"]);
});

test("normalizeArgs prefixes scan for npx path shorthand", () => {
  assert.deepEqual(normalizeArgs([]), ["scan"]);
  assert.deepEqual(normalizeArgs(["."]), ["scan", "."]);
  assert.deepEqual(normalizeArgs(["fixtures/spec/basic", "--format", "json"]), [
    "scan",
    "fixtures/spec/basic",
    "--format",
    "json"
  ]);
});

test("platform mapping returns release asset names", () => {
  assert.equal(platformTarget("linux", "x64"), "x86_64-unknown-linux-gnu");
  assert.equal(platformTarget("linux", "arm64"), "aarch64-unknown-linux-gnu");
  assert.equal(platformTarget("darwin", "x64"), "x86_64-apple-darwin");
  assert.equal(platformTarget("darwin", "arm64"), "aarch64-apple-darwin");
  assert.equal(platformTarget("win32", "x64"), "x86_64-pc-windows-msvc");
  assert.equal(platformTarget("win32", "arm64"), "aarch64-pc-windows-msvc");
  assert.equal(platformBinaryName("win32"), "agent-audit.exe");
  assert.equal(platformBinaryName("linux"), "agent-audit");
  assert.equal(platformAssetName("linux", "x64"), "agent-audit-x86_64-unknown-linux-gnu.tar.gz");
  assert.equal(platformAssetName("win32", "x64"), "agent-audit-x86_64-pc-windows-msvc.zip");
});

test("releaseDownloadUrl maps version to GitHub release asset", () => {
  assert.equal(
    releaseDownloadUrl("0.6.0", "darwin", "arm64"),
    "https://github.com/rdzehtsiar/agent-skill-auditor/releases/download/v0.6.0/agent-audit-aarch64-apple-darwin.tar.gz"
  );
  assert.equal(
    releaseDownloadUrl("v0.6.0", "win32", "x64"),
    "https://github.com/rdzehtsiar/agent-skill-auditor/releases/download/v0.6.0/agent-audit-x86_64-pc-windows-msvc.zip"
  );
});

test("resolveBinary prefers AGENT_AUDIT_BIN", () => {
  const workspace = temporaryDirectory("env-bin");
  const binary = writeExecutable(workspace, "custom-agent-audit");
  const pathBinary = writeExecutable(workspace, "agent-audit");

  assert.equal(
    resolveBinary(
      { AGENT_AUDIT_BIN: binary, PATH: path.dirname(pathBinary) },
      { currentScript: path.join(workspace, "wrapper.js") }
    ),
    binary
  );
});

test("resolveBinary finds PATH binary and skips current wrapper", () => {
  const workspace = temporaryDirectory("path-bin");
  const wrapper = writeExecutable(workspace, "agent-audit");
  const realBinDirectory = fs.mkdtempSync(path.join(workspace, "real-bin-"));
  const realBinary = writeExecutable(realBinDirectory, "agent-audit");

  assert.equal(
    resolveBinary(
      { PATH: [workspace, realBinDirectory].join(path.delimiter) },
      { currentScript: wrapper }
    ),
    realBinary
  );
});

test("resolveBinary tolerates realpath failures while searching PATH", () => {
  const workspace = temporaryDirectory("path-realpath-error");
  const realBinary = writeExecutable(workspace, "agent-audit");
  const originalRealpathSync = fs.realpathSync;
  fs.realpathSync = () => {
    const error = new Error("access denied");
    error.code = "EACCES";
    throw error;
  };

  try {
    assert.equal(
      resolveBinary(
        { PATH: workspace },
        { currentScript: path.join(workspace, "agent-audit-wrapper") }
      ),
      realBinary
    );
  } finally {
    fs.realpathSync = originalRealpathSync;
  }
});

test("resolveBinary returns null when no binary exists", () => {
  const workspace = temporaryDirectory("missing-bin");

  assert.equal(
    resolveBinary(
      { PATH: workspace },
      {
        currentScript: path.join(workspace, "agent-audit"),
        packageRoot: workspace,
        platform: "linux",
        arch: "x64"
      }
    ),
    null
  );
});

test("missing binary error is actionable and offline", () => {
  const message = missingBinaryError("0.6.0", "linux", "x64");

  assert.match(message, /AGENT_AUDIT_BIN/);
  assert.match(message, /PATH/);
  assert.match(message, /cargo build --release -p agent-audit-cli --bin agent-audit/);
  assert.match(message, /agent-audit-x86_64-unknown-linux-gnu\.tar\.gz/);
});

test("run returns missing binary status without network access", () => {
  const workspace = temporaryDirectory("run-missing-bin");
  const result = run(["."], { PATH: workspace }, {
    currentScript: path.join(workspace, "agent-audit"),
    packageRoot: workspace,
    platform: "linux",
    arch: "x64",
    version: "0.6.0"
  });

  assert.equal(result.status, 127);
  assert.match(result.error, /could not find the native agent-audit binary/);
});

test("run reports invalid AGENT_AUDIT_BIN with recovery guidance", () => {
  const workspace = temporaryDirectory("run-invalid-env-bin");
  const missingBinary = path.join(workspace, "missing-agent-audit");
  const result = run(["scan", "."], { AGENT_AUDIT_BIN: missingBinary, PATH: workspace }, {
    packageRoot: workspace,
    platform: "linux",
    arch: "x64",
    version: "0.6.0"
  });

  assert.equal(result.status, 127);
  assert.match(result.error, /AGENT_AUDIT_BIN points to a missing or non-file/);
  assert.match(result.error, /Set AGENT_AUDIT_BIN to an existing agent-audit executable/);
});

test("run keeps missing binary guidance when package metadata is unreadable", () => {
  const workspace = temporaryDirectory("run-unreadable-package-version");
  fs.mkdirSync(path.join(workspace, "package.json"));
  const result = run(["scan", "."], { PATH: workspace }, {
    currentScript: path.join(workspace, "agent-audit"),
    packageRoot: workspace,
    platform: "linux",
    arch: "x64"
  });

  assert.equal(result.status, 127);
  assert.match(result.error, /could not find the native agent-audit binary/);
  assert.match(result.error, /releases\/download\/v0\.0\.0/);
});

test("bin entrypoint returns missing binary guidance instead of wiring errors", () => {
  const workspace = temporaryDirectory("bin-entrypoint");
  const bin = path.join(__dirname, "..", "bin", "agent-audit.js");
  const result = spawnSync(process.execPath, [bin, "."], {
    cwd: workspace,
    env: {
      PATH: workspace
    },
    encoding: "utf8"
  });

  assert.equal(result.status, 127);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /could not find the native agent-audit binary/);
  assert.match(result.stderr, /Set AGENT_AUDIT_BIN to an existing agent-audit executable/);
  assert.doesNotMatch(result.stderr, /TypeError/);
});

function temporaryDirectory(name) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `agent-audit-npm-${name}-`));
}

function writeExecutable(directory, name) {
  const file = path.join(directory, name);
  fs.writeFileSync(file, "#!/bin/sh\nexit 0\n", "utf8");
  fs.chmodSync(file, ownerExecutableMode());
  return file;
}

function ownerExecutableMode() {
  return fs.constants.S_IRUSR | fs.constants.S_IWUSR | fs.constants.S_IXUSR;
}
