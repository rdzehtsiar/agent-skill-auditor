// SPDX-License-Identifier: Apache-2.0

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const SUBCOMMANDS = new Set(["scan"]);
const PACKAGE_OWNER = "rdzehtsiar";
const PACKAGE_REPOSITORY = "agent-skill-auditor";
const PACKAGE_NAME = "agent-audit";

function normalizeArgs(args) {
  if (args.length === 0) {
    return ["scan"];
  }

  const first = args[0];
  if (first.startsWith("-") || SUBCOMMANDS.has(first)) {
    return args.slice();
  }

  return ["scan", ...args];
}

function platformAssetName(platform = process.platform, arch = process.arch) {
  const target = platformTarget(platform, arch);
  return `${PACKAGE_NAME}-${target}${platform === "win32" ? ".zip" : ".tar.gz"}`;
}

function platformBinaryName(platform = process.platform) {
  return platform === "win32" ? `${PACKAGE_NAME}.exe` : PACKAGE_NAME;
}

function platformTarget(platform = process.platform, arch = process.arch) {
  const targets = {
    "darwin:arm64": "aarch64-apple-darwin",
    "darwin:x64": "x86_64-apple-darwin",
    "linux:arm64": "aarch64-unknown-linux-gnu",
    "linux:x64": "x86_64-unknown-linux-gnu",
    "win32:x64": "x86_64-pc-windows-msvc",
    "win32:arm64": "aarch64-pc-windows-msvc"
  };
  const target = targets[`${platform}:${arch}`];

  if (!target) {
    throw new Error(`Unsupported platform for agent-audit binary: ${platform}/${arch}`);
  }

  return target;
}

function releaseDownloadUrl(version, platform = process.platform, arch = process.arch) {
  const cleanVersion = version.startsWith("v") ? version : `v${version}`;
  return `https://github.com/${PACKAGE_OWNER}/${PACKAGE_REPOSITORY}/releases/download/${cleanVersion}/${platformAssetName(platform, arch)}`;
}

function resolveBinary(env = process.env, options = {}) {
  const platform = options.platform || process.platform;
  const arch = options.arch || process.arch;
  const currentScript = options.currentScript;
  const packageRoot = options.packageRoot || path.join(__dirname, "..");
  const pathValue = Object.prototype.hasOwnProperty.call(env, "PATH") ? env.PATH : process.env.PATH;
  const pathExt = Object.prototype.hasOwnProperty.call(env, "PATHEXT")
    ? env.PATHEXT
    : process.env.PATHEXT;

  if (env.AGENT_AUDIT_BIN) {
    return validateExecutable(env.AGENT_AUDIT_BIN, "AGENT_AUDIT_BIN");
  }

  const managedBinary = path.join(packageRoot, "bin", platformTarget(platform, arch), platformBinaryName(platform));
  if (isExecutableFile(managedBinary)) {
    return managedBinary;
  }

  const pathBinary = findOnPath(PACKAGE_NAME, pathValue, pathExt, currentScript, platform);
  if (pathBinary) {
    return pathBinary;
  }

  return null;
}

function missingBinaryError(version, platform = process.platform, arch = process.arch) {
  let download;
  try {
    download = releaseDownloadUrl(version, platform, arch);
  } catch (error) {
    download = `unsupported platform ${platform}/${arch}`;
  }

  return [
    "agent-audit npm wrapper could not find the native agent-audit binary.",
    "",
    "Fix one of the following:",
    "  - Set AGENT_AUDIT_BIN to an existing agent-audit executable.",
    "  - Put a native agent-audit executable on PATH.",
    `  - Download the matching release asset: ${download}`,
    "  - Build locally with: cargo build --release -p agent-audit-cli --bin agent-audit",
    "",
    `Current platform: ${platform}/${arch}`
  ].join("\n");
}

function run(args, env = process.env, options = {}) {
  const normalizedArgs = normalizeArgs(args);
  let binary;
  try {
    binary = resolveBinary(env, options);
  } catch (error) {
    return {
      status: 127,
      error: `${error.message}\n\n${missingBinaryError(options.version || packageVersion(options.packageRoot), options.platform, options.arch)}`
    };
  }

  if (!binary) {
    return {
      status: 127,
      error: missingBinaryError(options.version || packageVersion(options.packageRoot), options.platform, options.arch)
    };
  }

  const result = spawnSync(binary, normalizedArgs, {
    stdio: "inherit",
    env
  });

  if (result.error) {
    return {
      status: 127,
      error: `failed to run agent-audit binary at ${binary}: ${result.error.message}`
    };
  }

  return {
    status: result.status === null ? 1 : result.status,
    signal: result.signal
  };
}

function main(args, env = process.env, currentScript = process.argv[1]) {
  const result = run(args, env, { currentScript });

  if (result.error) {
    process.stderr.write(`${result.error}\n`);
  }

  if (result.signal) {
    process.kill(process.pid, result.signal);
  }

  process.exit(result.status);
}

function validateExecutable(candidate, source) {
  if (isExecutableFile(candidate)) {
    return candidate;
  }

  throw new Error(`${source} points to a missing or non-file agent-audit binary: ${candidate}`);
}

function findOnPath(command, pathValue, pathExt, currentScript, platform) {
  if (!pathValue) {
    return null;
  }

  const names = commandNames(command, pathExt, platform);
  const ignored = currentScript ? realpathOrNull(currentScript) : null;

  for (const directory of pathValue.split(path.delimiter)) {
    if (!directory) {
      continue;
    }

    for (const name of names) {
      const candidate = path.join(directory, name);
      if (!isExecutableFile(candidate)) {
        continue;
      }

      if (ignored && realpathOrNull(candidate) === ignored) {
        continue;
      }

      return candidate;
    }
  }

  return null;
}

function commandNames(command, pathExt, platform) {
  if (platform !== "win32") {
    return [command];
  }

  const extensions = (pathExt || ".EXE")
    .split(";")
    .filter(Boolean)
    .map((extension) => extension.toLowerCase())
    .filter((extension) => extension === ".exe");

  return [command, ...extensions.map((extension) => `${command}${extension}`)];
}

function isExecutableFile(candidate) {
  try {
    return fs.statSync(candidate).isFile();
  } catch (error) {
    return false;
  }
}

function realpathOrNull(candidate) {
  try {
    return fs.realpathSync(candidate);
  } catch (error) {
    return null;
  }
}

function packageVersion(packageRoot) {
  try {
    const root = packageRoot || path.join(__dirname, "..");
    return JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8")).version;
  } catch (error) {
    return "0.0.0";
  }
}

module.exports = {
  normalizeArgs,
  platformAssetName,
  platformBinaryName,
  platformTarget,
  releaseDownloadUrl,
  resolveBinary,
  missingBinaryError,
  main,
  run
};
