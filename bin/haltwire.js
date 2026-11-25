#!/usr/bin/env node
// haltwire -- npx launcher for the haltwire CLI.
// CommonJS, zero dependencies. Derives name and repo from package.json.
"use strict";

const { spawnSync } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");

// ---------------------------------------------------------------------------
// Single constant for the repo URL -- everything else derives from package.json
// ---------------------------------------------------------------------------
const REPO_URL = "https://github.com/Boredem125/haltwire";

// Read version from package.json (one directory up from bin/)
const pkg = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8")
);
const VERSION = pkg.version;

// ---------------------------------------------------------------------------
// Resolver: find uvx or pipx on PATH
// ---------------------------------------------------------------------------

const IS_WIN = process.platform === "win32";

// On Windows, only accept real executables (.exe, .com).  Refusing .cmd/.bat
// avoids the need for cmd.exe /c which exposes metacharacter injection
// (& | > < ^ %) -- user arguments would be interpreted as shell operators.
const _SAFE_EXTS = IS_WIN ? [".exe", ".com"] : [""];

/**
 * Resolve uvx or pipx on PATH. Exported for unit testing.
 *
 * @param {string} [pathOverride] - if provided, search only this single
 *   directory (used by tests); otherwise search the full PATH.
 * @returns {{ runner: "uvx"|"pipx", path: string } | null}
 */
function _resolveRunner(pathOverride) {
  const dirs = pathOverride
    ? [pathOverride]
    : (process.env.PATH || "").split(path.delimiter).filter(Boolean);

  for (const name of ["uvx", "pipx"]) {
    for (const dir of dirs) {
      for (const ext of _SAFE_EXTS) {
        const candidate = path.join(dir, name + ext);
        try {
          fs.accessSync(candidate, fs.constants.F_OK);
          return { runner: name, path: candidate };
        } catch (_) {
          // not found, try next
        }
      }
    }
  }

  // On Windows, check whether a .cmd/.bat wrapper exists so we can give a
  // specific diagnostic instead of a generic "not found".
  if (IS_WIN) {
    for (const name of ["uvx", "pipx"]) {
      for (const dir of dirs) {
        for (const ext of [".cmd", ".bat"]) {
          var candidate = path.join(dir, name + ext);
          try {
            fs.accessSync(candidate, fs.constants.F_OK);
            _resolveRunner._cmdFallback = candidate;
            return null;
          } catch (_) {}
        }
      }
    }
  }

  _resolveRunner._cmdFallback = null;
  return null;
}
_resolveRunner._cmdFallback = null;

// ---------------------------------------------------------------------------
// Install helper
// ---------------------------------------------------------------------------

function _installCommand() {
  if (IS_WIN) {
    return 'powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"';
  }
  return "curl -LsSf https://astral.sh/uv/install.sh | sh";
}

function handleInstallUv(args) {
  const hasYes = args.includes("--yes");
  const isTTY = process.stdin.isTTY && process.stdout.isTTY;

  if (!isTTY && !hasYes) {
    process.stderr.write(
      "Error: --install-uv requires an interactive terminal or --yes.\n" +
        "Re-run with --install-uv --yes to skip the prompt.\n"
    );
    process.exit(1);
  }

  const cmd = _installCommand();
  process.stdout.write("This will run:\n  " + cmd + "\n");

  if (hasYes) {
    _runInstaller();
    return;
  }

  // Interactive confirmation
  const rl = require("node:readline").createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  rl.question("Continue? [y/N] ", function (answer) {
    rl.close();
    if (answer.toLowerCase() !== "y") {
      process.stdout.write("Aborted.\n");
      process.exit(1);
    }
    _runInstaller();
  });
}

function _runInstaller() {
  var result;
  if (IS_WIN) {
    result = spawnSync(
      "powershell",
      ["-ExecutionPolicy", "ByPass", "-c", "irm https://astral.sh/uv/install.ps1 | iex"],
      { stdio: "inherit", shell: false }
    );
  } else {
    result = spawnSync(
      "sh",
      ["-c", "curl -LsSf https://astral.sh/uv/install.sh | sh"],
      { stdio: "inherit", shell: false }
    );
  }
  process.exit(result.status != null ? result.status : 1);
}

// ---------------------------------------------------------------------------
// Ref validation
// ---------------------------------------------------------------------------

function validateRef(ref) {
  return /^[A-Za-z0-9._\/-]+$/.test(ref);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const args = process.argv.slice(2);

  // Handle --install-uv early
  if (args.includes("--install-uv")) {
    handleInstallUv(args);
    return;
  }

  // Resolve runner
  const found = _resolveRunner();
  if (!found) {
    var cmd = _installCommand();
    if (_resolveRunner._cmdFallback) {
      // A .cmd/.bat wrapper exists but we refuse it (metacharacter injection
      // risk when arguments are relayed through cmd.exe /c).
      process.stderr.write(
        "Found " + _resolveRunner._cmdFallback + " but haltwire needs uvx.exe " +
        "(not a .cmd wrapper) for safe argument passing.\n" +
        "Install uv:\n  " + cmd + "\n"
      );
    } else {
      process.stderr.write(
        "Neither uvx nor pipx found on PATH.\nInstall uv:\n  " + cmd + "\n"
      );
    }
    process.exit(1);
  }

  // Determine git ref
  const envRef = process.env.HALTWIRE_REF;
  var ref;
  if (envRef) {
    if (!validateRef(envRef)) {
      process.stderr.write(
        'Invalid HALTWIRE_REF: "' + envRef + '". Only [A-Za-z0-9._/-] allowed.\n'
      );
      process.exit(1);
    }
    ref = envRef;
  } else {
    ref = "v" + VERSION;
  }

  const gitSpec = "git+" + REPO_URL + "@" + ref;

  // Build the haltwire args
  var hwArgs;
  if (args.length === 0) {
    hwArgs = ["--help"];
  } else if (args[0] === "init" && args.length === 1) {
    hwArgs = ["init", "."];
  } else {
    hwArgs = args;
  }

  // Build the spawn command
  var allArgs;
  if (found.runner === "uvx") {
    allArgs = [found.path, "--from", gitSpec, "haltwire"].concat(hwArgs);
  } else {
    // pipx run --spec <spec> haltwire <args>
    allArgs = [found.path, "run", "--spec", gitSpec, "haltwire"].concat(hwArgs);
  }

  // Spawn the resolved executable directly -- no cmd.exe /c needed because
  // the resolver only accepts real .exe/.com (not .cmd/.bat).
  var result = spawnSync(allArgs[0], allArgs.slice(1), {
    stdio: "inherit",
    shell: false,
  });

  // Propagate signals
  if (result.signal) {
    process.kill(process.pid, result.signal);
  }

  process.exit(result.status != null ? result.status : 1);
}

// Guard: only run main when this file is the entry point
if (require.main === module) {
  main();
}

// Export for unit testing
module.exports = { _resolveRunner };
