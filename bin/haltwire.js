#!/usr/bin/env node
// haltwire -- npx launcher for the haltwire CLI.
// CommonJS, zero dependencies.  Uses `uv tool install` (persistent) instead
// of `uvx --from` (ephemeral cache) so hook commands survive cache clean/prune.
"use strict";

const { spawnSync } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const REPO_URL = "https://github.com/Boredem125/haltwire";
const pkg = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8")
);
const VERSION = pkg.version;
const IS_WIN = process.platform === "win32";

// On Windows only accept real .exe/.com -- refuse .cmd/.bat (metacharacter
// injection through cmd.exe /c).
const _SAFE_EXTS = IS_WIN ? [".exe", ".com"] : [""];

// ---------------------------------------------------------------------------
// PATH search helpers
// ---------------------------------------------------------------------------

/**
 * Convert an MSYS/Git-Bash-style path to a Windows path.
 * /d/tools/uv  ->  D:\tools\uv
 * /c/Users/... ->  C:\Users\...
 * Leaves normal Windows paths and POSIX paths untouched.
 */
function _msysToWin(p) {
  // Match /x/... where x is a single letter (drive letter).
  var m = /^\/([A-Za-z])(\/.*)?$/.exec(p);
  if (m) return m[1].toUpperCase() + ":" + (m[2] || "\\").replace(/\//g, "\\");
  return p;
}

/**
 * Split PATH, handling both `;` (Windows native) and `:` (MSYS / Git Bash).
 * On win32, if PATH contains no `;` but does contain `:` after the first
 * two chars (ruling out `C:\...`), split on `:` and convert MSYS paths.
 */
function _splitPath(pathStr) {
  if (!pathStr) return [];
  if (!IS_WIN) return pathStr.split(":").filter(Boolean);
  // Normal Windows PATH uses `;`.
  if (pathStr.indexOf(";") >= 0) {
    return pathStr.split(";").filter(Boolean);
  }
  // No semicolons -- possibly MSYS colon-separated PATH.
  // Split on `:` that is NOT immediately after a drive letter (X:).
  var parts = pathStr.split(":").filter(Boolean);
  var result = [];
  for (var i = 0; i < parts.length; i++) {
    // If the part is a single letter and the next part starts with \\ or /,
    // rejoin them as a drive letter.
    if (parts[i].length === 1 && /^[A-Za-z]$/.test(parts[i]) && i + 1 < parts.length) {
      result.push(parts[i] + ":" + parts[i + 1]);
      i++;
    } else {
      result.push(_msysToWin(parts[i]));
    }
  }
  return result.filter(Boolean);
}

/** Find an executable *name* on PATH (or a single *override* dir). */
function _findOnPath(name, override) {
  var dirs = override
    ? [override]
    : _splitPath(process.env.PATH || "");
  for (var i = 0; i < dirs.length; i++) {
    var dir = IS_WIN ? _msysToWin(dirs[i]) : dirs[i];
    for (var j = 0; j < _SAFE_EXTS.length; j++) {
      var p = path.join(dir, name + _SAFE_EXTS[j]);
      try { fs.accessSync(p, fs.constants.F_OK); return p; } catch (_) {}
    }
  }
  return null;
}

/**
 * Resolve the package manager: uv or pipx.
 * Returns { manager: "uv"|"pipx", path: string } or null.
 * Exported for unit testing.
 */
function _resolveRunner(pathOverride) {
  for (var k = 0; k < 2; k++) {
    var name = k === 0 ? "uv" : "pipx";
    var found = _findOnPath(name, pathOverride);
    if (found) return { manager: name, path: found };
  }

  // Windows: check for .cmd/.bat fallback for a helpful error message.
  if (IS_WIN && !pathOverride) {
    var dirs = _splitPath(process.env.PATH || "");
    for (var n = 0; n < 2; n++) {
      var nm = n === 0 ? "uv" : "pipx";
      for (var d = 0; d < dirs.length; d++) {
        for (var ext of [".cmd", ".bat"]) {
          var c = path.join(dirs[d], nm + ext);
          try { fs.accessSync(c, fs.constants.F_OK); _resolveRunner._cmdFallback = c; return null; } catch (_) {}
        }
      }
    }
  }
  _resolveRunner._cmdFallback = null;
  return null;
}
_resolveRunner._cmdFallback = null;

// ---------------------------------------------------------------------------
// Persistent install via uv tool / pipx
// ---------------------------------------------------------------------------

/**
 * Ensure haltwire is persistently installed at the right ref/version.
 * Returns the absolute path to the installed haltwire binary.
 *
 * @param {{ manager: string, path: string }} mgr - resolved manager
 * @param {string} gitSpec - e.g. "git+https://...@v0.1.0"
 * @param {string} ref     - the ref/version string
 * @returns {string} absolute path to installed haltwire binary
 */
function _ensureInstalled(mgr, gitSpec, ref) {
  if (mgr.manager === "uv") {
    return _ensureUv(mgr.path, gitSpec, ref);
  }
  return _ensurePipx(mgr.path, gitSpec, ref);
}

function _ensureUv(uvPath, gitSpec, ref) {
  // Check if already installed with the right version.
  var list = spawnSync(uvPath, ["tool", "list"], {
    encoding: "utf8", timeout: 15000, stdio: ["pipe", "pipe", "pipe"]
  });
  var listOut = (list.stdout || "") + (list.stderr || "");
  // `uv tool list` output: "haltwire v0.1.0\n  - haltwire\n  - sandbox\n"
  if (list.status === 0 && _uvToolListHasVersion(listOut, ref)) {
    // Already installed at the right version -- skip reinstall.
  } else {
    var inst = spawnSync(uvPath, ["tool", "install", "--force", gitSpec], {
      stdio: "inherit", timeout: 120000
    });
    if (inst.status !== 0) {
      process.stderr.write("uv tool install failed (exit " + (inst.status || "null") + ")\n");
      process.exit(inst.status || 1);
    }
  }

  // Get the tool bin dir.
  var binDir = spawnSync(uvPath, ["tool", "dir", "--bin"], {
    encoding: "utf8", timeout: 10000, stdio: ["pipe", "pipe", "pipe"]
  });
  var toolBin = (binDir.stdout || "").trim();
  if (!toolBin || binDir.status !== 0) {
    process.stderr.write("Could not determine uv tool bin dir\n");
    process.exit(1);
  }

  var hwBin = path.join(toolBin, IS_WIN ? "haltwire.exe" : "haltwire");
  if (!_fileExists(hwBin)) {
    process.stderr.write("haltwire not found at " + hwBin + " after install\n");
    process.exit(1);
  }

  _hintPathIfNeeded(toolBin);
  return hwBin;
}

/** Check whether `uv tool list` output shows haltwire at the given ref. */
function _uvToolListHasVersion(output, ref) {
  // Match "haltwire v0.1.0" or "haltwire 0.1.0" (uv prints with/without v).
  var ver = ref.replace(/^v/, "");
  var re = new RegExp("haltwire\\s+v?" + _escapeRegex(ver) + "\\b");
  return re.test(output);
}

function _ensurePipx(pipxPath, gitSpec, ref) {
  // pipx install --force git+...@ref
  var inst = spawnSync(pipxPath, ["install", "--force", gitSpec], {
    stdio: "inherit", timeout: 120000
  });
  if (inst.status !== 0) {
    process.stderr.write("pipx install failed (exit " + (inst.status || "null") + ")\n");
    process.exit(inst.status || 1);
  }

  // Get the bin dir.
  var env = spawnSync(pipxPath, ["environment", "--value", "PIPX_BIN_DIR"], {
    encoding: "utf8", timeout: 10000, stdio: ["pipe", "pipe", "pipe"]
  });
  var binDir = (env.stdout || "").trim();
  if (!binDir || env.status !== 0) {
    process.stderr.write("Could not determine pipx bin dir\n");
    process.exit(1);
  }

  var hwBin = path.join(binDir, IS_WIN ? "haltwire.exe" : "haltwire");
  if (!_fileExists(hwBin)) {
    process.stderr.write("haltwire not found at " + hwBin + " after install\n");
    process.exit(1);
  }

  _hintPathIfNeeded(binDir);
  return hwBin;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function _fileExists(p) {
  try { fs.accessSync(p, fs.constants.F_OK); return true; } catch (_) { return false; }
}

function _escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** If the tool bin dir is not on PATH, print one clear line. */
function _hintPathIfNeeded(binDir) {
  var dirs = (process.env.PATH || "").split(path.delimiter);
  var normalBin = path.resolve(binDir);
  for (var i = 0; i < dirs.length; i++) {
    try { if (path.resolve(dirs[i]) === normalBin) return; } catch (_) {}
  }
  process.stderr.write(
    "Note: " + binDir + " is not on your PATH.\n" +
    "  Run `uv tool update-shell` or add it manually so `haltwire watch` works in new terminals.\n"
  );
}

// ---------------------------------------------------------------------------
// Install helper (--install-uv)
// ---------------------------------------------------------------------------

function _installCommand() {
  if (IS_WIN) {
    return 'powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"';
  }
  return "curl -LsSf https://astral.sh/uv/install.sh | sh";
}

function handleInstallUv(args) {
  var hasYes = args.includes("--yes");
  var isTTY = process.stdin.isTTY && process.stdout.isTTY;

  if (!isTTY && !hasYes) {
    process.stderr.write(
      "Error: --install-uv requires an interactive terminal or --yes.\n" +
        "Re-run with --install-uv --yes to skip the prompt.\n"
    );
    process.exit(1);
  }

  var cmd = _installCommand();
  process.stdout.write("This will run:\n  " + cmd + "\n");

  if (hasYes) {
    _runInstaller();
    return;
  }

  var rl = require("node:readline").createInterface({
    input: process.stdin, output: process.stdout,
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
    result = spawnSync("powershell",
      ["-ExecutionPolicy", "ByPass", "-c", "irm https://astral.sh/uv/install.ps1 | iex"],
      { stdio: "inherit", shell: false });
  } else {
    result = spawnSync("sh",
      ["-c", "curl -LsSf https://astral.sh/uv/install.sh | sh"],
      { stdio: "inherit", shell: false });
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
  var args = process.argv.slice(2);

  // Handle --install-uv early.
  if (args.includes("--install-uv")) {
    handleInstallUv(args);
    return;
  }

  // Resolve package manager.
  var mgr = _resolveRunner();
  if (!mgr) {
    var cmd = _installCommand();
    if (_resolveRunner._cmdFallback) {
      process.stderr.write(
        "Found " + _resolveRunner._cmdFallback + " but haltwire needs uv.exe " +
        "(not a .cmd wrapper) for safe argument passing.\n" +
        "Install uv:\n  " + cmd + "\n"
      );
    } else {
      process.stderr.write(
        "Neither uv nor pipx found on PATH.\nInstall uv:\n  " + cmd + "\n"
      );
    }
    process.exit(1);
  }

  // Determine git ref.
  var envRef = process.env.HALTWIRE_REF;
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

  var gitSpec = "git+" + REPO_URL + "@" + ref;

  // Ensure persistent install, get the installed binary path.
  var hwBin = _ensureInstalled(mgr, gitSpec, ref);

  // Build haltwire args.
  var hwArgs;
  if (args.length === 0) {
    hwArgs = ["--help"];
  } else if (args[0] === "init" && args.length === 1) {
    hwArgs = ["init", "."];
  } else {
    hwArgs = args;
  }

  // Run the installed binary.
  var result = spawnSync(hwBin, hwArgs, { stdio: "inherit", shell: false });

  if (result.signal) {
    process.kill(process.pid, result.signal);
  }
  process.exit(result.status != null ? result.status : 1);
}

// Guard: only run main when this file is the entry point.
if (require.main === module) {
  main();
}

// Export for unit testing.
module.exports = { _resolveRunner, _ensureInstalled, _uvToolListHasVersion, _msysToWin, _splitPath };
