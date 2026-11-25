// Tests for bin/haltwire.js -- node:test, no network, cross-platform.
//
// The launcher now uses `uv tool install` (persistent) instead of `uvx --from`
// (ephemeral).  Fake uv/pipx scripts simulate the subcommands: tool install,
// tool list, tool dir --bin, and an installed haltwire binary that records argv.
//
// On POSIX the fakes are shell scripts.  On Windows we cannot cheaply create a
// real .exe that records arguments, so integration tests are POSIX-only; Windows
// exercises the resolver unit tests, .cmd refusal, and error/help paths.
"use strict";

const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { execFileSync } = require("node:child_process");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const IS_WIN = process.platform === "win32";
const NODE = process.execPath;
const NODE_DIR = path.dirname(NODE);
const TMPBASE = process.env.TMP || process.env.TEMP || os.tmpdir();

function mkTmp(label) {
  return fs.mkdtempSync(path.join(TMPBASE, "haltwire-test-" + label + "-"));
}

/**
 * Build a fake `uv` script that handles the subcommands haltwire.js uses:
 *   tool list    -> prints toolListOutput
 *   tool install -> writes "installed" marker + exits 0
 *   tool dir --bin -> prints binDir
 * Also builds a fake installed `haltwire` in binDir that records argv.
 *
 * POSIX only.
 */
function buildFakeUv(dir, opts) {
  if (IS_WIN) throw new Error("buildFakeUv: POSIX only");
  opts = opts || {};
  var binDir = opts.binDir || path.join(dir, "toolbin");
  var argvFile = opts.argvFile || path.join(dir, "argv.json");
  var toolListOutput = opts.toolListOutput || "";
  var installMarker = path.join(dir, "install-called");
  var installExit = opts.installExit != null ? opts.installExit : 0;

  fs.mkdirSync(binDir, { recursive: true });

  // Fake uv: a shell script that dispatches on $1 $2.
  var uvScript = '#!/bin/sh\n' +
    'if [ "$1" = "tool" ] && [ "$2" = "list" ]; then\n' +
    '  printf "%s\\n" ' + JSON.stringify(toolListOutput) + '\n' +
    '  exit 0\n' +
    'fi\n' +
    'if [ "$1" = "tool" ] && [ "$2" = "install" ]; then\n' +
    '  printf "installed\\n" > ' + JSON.stringify(installMarker) + '\n' +
    '  # write all args so tests can inspect\n' +
    '  printf "%s\\n" "$@" > ' + JSON.stringify(installMarker + ".args") + '\n' +
    '  exit ' + installExit + '\n' +
    'fi\n' +
    'if [ "$1" = "tool" ] && [ "$2" = "dir" ]; then\n' +
    '  printf "%s\\n" ' + JSON.stringify(binDir) + '\n' +
    '  exit 0\n' +
    'fi\n' +
    'echo "fake uv: unknown command $@" >&2\n' +
    'exit 1\n';
  var uvPath = path.join(dir, "uv");
  fs.writeFileSync(uvPath, uvScript, { mode: 0o755 });

  // Fake installed haltwire that records argv.
  var hwEsc = argvFile.replace(/'/g, "'\\''");
  var hwScript = '#!/bin/sh\n"' + NODE + '" -e "' +
    "fs=require('fs');" +
    "fs.writeFileSync('" + hwEsc + "',JSON.stringify({argv:process.argv.slice(1)}));" +
    "process.exit(0)" +
    '" -- "$@"\n';
  var hwPath = path.join(binDir, "haltwire");
  fs.writeFileSync(hwPath, hwScript, { mode: 0o755 });

  return {
    uvPath: uvPath,
    binDir: binDir,
    argvFile: argvFile,
    installMarker: installMarker,
    hwPath: hwPath,
  };
}

/**
 * Build a fake `pipx` script similar to buildFakeUv but for the pipx path:
 *   install --force ... -> marker
 *   environment --value PIPX_BIN_DIR -> binDir
 */
function buildFakePipx(dir, opts) {
  if (IS_WIN) throw new Error("buildFakePipx: POSIX only");
  opts = opts || {};
  var binDir = opts.binDir || path.join(dir, "pipxbin");
  var argvFile = opts.argvFile || path.join(dir, "argv.json");
  var installMarker = path.join(dir, "install-called");

  fs.mkdirSync(binDir, { recursive: true });

  var pipxScript = '#!/bin/sh\n' +
    'if [ "$1" = "install" ]; then\n' +
    '  printf "installed\\n" > ' + JSON.stringify(installMarker) + '\n' +
    '  exit 0\n' +
    'fi\n' +
    'if [ "$1" = "environment" ]; then\n' +
    '  printf "%s\\n" ' + JSON.stringify(binDir) + '\n' +
    '  exit 0\n' +
    'fi\n' +
    'exit 1\n';
  var pipxPath = path.join(dir, "pipx");
  fs.writeFileSync(pipxPath, pipxScript, { mode: 0o755 });

  // Fake installed haltwire.
  var hwEsc = argvFile.replace(/'/g, "'\\''");
  var hwScript = '#!/bin/sh\n"' + NODE + '" -e "' +
    "fs=require('fs');" +
    "fs.writeFileSync('" + hwEsc + "',JSON.stringify({argv:process.argv.slice(1)}));" +
    "process.exit(0)" +
    '" -- "$@"\n';
  fs.writeFileSync(path.join(binDir, "haltwire"), hwScript, { mode: 0o755 });

  return { pipxPath: pipxPath, binDir: binDir, argvFile: argvFile, installMarker: installMarker };
}

/** Build a fake installed haltwire that exits with a given code (POSIX). */
function buildFakeHwExit(binDir, exitCode) {
  if (IS_WIN) throw new Error("POSIX only");
  var hw = path.join(binDir, "haltwire");
  fs.writeFileSync(hw, "#!/bin/sh\nexit " + exitCode + "\n", { mode: 0o755 });
}

/** Run bin/haltwire.js as a child process. */
function run(args, env, opts) {
  var bin = path.resolve(__dirname, "..", "..", "bin", "haltwire.js");
  var merged = Object.assign({}, process.env, { TMP: TMPBASE, TEMP: TMPBASE }, env);
  if (merged.PATH && merged.PATH.indexOf(NODE_DIR) === -1) {
    merged.PATH = merged.PATH + path.delimiter + NODE_DIR;
  }
  try {
    var stdout = execFileSync(NODE, [bin].concat(args), Object.assign({
      env: merged, timeout: 30000, encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    }, opts || {}));
    return { stdout: stdout, stderr: "", status: 0 };
  } catch (err) {
    return { stdout: err.stdout || "", stderr: err.stderr || "",
             status: err.status != null ? err.status : 1 };
  }
}

// ---------------------------------------------------------------------------
// Unit tests for the resolver
// ---------------------------------------------------------------------------

var mod = require("../../bin/haltwire.js");

describe("_resolveRunner (unit)", function () {
  it("finds uv when uv is on PATH", function () {
    var tmp = mkTmp("resolver-uv");
    try {
      if (IS_WIN) {
        fs.writeFileSync(path.join(tmp, "uv.exe"), "");
      } else {
        fs.writeFileSync(path.join(tmp, "uv"), "#!/bin/sh\n", { mode: 0o755 });
      }
      var r = mod._resolveRunner(tmp);
      assert.equal(r.manager, "uv");
      assert.ok(r.path.includes(tmp));
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });

  it("falls back to pipx when uv is missing", function () {
    var tmp = mkTmp("resolver-pipx");
    try {
      if (IS_WIN) {
        fs.writeFileSync(path.join(tmp, "pipx.exe"), "");
      } else {
        fs.writeFileSync(path.join(tmp, "pipx"), "#!/bin/sh\n", { mode: 0o755 });
      }
      var r = mod._resolveRunner(tmp);
      assert.equal(r.manager, "pipx");
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });

  it("returns null when neither uv nor pipx exists", function () {
    var tmp = mkTmp("resolver-none");
    try {
      var r = mod._resolveRunner(tmp);
      assert.equal(r, null);
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });

  it("ignores .cmd on Windows", { skip: !IS_WIN && "Windows only" }, function () {
    var tmp = mkTmp("resolver-cmd");
    try {
      fs.writeFileSync(path.join(tmp, "uv.cmd"), "@echo off\r\n");
      var r = mod._resolveRunner(tmp);
      assert.equal(r, null);
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });
});

// ---------------------------------------------------------------------------
// Unit test for the tool-list version check
// ---------------------------------------------------------------------------

describe("_uvToolListHasVersion (unit)", function () {
  it("matches haltwire v0.1.0", function () {
    assert.ok(mod._uvToolListHasVersion("haltwire v0.1.0\n- haltwire\n- sandbox", "v0.1.0"));
  });
  it("matches without v prefix", function () {
    assert.ok(mod._uvToolListHasVersion("haltwire 0.1.0\n", "v0.1.0"));
  });
  it("rejects different version", function () {
    assert.ok(!mod._uvToolListHasVersion("haltwire v0.2.0\n", "v0.1.0"));
  });
  it("rejects when haltwire not listed", function () {
    assert.ok(!mod._uvToolListHasVersion("other-tool v0.1.0\n", "v0.1.0"));
  });
});

// ---------------------------------------------------------------------------
// Integration tests (spawned process) -- POSIX only
// ---------------------------------------------------------------------------

var POSIX_ONLY = IS_WIN && "needs shell-script fakes (POSIX only)";

describe("haltwire CLI - uv path (integration)", function () {
  it("installs on first run, skips on second", { skip: POSIX_ONLY }, function () {
    var tmp = mkTmp("uv-install");
    try {
      // First run: tool list shows nothing -> install is called.
      var fake = buildFakeUv(tmp, { toolListOutput: "" });
      var r = run(["status"], { PATH: path.dirname(fake.uvPath) });
      assert.equal(r.status, 0, "stderr: " + r.stderr);
      assert.ok(fs.existsSync(fake.installMarker), "install should have been called");

      // Check argv of installed haltwire.
      var recorded = JSON.parse(fs.readFileSync(fake.argvFile, "utf8"));
      assert.ok(recorded.argv.includes("status"));

      // Clean up and re-run with the version already listed.
      fs.unlinkSync(fake.installMarker);
      fs.unlinkSync(fake.argvFile);
      var fake2 = buildFakeUv(tmp, {
        toolListOutput: "haltwire v0.1.0\n- haltwire\n- sandbox",
        binDir: fake.binDir,
        argvFile: fake.argvFile,
      });
      var r2 = run(["status"], { PATH: path.dirname(fake2.uvPath) });
      assert.equal(r2.status, 0, "stderr: " + r2.stderr);
      assert.ok(!fs.existsSync(fake.installMarker), "install should have been skipped");
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });

  it("passes args through to the installed haltwire", { skip: POSIX_ONLY }, function () {
    var tmp = mkTmp("uv-args");
    try {
      var fake = buildFakeUv(tmp, { toolListOutput: "haltwire v0.1.0" });
      var r = run(["verify", "--verbose"], { PATH: path.dirname(fake.uvPath) });
      assert.equal(r.status, 0, "stderr: " + r.stderr);
      var recorded = JSON.parse(fs.readFileSync(fake.argvFile, "utf8"));
      assert.ok(recorded.argv.includes("verify"));
      assert.ok(recorded.argv.includes("--verbose"));
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });

  it("maps init with no path to init .", { skip: POSIX_ONLY }, function () {
    var tmp = mkTmp("uv-init");
    try {
      var fake = buildFakeUv(tmp, { toolListOutput: "haltwire v0.1.0" });
      var r = run(["init"], { PATH: path.dirname(fake.uvPath) });
      assert.equal(r.status, 0, "stderr: " + r.stderr);
      var recorded = JSON.parse(fs.readFileSync(fake.argvFile, "utf8"));
      var idx = recorded.argv.indexOf("init");
      assert.ok(idx >= 0);
      assert.equal(recorded.argv[idx + 1], ".");
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });

  it("propagates a non-zero exit code", { skip: POSIX_ONLY }, function () {
    var tmp = mkTmp("uv-exit");
    try {
      var fake = buildFakeUv(tmp, { toolListOutput: "haltwire v0.1.0" });
      buildFakeHwExit(fake.binDir, 42);
      var r = run(["verify"], { PATH: path.dirname(fake.uvPath) });
      assert.equal(r.status, 42);
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });

  it("uses HALTWIRE_REF to override the ref", { skip: POSIX_ONLY }, function () {
    var tmp = mkTmp("uv-ref");
    try {
      var fake = buildFakeUv(tmp, { toolListOutput: "" });
      var r = run(["verify"], { PATH: path.dirname(fake.uvPath), HALTWIRE_REF: "my-branch" });
      assert.equal(r.status, 0, "stderr: " + r.stderr);
      // Check that install was called with the right spec.
      var installArgs = fs.readFileSync(fake.installMarker + ".args", "utf8");
      assert.ok(installArgs.includes("@my-branch"), "expected @my-branch in install args: " + installArgs);
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });

  it("rejects invalid HALTWIRE_REF", { skip: POSIX_ONLY }, function () {
    var tmp = mkTmp("uv-badref");
    try {
      buildFakeUv(tmp);
      var r = run(["verify"], { PATH: tmp, HALTWIRE_REF: "foo;rm -rf /" });
      assert.equal(r.status, 1);
      assert.ok((r.stdout + r.stderr).includes("Invalid"));
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });
});

describe("haltwire CLI - pipx path (integration)", function () {
  it("installs and runs via pipx when uv is missing", { skip: POSIX_ONLY }, function () {
    var tmp = mkTmp("pipx-path");
    try {
      var fake = buildFakePipx(tmp);
      var r = run(["verify"], { PATH: path.dirname(fake.pipxPath) });
      assert.equal(r.status, 0, "stderr: " + r.stderr);
      assert.ok(fs.existsSync(fake.installMarker), "pipx install should have been called");
      var recorded = JSON.parse(fs.readFileSync(fake.argvFile, "utf8"));
      assert.ok(recorded.argv.includes("verify"));
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });
});

describe("haltwire CLI - error paths", function () {
  it("prints install instructions when uv and pipx are missing", function () {
    var r = run(["init"], { PATH: NODE_DIR });
    assert.equal(r.status, 1);
    var output = r.stdout + r.stderr;
    if (IS_WIN) {
      assert.ok(output.includes("irm https://astral.sh/uv/install.ps1"));
    } else {
      assert.ok(output.includes("curl -LsSf https://astral.sh/uv/install.sh"));
    }
  });

  it("refuses .cmd runner with helpful message", { skip: !IS_WIN && "Windows only" }, function () {
    var tmp = mkTmp("cmd-refuse");
    try {
      fs.writeFileSync(path.join(tmp, "uv.cmd"), "@echo off\r\n");
      var r = run(["verify"], { PATH: tmp });
      assert.equal(r.status, 1);
      var output = r.stdout + r.stderr;
      assert.ok(output.includes("uv.exe"));
      assert.ok(output.includes(".cmd"));
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });

  it("--install-uv refuses in non-TTY without --yes", function () {
    var r = run(["--install-uv"], { PATH: NODE_DIR });
    assert.equal(r.status, 1);
    assert.ok((r.stdout + r.stderr).includes("--yes") || (r.stdout + r.stderr).includes("interactive"));
  });

  it("--install-uv with --yes prints what will run", function () {
    var interceptDir = mkTmp("install-intercept");
    try {
      if (IS_WIN) {
        fs.writeFileSync(path.join(interceptDir, "powershell.cmd"), '@echo off\r\nexit /b 0\r\n');
      } else {
        fs.writeFileSync(path.join(interceptDir, "curl"), "#!/bin/sh\necho fake\n", { mode: 0o755 });
        fs.writeFileSync(path.join(interceptDir, "sh"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
      }
      var r = run(["--install-uv", "--yes"], { PATH: interceptDir });
      assert.ok((r.stdout + r.stderr).includes("astral.sh/uv/install"));
    } finally { fs.rmSync(interceptDir, { recursive: true, force: true }); }
  });
});
