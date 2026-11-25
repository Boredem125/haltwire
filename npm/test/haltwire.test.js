// Tests for bin/haltwire.js -- node:test, no network, cross-platform.
// Fake uvx/pipx executables record argv to a file so we can assert.
//
// On POSIX, the fakes are shell scripts that forward args to node via --.
// On Windows, we cannot cheaply create a real .exe that records arguments
// (node.exe rejects unknown flags like --from before any JS runs), so the
// integration tests that need arg recording are POSIX-only.  Windows CI
// exercises the resolver unit tests, the .cmd refusal path, and the
// error / help paths.
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
// Directory containing the node binary -- needed in PATH
const NODE_DIR = path.dirname(NODE);

// Temp root: TMP/TEMP if set, else the OS temp dir
const TMPBASE = process.env.TMP || process.env.TEMP || os.tmpdir();

/** Create a unique temp dir for a single test. */
function mkTmp(label) {
  return fs.mkdtempSync(path.join(TMPBASE, "haltwire-test-" + label + "-"));
}

/**
 * Build a fake executable in dir that writes JSON {argv} to outFile.
 * POSIX only -- on Windows there is no easy way to build a recording .exe
 * (node.exe rejects unknown flags before any JS runs).
 */
function writeFakeExe(dir, name, outFile, exitCode) {
  if (exitCode === undefined) exitCode = 0;
  if (IS_WIN) {
    throw new Error("writeFakeExe is not supported on Windows");
  }
  var sh = path.join(dir, name);
  var escaped = outFile.replace(/'/g, "'\\''");
  var body = '#!/bin/sh\n"' + NODE + '" -e "' +
    "fs=require('fs');" +
    "fs.writeFileSync('" + escaped + "',JSON.stringify({argv:process.argv.slice(1)}));" +
    "process.exit(" + exitCode + ")" +
    '" -- "$@"\n';
  fs.writeFileSync(sh, body, { mode: 0o755 });
  return sh;
}

/**
 * Build a fake executable that exits with the given code, writes no output file.
 * POSIX only.
 */
function writeFakeExeCode(dir, name, exitCode) {
  if (IS_WIN) {
    throw new Error("writeFakeExeCode is not supported on Windows");
  }
  var sh = path.join(dir, name);
  fs.writeFileSync(sh, "#!/bin/sh\nexit " + exitCode + "\n", { mode: 0o755 });
  return sh;
}

/**
 * Run bin/haltwire.js as a child process with custom env/args.
 * Returns { stdout, stderr, status }.
 */
function run(args, env, opts) {
  var bin = path.resolve(__dirname, "..", "..", "bin", "haltwire.js");
  var merged = Object.assign({}, process.env, {
    TMP: TMPBASE,
    TEMP: TMPBASE,
  }, env);

  // Always include the node binary dir
  if (merged.PATH && merged.PATH.indexOf(NODE_DIR) === -1) {
    merged.PATH = merged.PATH + path.delimiter + NODE_DIR;
  }

  try {
    var stdout = execFileSync(NODE, [bin].concat(args), Object.assign({
      env: merged,
      timeout: 15000,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    }, opts || {}));
    return { stdout: stdout, stderr: "", status: 0 };
  } catch (err) {
    return {
      stdout: err.stdout || "",
      stderr: err.stderr || "",
      status: err.status != null ? err.status : 1,
    };
  }
}

// ---------------------------------------------------------------------------
// Unit tests for the resolver (exported from bin/haltwire.js)
// ---------------------------------------------------------------------------

// We require the module directly to test _resolveRunner.
// bin/haltwire.js guards its main with require.main === module.
var mod = require("../../bin/haltwire.js");

describe("_resolveRunner (unit)", function () {
  it("finds uvx when uvx is on PATH", function () {
    var tmp = mkTmp("resolver-uvx");
    try {
      if (IS_WIN) {
        // The resolver only accepts .exe on Windows (not .cmd/.bat)
        fs.writeFileSync(path.join(tmp, "uvx.exe"), "");
      } else {
        fs.writeFileSync(path.join(tmp, "uvx"), "#!/bin/sh\n", { mode: 0o755 });
      }
      var result = mod._resolveRunner(tmp);
      assert.equal(result.runner, "uvx");
      assert.ok(result.path.includes(tmp));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("finds uvx.exe on Windows", { skip: !IS_WIN && "POSIX does not use PATHEXT" }, function () {
    var tmp = mkTmp("resolver-exe");
    try {
      // Only create uvx.exe, no .cmd
      fs.writeFileSync(path.join(tmp, "uvx.exe"), "");
      var result = mod._resolveRunner(tmp);
      assert.equal(result.runner, "uvx");
      assert.ok(result.path.toLowerCase().endsWith("uvx.exe"),
        "expected path ending in uvx.exe, got: " + result.path);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("ignores .cmd on Windows (metacharacter safety)", { skip: !IS_WIN && "Windows only" }, function () {
    var tmp = mkTmp("resolver-cmd-refused");
    try {
      // Only a .cmd exists -- the resolver must not return it
      fs.writeFileSync(path.join(tmp, "uvx.cmd"), "@echo off\r\n");
      var result = mod._resolveRunner(tmp);
      assert.equal(result, null, ".cmd must not be accepted");
      assert.ok(mod._resolveRunner._cmdFallback, "should record the .cmd as a fallback hint");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("falls back to pipx when uvx is missing", function () {
    var tmp = mkTmp("resolver-pipx");
    try {
      if (IS_WIN) {
        fs.writeFileSync(path.join(tmp, "pipx.exe"), "");
      } else {
        fs.writeFileSync(path.join(tmp, "pipx"), "#!/bin/sh\n", { mode: 0o755 });
      }
      var result = mod._resolveRunner(tmp);
      assert.equal(result.runner, "pipx");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("returns null when neither uvx nor pipx exists", function () {
    var tmp = mkTmp("resolver-none");
    try {
      var result = mod._resolveRunner(tmp);
      assert.equal(result, null);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// Integration tests (spawned process)
// ---------------------------------------------------------------------------

// Tests that need a fake runner exe: POSIX only (we cannot create a real
// .exe that records arbitrary argv on Windows without a compiler).
var NEEDS_FAKE_RUNNER = IS_WIN && "needs a fake runner .exe (POSIX only)";

describe("haltwire CLI (integration)", function () {
  var fakeDir;
  var argvFile;

  beforeEach(function () {
    fakeDir = mkTmp("cli");
    argvFile = path.join(fakeDir, "argv.json");
    if (fs.existsSync(argvFile)) fs.unlinkSync(argvFile);
  });

  // --- args pass-through ---

  it("passes arbitrary args through to uvx", { skip: NEEDS_FAKE_RUNNER }, function () {
    writeFakeExe(fakeDir, "uvx", argvFile);
    var r = run(["verify", "--verbose"], { PATH: fakeDir });
    assert.equal(r.status, 0, "stderr: " + r.stderr);
    var recorded = JSON.parse(fs.readFileSync(argvFile, "utf8"));
    // uvx --from git+...@v0.1.0 haltwire verify --verbose
    assert.ok(recorded.argv.includes("haltwire"));
    assert.ok(recorded.argv.includes("verify"));
    assert.ok(recorded.argv.includes("--verbose"));
    assert.ok(recorded.argv.some(function (a) { return a.startsWith("--from"); }));
    fs.rmSync(fakeDir, { recursive: true, force: true });
  });

  // --- init -> init . ---

  it("maps 'init' with no path to 'haltwire init .'", { skip: NEEDS_FAKE_RUNNER }, function () {
    writeFakeExe(fakeDir, "uvx", argvFile);
    var r = run(["init"], { PATH: fakeDir });
    assert.equal(r.status, 0, "stderr: " + r.stderr);
    var recorded = JSON.parse(fs.readFileSync(argvFile, "utf8"));
    var idx = recorded.argv.indexOf("init");
    assert.ok(idx >= 0, "should contain init");
    assert.equal(recorded.argv[idx + 1], ".", "init should be followed by .");
    fs.rmSync(fakeDir, { recursive: true, force: true });
  });

  it("does NOT append . when init already has a path", { skip: NEEDS_FAKE_RUNNER }, function () {
    writeFakeExe(fakeDir, "uvx", argvFile);
    var r = run(["init", "/some/path"], { PATH: fakeDir });
    assert.equal(r.status, 0, "stderr: " + r.stderr);
    var recorded = JSON.parse(fs.readFileSync(argvFile, "utf8"));
    var idx = recorded.argv.indexOf("init");
    assert.ok(idx >= 0);
    assert.equal(recorded.argv[idx + 1], "/some/path");
    // "." should not appear after init
    var dotIdx = recorded.argv.indexOf(".");
    assert.ok(dotIdx === -1 || dotIdx < idx,
      "should not append extra .");
    fs.rmSync(fakeDir, { recursive: true, force: true });
  });

  // --- no args -> --help ---

  it("runs haltwire --help when invoked with no args", { skip: NEEDS_FAKE_RUNNER }, function () {
    writeFakeExe(fakeDir, "uvx", argvFile);
    var r = run([], { PATH: fakeDir });
    assert.equal(r.status, 0, "stderr: " + r.stderr);
    var recorded = JSON.parse(fs.readFileSync(argvFile, "utf8"));
    assert.ok(recorded.argv.includes("haltwire"));
    assert.ok(recorded.argv.includes("--help"));
    fs.rmSync(fakeDir, { recursive: true, force: true });
  });

  // --- exit code propagation ---

  it("propagates a non-zero exit code from uvx", { skip: NEEDS_FAKE_RUNNER }, function () {
    writeFakeExeCode(fakeDir, "uvx", 42);
    var r = run(["verify"], { PATH: fakeDir });
    assert.equal(r.status, 42);
    fs.rmSync(fakeDir, { recursive: true, force: true });
  });

  // --- missing uv -> message + exit 1 ---

  it("prints install instructions and exits 1 when uvx and pipx are missing", function () {
    // PATH with only the node dir (no uvx, no pipx)
    var r = run(["init"], { PATH: NODE_DIR });
    assert.equal(r.status, 1);
    var output = r.stdout + r.stderr;
    if (IS_WIN) {
      assert.ok(output.includes("irm https://astral.sh/uv/install.ps1"),
        "should print Windows install command");
    } else {
      assert.ok(output.includes("curl -LsSf https://astral.sh/uv/install.sh"),
        "should print Unix install command");
    }
  });

  // --- .cmd refusal on Windows ---

  it("refuses .cmd runner with helpful message", { skip: !IS_WIN && "Windows only" }, function () {
    // Only a .cmd exists -- should refuse and mention .exe requirement
    fs.writeFileSync(path.join(fakeDir, "uvx.cmd"), "@echo off\r\n");
    var r = run(["verify"], { PATH: fakeDir });
    assert.equal(r.status, 1);
    var output = r.stdout + r.stderr;
    assert.ok(output.includes("uvx.exe"), "should mention needing uvx.exe");
    assert.ok(output.includes(".cmd"), "should mention the .cmd it found");
    fs.rmSync(fakeDir, { recursive: true, force: true });
  });

  // --- pipx fallback ---

  it("uses pipx when uvx is not found", { skip: NEEDS_FAKE_RUNNER }, function () {
    writeFakeExe(fakeDir, "pipx", argvFile);
    var r = run(["verify"], { PATH: fakeDir });
    assert.equal(r.status, 0, "stderr: " + r.stderr);
    var recorded = JSON.parse(fs.readFileSync(argvFile, "utf8"));
    // pipx run --spec git+...@v0.1.0 haltwire verify
    assert.ok(recorded.argv.includes("run"));
    assert.ok(recorded.argv.some(function (a) { return a.startsWith("--spec"); }));
    assert.ok(recorded.argv.includes("haltwire"));
    assert.ok(recorded.argv.includes("verify"));
    fs.rmSync(fakeDir, { recursive: true, force: true });
  });

  // --- HALTWIRE_REF override ---

  it("uses HALTWIRE_REF to override the git ref", { skip: NEEDS_FAKE_RUNNER }, function () {
    writeFakeExe(fakeDir, "uvx", argvFile);
    var r = run(["verify"], { PATH: fakeDir, HALTWIRE_REF: "my-branch" });
    assert.equal(r.status, 0, "stderr: " + r.stderr);
    var recorded = JSON.parse(fs.readFileSync(argvFile, "utf8"));
    var allArgs = recorded.argv.join(" ");
    assert.ok(allArgs.includes("@my-branch"),
      "expected @my-branch in: " + allArgs);
    fs.rmSync(fakeDir, { recursive: true, force: true });
  });

  it("rejects HALTWIRE_REF with invalid characters", { skip: NEEDS_FAKE_RUNNER }, function () {
    writeFakeExe(fakeDir, "uvx", argvFile);
    var r = run(["verify"], { PATH: fakeDir, HALTWIRE_REF: "foo;rm -rf /" });
    assert.equal(r.status, 1);
    var output = r.stdout + r.stderr;
    assert.ok(output.includes("Invalid"), "should reject bad ref");
    // The argvFile should NOT exist -- uvx was never called
    assert.ok(!fs.existsSync(argvFile), "uvx should not have been invoked");
    fs.rmSync(fakeDir, { recursive: true, force: true });
  });

  it("accepts HALTWIRE_REF with dots, slashes, dashes, underscores", { skip: NEEDS_FAKE_RUNNER }, function () {
    writeFakeExe(fakeDir, "uvx", argvFile);
    var r = run(["verify"], { PATH: fakeDir, HALTWIRE_REF: "v1.2.3-rc_1/beta" });
    assert.equal(r.status, 0, "stderr: " + r.stderr);
    var recorded = JSON.parse(fs.readFileSync(argvFile, "utf8"));
    var allArgs = recorded.argv.join(" ");
    assert.ok(allArgs.includes("@v1.2.3-rc_1/beta"));
    fs.rmSync(fakeDir, { recursive: true, force: true });
  });

  // --- --install-uv refuses without TTY / --yes ---

  it("--install-uv refuses in non-TTY without --yes", function () {
    var r = run(["--install-uv"], { PATH: NODE_DIR });
    assert.equal(r.status, 1);
    var output = r.stdout + r.stderr;
    assert.ok(
      output.includes("--yes") || output.includes("interactive"),
      "should mention --yes or interactive"
    );
  });

  it("--install-uv with --yes prints what will run", function () {
    // We provide a fake powershell/sh to intercept the actual installer
    var interceptDir = mkTmp("install-intercept");

    if (IS_WIN) {
      // Create fake powershell.cmd that just exits 0
      fs.writeFileSync(
        path.join(interceptDir, "powershell.cmd"),
        '@echo off\r\nexit /b 0\r\n'
      );
    } else {
      // Create fake curl and sh that just exit 0
      fs.writeFileSync(
        path.join(interceptDir, "curl"),
        "#!/bin/sh\necho fake\n",
        { mode: 0o755 }
      );
      fs.writeFileSync(
        path.join(interceptDir, "sh"),
        "#!/bin/sh\nexit 0\n",
        { mode: 0o755 }
      );
    }

    var r = run(["--install-uv", "--yes"], { PATH: interceptDir });
    var output = r.stdout + r.stderr;
    assert.ok(
      output.includes("astral.sh/uv/install"),
      "should show the install command. Got: " + output
    );
    fs.rmSync(interceptDir, { recursive: true, force: true });
  });

  // --- --from spec format ---

  it("uvx receives --from with correct git+https spec", { skip: NEEDS_FAKE_RUNNER }, function () {
    writeFakeExe(fakeDir, "uvx", argvFile);
    var r = run(["status"], { PATH: fakeDir });
    assert.equal(r.status, 0, "stderr: " + r.stderr);
    var recorded = JSON.parse(fs.readFileSync(argvFile, "utf8"));
    var fromIdx = recorded.argv.indexOf("--from");
    assert.ok(fromIdx >= 0, "should have --from flag");
    var spec = recorded.argv[fromIdx + 1];
    assert.ok(spec.startsWith("git+https://github.com/Boredem125/haltwire@"),
      "spec should start with git+https://...@, got: " + spec);
    assert.ok(spec.endsWith("@v0.1.0"),
      "default ref should be v0.1.0, got: " + spec);
    fs.rmSync(fakeDir, { recursive: true, force: true });
  });

  it("pipx receives --spec with correct git+https spec", { skip: NEEDS_FAKE_RUNNER }, function () {
    writeFakeExe(fakeDir, "pipx", argvFile);
    var r = run(["status"], { PATH: fakeDir });
    assert.equal(r.status, 0, "stderr: " + r.stderr);
    var recorded = JSON.parse(fs.readFileSync(argvFile, "utf8"));
    var specIdx = recorded.argv.indexOf("--spec");
    assert.ok(specIdx >= 0, "should have --spec flag");
    var spec = recorded.argv[specIdx + 1];
    assert.ok(spec.startsWith("git+https://github.com/Boredem125/haltwire@"),
      "spec should start with git+https://...@, got: " + spec);
    fs.rmSync(fakeDir, { recursive: true, force: true });
  });
});
