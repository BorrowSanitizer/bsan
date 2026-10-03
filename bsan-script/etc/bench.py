# This script calculates BorrowSanitizer's relative execution time
# across all test cases for a crate. It produces two output files:
#
# * A JSON file with relative execution times in a format that is
#   compatible with `github-actions-benchmark`
#
# * A CSV file listing the mean execution times of each mode, including
#   both the baselines and tested configurations.
import argparse
import traceback
import re
import statistics
import json
import csv
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

RUNS = 3
WARMUP = 1

# How long one run of one test may take, in seconds, before it counts as hung
# (`timed_out`) rather than holding its CI job until GitHub kills it. Miri is
# far slower than native execution, so it gets several times as long.
TEST_TIMEOUT = 300
MIRI_TIMEOUT_FACTOR = 4

# Uninstrumented native execution.
NATIVE = {
    "name": "native",
    "cmd": ["cargo", "test", "--lib"],
    "env": {"RUSTFLAGS": "--cfg=bsan --cfg=miri"},
}

# Flags shared by every Miri configuration. These disable most forms of
# checking, and ensure deterministic execution.
MIRI_COMMON_FLAGS = (
    "-Zmiri-mute-stdout-stderr "
    "-Zmiri-disable-data-race-detector -Zmiri-deterministic-concurrency "
    "-Zmiri-disable-alignment-check -Zmiri-ignore-leaks"
)

# Miri with Tree Borrows enabled,and all other checking disabled
# (to the extent possible).
MIRI = {
    "name": "miri-tb",
    "env": {
        "MIRIFLAGS": f"-Zmiri-tree-borrows {MIRI_COMMON_FLAGS}",
    },
}

# Every Miri configuration.
MIRI_CONFIGS = [MIRI]

# `cargo bsan` sets `BSAN_SYMBOLIZER` for the processes it runs, but test
# binaries are copied out and run directly, so without this an error's stack
# trace has no source locations.
SYMBOLIZER = "/root/.rustup/toolchains/bsan/bin/llvm-symbolizer"

# BorrowSanitizer configurations.
BSAN_CONFIGS = [
    # Full checking.
    {
        "name": "full",
        "cmd": ["cargo", "bsan", "test", "--lib"],
        "env": {"RUSTFLAGS": "--cfg=miri"},
    },
    # Full, but with wildcard provenance disabled.
    {
        "name": "full-no-wildcard",
        "cmd": ["cargo", "bsan", "test", "--lib"],
        "env": {
            "RUSTFLAGS": "--cfg=miri", 
            "BSAN_OPTIONS": "wildcard=0"
        },
    },
    # No-op checking. Instrumentation is inserted, but
    # all memory access checks, retags, and reference count
    # updates are disabled.
    {
        "name": "no-op",
        "cmd": ["cargo", "bsan", "test", "--nop", "--lib"],
        "env": {"RUSTFLAGS": "--cfg=miri"},
    }
]

# Every configuration that requires compiling a native binary.
ALL_BINARY_CONFIGS = [NATIVE] + BSAN_CONFIGS

# Raw timing results are output as a CSV with these headers.
CSV_HEADERS = [
    'target',
    'crate_name',
    'version',
    'test_name',
    'mode',
    'status',
    'mean_exec_time_seconds',
    # Filled in only for `test_failed`; see `describe_failure`.
    'error_message',
    'error_location',
    'log_url',
    'error_detail',
]

# How much of a failing test's output, from the error onward, is kept.
ERROR_DETAIL_LINES = 40
ERROR_DETAIL_CHARS = 4000

class TestHarnessJSON:
    def __init__(self, txt):
        self.lines = txt.splitlines()
        self.idx = 0

    def __iter__(self):
        return self

    def __next__(self):
        while self.idx < len(self.lines):
            prev = self.idx
            self.idx += 1
            try:
                return json.loads(self.lines[prev])
            except json.JSONDecodeError:
                continue
        raise StopIteration

def _build_env(kwargs: dict) -> dict:
    """Creates a copy of the current environment, merged with an `env` mapping from `kwargs`.

    If a a value is set to `None` in `kwargs`, then the value will be unset from the environment,
    instead of being inherited by the parent process.
    """
    env = os.environ.copy()
    for key, value in (kwargs.pop("env", None) or {}).items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return env

def run_rc(
    cmd: list[str],
    **kwargs,
) -> int:
    """Run a command and return its exit code instead of aborting.

    Used where a non-zero exit is a measurement result rather than an error: a
    test that fails under one configuration is data we want to report, not a
    reason to throw away every other measurement in the job.
    """
    sys.stderr.flush()
    return subprocess.run(cmd, check=False, env=_build_env(kwargs), **kwargs).returncode

def run_capture(
    cmd: list[str],
    **kwargs,
) -> str:
    """Run a command and return stdout as a string.

    The command inherits the current environment.
    """
    proc = subprocess.run(
        cmd, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=_build_env(kwargs),
        **kwargs,
    )
    return proc.stdout

def run_limited(cmd: list[str], timeout: float, capture: bool = False,
                **kwargs) -> tuple[int | None, str]:
    """Run a command for at most `timeout` seconds and return
    `(returncode, output)`, with None for the return code if it timed out.

    The command gets its own process group, and on timeout the whole group is
    killed: a test binary under hyperfine, or `miri` under cargo, must not
    outlive its parent and keep a CPU busy during later measurements.
    """
    sys.stderr.flush()
    env = _build_env(dict(kwargs))
    rest = {k: v for k, v in kwargs.items() if k != "env"}
    if capture:
        rest.update(stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    proc = subprocess.Popen(cmd, env=env, start_new_session=True,
                            text=True, errors="replace", **rest)
    try:
        out, _ = proc.communicate(timeout=timeout)
        return proc.returncode, out or ""
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        out, _ = proc.communicate()
        return None, out or ""

def probe(cmd: list[str], timeout: float, **kwargs) -> tuple[str, str | None]:
    """Run a test once, untimed, and return `(status, output)`.

    This is the warmup run hyperfine would otherwise do, under a time limit:
    a test that hangs is stopped here, and one that fails is caught with its
    output, which hyperfine would discard. Output is only returned for a
    failure: `success`, `test_failed` or `timed_out`.
    """
    rc, output = run_limited(cmd, timeout, capture=True, **kwargs)
    if rc is None:
        return "timed_out", f"timed out after {timeout:g}s\n{output}"
    if rc != 0:
        return "test_failed", output
    return "success", None

# `--> src/lib.rs:12:5`, as BorrowSanitizer and Miri print below an error.
ARROW_LOCATION = re.compile(r"^\s*--> (?P<path>[^\s:][^:]*):(?P<line>\d+):(?P<col>\d+)")
# `thread 'x' panicked at src/lib.rs:12:5:`, with the message on the next line.
PANIC_LOCATION = re.compile(r"panicked at (?P<path>[^\s:][^:]*):(?P<line>\d+):(?P<col>\d+):?")
# `error[E0308]: mismatched types`, as rustc prints it.
COMPILER_ERROR = re.compile(r"^error(\[\w+\])?: ")
# A dependency's source, as cargo unpacks it from a registry.
REGISTRY_PATH = re.compile(
    r"/registry/src/[^/]+/(?P<name>[A-Za-z0-9_-]+?)-(?P<version>\d[^/]*)/(?P<rest>.+)$")
# The standard library's source, as rustc records it.
RUSTC_PATH = re.compile(r"^/rustc/(?P<hash>[0-9a-f]{40})/(?P<rest>.+)$")

def describe_failure(output: str | None, src_dir: Path, log_url: str,
                     status: str = "") -> dict:
    """Pull the first error out of a failing test's output.

    Returns the CSV's error fields: a one-line message, the `path:line:col` it
    points at (relative to the crate, when it is in the crate), a link to the
    CI log the full output was printed to (see `print_failure`), and the output
    from the error onward. Any of them may be empty: a test can fail without
    printing a location, or without printing at all.

    `output` is None for anything but a failed test, which has no error.
    """
    empty = {"error_message": "", "error_location": "", "log_url": "", "error_detail": ""}
    if output is None:
        return empty
    empty["log_url"] = log_url
    if not output:
        return empty
    if status == "timed_out":
        # Whatever a hung test printed before it was stopped is not its error;
        # the first line says how long it was given.
        first, _, rest = output.partition("\n")
        tail = "\n".join(rest.splitlines()[-ERROR_DETAIL_LINES:])
        return {**empty, "error_message": first, "error_detail": tail[:ERROR_DETAIL_CHARS]}
    lines = output.splitlines()

    start = message = loc = None
    # A sanitizer report is the more specific finding: the test harness only
    # adds a generic panic or abort after it.
    for i, text in enumerate(lines):
        if "Undefined Behavior" in text:
            start, message = i, text.strip()
            for later in lines[i + 1:]:
                if m := ARROW_LOCATION.match(later):
                    loc = m
                    break
            break
    if start is None:
        # A compiler error, when a crate did not build.
        for i, text in enumerate(lines):
            if COMPILER_ERROR.match(text):
                start, message = i, text.strip()
                for later in lines[i + 1:]:
                    if m := ARROW_LOCATION.match(later):
                        loc = m
                        break
                break
    if start is None:
        for i, text in enumerate(lines):
            if m := PANIC_LOCATION.search(text):
                start, loc = i, m
                following = lines[i + 1].strip() if i + 1 < len(lines) else ""
                message = following or text.strip()
                break
    if start is None:
        # Nothing recognisable, e.g. a crash with no report: keep the end of
        # the output, which is where the reason usually is.
        nonblank = [i for i, text in enumerate(lines) if text.strip()]
        if not nonblank:
            return empty
        start = max(0, nonblank[-1] - ERROR_DETAIL_LINES + 1)
        message = lines[nonblank[-1]].strip()

    detail = "\n".join(lines[start:start + ERROR_DETAIL_LINES])[:ERROR_DETAIL_CHARS]
    result = {**empty, "error_message": message[:300], "error_detail": detail}
    if loc:
        path = loc["path"]
        root = str(src_dir) + "/"
        # Show a path the way someone would look it up, not where it happened
        # to be unpacked on the runner.
        if path.startswith(root):
            shown = path[len(root):]
        elif m := REGISTRY_PATH.search(path):
            shown = f"{m['name']}-{m['version']}/{m['rest']}"
        elif m := RUSTC_PATH.match(path):
            shown = m["rest"]
        else:
            shown = path
        result["error_location"] = f"{shown}:{loc['line']}:{loc['col']}"
    return result

def print_failure(mode: str, test: str, output: str | None) -> None:
    """Print a failed test's output to the log, which `log_url` links to.

    In GitHub Actions each failure is a collapsed group, titled so that it can
    be found by searching the log for the test's name.
    """
    if output is None:
        return
    actions = os.environ.get("GITHUB_ACTIONS") == "true"
    print(f"::group::FAILED {mode}: {test}" if actions else f"FAILED {mode}: {test}")
    print(output.rstrip() or "(no output)")
    if actions:
        print("::endgroup::")
    sys.stdout.flush()

def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        sys.exit(f"Error: '{name}' is required but not installed.")

def download_crate(crate: str, version: str, dest_dir: Path) -> Path:
    """Downloads <crate>@<version> from crates.io into dest_dir, extracts it,
    and returns the path to the extracted contents."""
    url = f"https://crates.io/api/v1/crates/{crate}/{version}/download"
    tarball = dest_dir / f"{crate}-{version}.crate"

    # crates.io asks clients to identify themselves, and a stalled download
    # must fail rather than hold the job.
    req = urllib.request.Request(url, headers={
        "User-Agent": "BorrowSanitizer benchmarks (https://github.com/BorrowSanitizer/bsan)"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(tarball, "wb") as out:
        shutil.copyfileobj(resp, out)

    with tarfile.open(tarball, "r:gz") as tf:
        try:
            tf.extractall(dest_dir, filter="data")
        except TypeError:
            tf.extractall(dest_dir)
    tarball.unlink()

    extracted = dest_dir / f"{crate}-{version}"
    if not extracted.is_dir():
        sys.exit(f"Error: expected extracted directory {extracted} not found.")
    return extracted

class CrateFailure(Exception):
    """A crate, or one configuration of it, could not be benchmarked at all.

    Recorded in the CSV as a row with no test name, rather than aborting the
    run: one crate that fails to build should not cost every other crate in the
    job its results.
    """
    def __init__(self, status: str, message: str, output: str = ""):
        super().__init__(message)
        self.status = status
        self.output = output or message

def compiler_output(stdout: str, stderr: str) -> str:
    """The human-readable output of a failed `--message-format=json` build.

    Diagnostics are rendered into the JSON on stdout; stderr only has cargo's
    own summary.
    """
    rendered = []
    for msg in TestHarnessJSON(stdout or ""):
        if msg.get("reason") == "compiler-message":
            text = (msg.get("message") or {}).get("rendered")
            if text:
                rendered.append(text.rstrip())
    return "\n".join(rendered + [(stderr or "").rstrip()]).strip()

def compile_test_binary(config: dict, cwd: Path, out_dir: Path):
    """Compiles the test binary for the given cargo invocation and copies it into
    `out_dir`. Raises `CrateFailure` on compile failure or if no executable is
    created.
    """
    print(f"compiling tests ({config["name"]}): {' '.join(config["cmd"])}",
          file=sys.stderr)
    # We need to parse the output JSON to find the name of the test binary.
    try:
        msg_json = run_capture(
            config["cmd"] + ["--no-run", "--message-format=json"],
            cwd=cwd,
            env=config.get("env"),
        )
    except subprocess.CalledProcessError as exc:
        raise CrateFailure("build_failed", f"{config['name']} tests failed to compile",
                           compiler_output(exc.stdout, exc.stderr)) from exc
    for msg in TestHarnessJSON(msg_json):
        exe = msg.get("executable")
        target = msg.get("target") or {}
        if exe and target.get("test"):
            print("done.")
            binary = out_dir / config["name"]
            shutil.copy2(exe, binary)
            binary.chmod(0o755)
            return

    raise CrateFailure("build_failed", f"could not locate the {config['name']} test binary")

def miri_binary() -> str:
    """Resolve the real `miri` executable for the active toolchain."""
    return run_capture(["rustup", "which", "miri"]).strip()


# The only way to execute a program in Miri is through Miri's cargo plugin
# (e.g. `cargo miri ...`). This adds additional overhead that is not present
# for natively compiled code. We want our timing measurements to be as accurate
# as possible, so instead of timing `cargo miri test`, we capture Miri's
# environment right before it invokes the actual `miri` binary as an interpreter.
# Then, we create a shell script to recreate that environment and execute `miri`
# directly, bypassing `cargo-miri`.
#
# This happens in two stages. First, we emit the shell script below. This is a one-time
# operation; we reuse it for subsequent invocations. Whenever we execute Miri, we set
# the `MIRI` environment variable to point to this script. Every time that `cargo-miri`
# invokes the `miri` binary, this script will be executed instead. It forwards all
# argument to `miri`, but it also checks to see if it is being invoked as the final call
# to the interpreter. We identify this case if the variable `CARGO_PRIMARY_PACKAGE` is set
# and the flag `--test` is provided. In that situation, we capture the environment and all
# flags, and emit it as an additional shell script. That final shell script, which is
# created per-test, is what gets benchmarked.
#
# This generally saves ~0.1 seconds of overhead, which is small but significant when
# comparing against native execution.
MIRI_WRAPPER_TEMPLATE = """#!/usr/bin/env bash
if [ -n "$CARGO_PRIMARY_PACKAGE" ] && [[ " $* " == *" --test "* ]]; then
    {
        echo '#!/usr/bin/env bash'
        printf 'cd %q || exit 1\\n' "$PWD"
        printf 'exec env -i'
        while IFS= read -r -d '' var; do printf ' %q' "$var"; done < <(env -0)
        printf ' %q' @MIRI_BIN@ "$@"
        echo
    } > "$BSAN_MIRI_REPLAY"
    chmod +x "$BSAN_MIRI_REPLAY"
fi
exec @MIRI_BIN@ "$@"
"""

def ensure_miri_wrapper(scratch: Path) -> Path:
    """Ensure that the wrapper script for capturing Miri invocations is initialized."""
    wrapper = scratch / "miri-wrapper.sh"
    if not wrapper.is_file():
        script = MIRI_WRAPPER_TEMPLATE.replace("@MIRI_BIN@", shlex.quote(miri_binary()))
        wrapper.write_text(script)
        wrapper.chmod(0o755)
    return wrapper

def compile_miri_tests(cwd: Path):
    print("compiling tests (miri)")
    run_capture(
        ["cargo", "miri", "test", "--no-run", "--message-format=json"],
        cwd=cwd,
    )

def run_miri_test(cwd: Path, t: str, config: dict, scratch: Path, timeout: float
                  ) -> tuple[float | None, str, str | None]:
    """Time a single Miri test, excluding `cargo-miri` overhead, by capturing its
    final `miri` invocation as a standalone script.

    Returns `(mean_seconds, status, output)` on the same terms as
    `hyperfine_mean`: a test Miri refuses to run is reported, not fatal.
    """
    replay = scratch / "miri-replay.sh"
    # The wrapper rewrites this for every test. Clear it first so that a failed
    # interception cannot leave the previous test's script in place, which we
    # would then happily time and attribute to this one.
    replay.unlink(missing_ok=True)

    override_env = { **(config.get("env") or {}) }
    override_env["MIRI"] = str(ensure_miri_wrapper(scratch))
    override_env["BSAN_MIRI_REPLAY"] = str(replay)

    # One cargo-miri run generates the replay script for this test's final miri
    # invocation; we then time that script on its own, free of cargo overhead.
    # That run also serves as the test's warmup and its time-limited probe.
    status, output = probe(
        ["cargo", "miri", "test", "-q", "--lib", "--", "--exact", t, "--nocapture"],
        timeout, cwd=cwd, env=override_env)
    if status != "success":
        return None, status, output
    if not replay.is_file():
        return None, "bench_failed", None
    return hyperfine_mean(str(replay), config, timeout, probed=True)

def list_tests(cwd: Path, cmd: list[str]) -> list[str]:
    out = run_capture(cmd + [
        # Format the test list as JSON
        "--list", "--format=json",
        # Enable JSON output
        "-Zunstable-options"
        ],
        cwd=cwd
    )
    tests = []
    for obj in TestHarnessJSON(out):
        type = obj.get("type")
        event = obj.get("event")
        name = obj.get("name")
        ignored = obj.get("ignore")
        # every JSON output line had "type" and "event" keys
        if type is not None and event is not None:
            if type == "test" and event == "discovered":
                # the "ignore" flag indicates if the test configured
                # to be ignored under this compilation configuration.
                if name is not None and ignored is not None:
                    if not ignored:
                        tests.append(name)
                    continue
            else:
                continue
        sys.exit(f"Invalid libtest JSON format.")
    return tests

def hyperfine_mean(cmd, config: dict, timeout: float, probed: bool = False,
                   **kwargs) -> tuple[float | None, str, str | None]:
    """Run hyperfine on a single command and return
    `(mean_seconds, status, output)`.

    A configuration that cannot run a test is a result, not an error: the same
    test usually runs fine under the others, and which configurations disagree
    is exactly what the per-branch report exists to show. So nothing here
    aborts.

      success       hyperfine timed the command and reported a positive mean
      test_failed   the command exited non-zero, so hyperfine has no timing
      timed_out     one run took longer than `timeout` seconds
      bench_failed  hyperfine ran but reported no usable mean

    Only `success` carries a mean; the rest return None, which the CSV writes
    as an empty cell. The first run is a `probe`, standing in for hyperfine's
    warmup, which catches a failing or hanging test with its output; skip it
    with `probed` when the caller has already run the test once.
    """
    warmup = WARMUP
    if not probed:
        status, output = probe(shlex.split(cmd), timeout, **kwargs)
        if status != "success":
            return None, status, output
        warmup = max(0, WARMUP - 1)
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out_json:
        out_path = Path(out_json.name)
    try:
        # A test that passed its probe can still hang on a later run.
        limit = timeout * (RUNS + warmup) + 60
        rc, _ = run_limited(
            [
                "hyperfine",
                "--runs", str(RUNS),
                "--warmup", str(warmup),
                "--shell=none",
                "--export-json", str(out_path),
                "--show-output",
                cmd,
            ],
            limit,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            **kwargs
        )
        if rc is None:
            return None, "timed_out", f"timed out after {limit:g}s while being timed"
        # Without `--ignore-failure` hyperfine exits non-zero as soon as the
        # command under test does, and writes no JSON. The probe passed, so
        # this one is flaky; there is no output to show for it.
        if rc != 0:
            return None, "test_failed", "passed once, then failed while being timed"
        try:
            data = json.loads(out_path.read_text())
            mean = float(data["results"][0]["mean"])
        except (OSError, ValueError, KeyError, IndexError):
            return None, "bench_failed", None
        return (mean, "success", None) if mean > 0 else (None, "bench_failed", None)
    finally:
        out_path.unlink(missing_ok=True)

def process_config(
    cfg: dict,
    target: str,
    scratch: Path,
    miri: bool = True,
    binary_configs: list[dict] = ALL_BINARY_CONFIGS,
    log_url: str = "",
    timeout: float = TEST_TIMEOUT,
) -> list:
    crate = cfg.get("name")
    version = cfg.get("version")
    excluded_tests = set(cfg.get("exclude") or [])

    if not crate or not version:
        sys.exit(f"Error: invalid per-crate config:\n{cfg}")

    bench_name = f"{crate}@{version} - {target}"

    print(f"Running: {bench_name}")
    if excluded_tests:
        print("Excluding:")
        for test_name in excluded_tests:
            print(f"- {test_name}")

    # a raw list of execution times per crate, version, test case, and mode
    raw_results: list[tuple] = []

    def record_failure(mode: str, failure: CrateFailure) -> None:
        """Record that `mode` produced nothing for this crate, and why."""
        print(f"    - {mode}: {failure.status} ({failure})")
        print_failure(mode, "(whole crate)", failure.output)
        error = describe_failure(failure.output, src_dir, log_url)
        raw_results.append((target, crate, version, "", mode, failure.status, None)
                           + tuple(error.values()))

    try:
        src_dir = download_crate(crate, version, scratch)
    except (OSError, urllib.error.URLError, tarfile.TarError) as exc:
        src_dir = scratch
        failure = CrateFailure("setup_failed", f"could not download {crate}@{version}: {exc}")
        for mode in [c["name"] for c in binary_configs] + ([c["name"] for c in MIRI_CONFIGS] if miri else []):
            record_failure(mode, failure)
        return {"relative": [], "raw": raw_results}

    # A configuration that does not compile is left out of the rest of the
    # run; the others are still measured.
    built = []
    for config in binary_configs:
        try:
            compile_test_binary(config, cwd=src_dir, out_dir=scratch)
            built.append(config)
        except CrateFailure as failure:
            record_failure(config["name"], failure)
        run_rc(["cargo", "clean", "--quiet"], cwd=src_dir)

    miri_configs = MIRI_CONFIGS if miri else []
    try:
        # Without Miri, list from the first compiled binary instead. Every one
        # is built with `--cfg=miri` too, so `#[cfg_attr(miri, ignore)]` still
        # takes effect.
        if miri:
            all_tests = list_tests(src_dir, ["cargo", "miri", "test", "--lib", "--"])
        elif built:
            all_tests = list_tests(src_dir, [str(scratch / built[0]["name"])])
        else:
            all_tests = []

        if built or miri:
            if not all_tests:
                raise CrateFailure("setup_failed", f"no tests discovered for {bench_name}")
            print(f"Found {len(all_tests)} tests for {bench_name}.")

        tests = [t for t in all_tests if t not in excluded_tests]
        if all_tests and not tests:
            raise CrateFailure("setup_failed",
                               f"every discovered test was excluded for {bench_name}")

        if miri:
            try:
                compile_miri_tests(src_dir)
            except subprocess.CalledProcessError as exc:
                raise CrateFailure("build_failed", "tests failed to compile under Miri",
                                   compiler_output(exc.stdout, exc.stderr)) from exc
    except (CrateFailure, subprocess.CalledProcessError, SystemExit) as exc:
        # Nothing about this crate can be measured, under any configuration
        # that is still left.
        if not isinstance(exc, CrateFailure):
            output = getattr(exc, "stderr", None) or str(exc)
            exc = CrateFailure("setup_failed", f"could not list tests for {bench_name}", output)
        for mode in [c["name"] for c in built + miri_configs]:
            record_failure(mode, exc)
        return {"relative": [], "raw": raw_results}
    binary_configs = built

    # a mapping from (config, baseline) pairs to mean execution times for each test case
    # for example, we would have `ratios[("no-op", "miri-tb")]` map to the list of
    # mean execution times for our no-op mode relative to Miri with tree borrows enabled.
    ratios: dict[tuple[str, str], list[float]] = {}

    # measurements that produced no timing, reported once at the end so a run
    # that quietly lost a configuration is visible in the log
    failed = 0
    for t in tests:
        row_start = (target, crate, version, t)
        print(f"  -> {t}")
        # a mapping from each config to its mean execution time; a config that
        # could not run this test has no entry
        per_test_means: dict[str, float] = {}

        # execute every natively-compiled binary and record its mean execution time
        for config in binary_configs:
            binary = scratch / config["name"]
            mean, status, output = hyperfine_mean(f"{binary} --exact {t} --nocapture",
                                                  config, timeout, env=config.get("env"))
            if mean is None:
                print(f"    - {config['name']}: {status}")
                failed += 1
            else:
                print(f"    - {config['name']}={round(mean, 8)}s")
                per_test_means[config["name"]] = mean
            print_failure(config["name"], t, output)
            error = describe_failure(output, src_dir, log_url, status)
            raw_results.append(row_start + (config["name"], status, mean)
                               + tuple(error.values()))

        baselines = {}
        if NATIVE["name"] in per_test_means:
            baselines[NATIVE["name"]] = per_test_means.pop(NATIVE["name"])
        # execute Miri and add each configuration as a baseline for comparison
        for miri_config in miri_configs:
            miri_mean, status, output = run_miri_test(src_dir, t, miri_config, scratch,
                                                      timeout * MIRI_TIMEOUT_FACTOR)
            if miri_mean is None:
                print(f"    - {miri_config['name']}: {status}")
                failed += 1
            else:
                print(f"    - {miri_config['name']}={round(miri_mean, 8)}s")
                baselines[miri_config["name"]] = miri_mean
            print_failure(miri_config["name"], t, output)
            error = describe_failure(output, src_dir, log_url, status)
            raw_results.append(row_start + (miri_config["name"], status, miri_mean)
                               + tuple(error.values()))

        # A ratio needs both of its halves measured on this test, so a config
        # that failed here contributes no ratio and the mean below is taken over
        # the tests that did produce one.
        for mode, mode_mean in per_test_means.items():
            for baseline, baseline_mean in baselines.items():
                ratio = mode_mean / baseline_mean
                ratios.setdefault((mode, baseline), []).append(ratio)
                print(f"    - {mode} vs {baseline} = {round(ratio, 4)}x")

    if failed:
        print(f"{failed} measurement(s) produced no timing for {bench_name}; "
              f"see the status column of the CSV.")

    relative_results = []
    for (mode, baseline), ratio_list in ratios.items():
        relative_results.append({
            "name": bench_name,
            "unit": "Mean Relative Execution Time",
            "value": statistics.mean(ratio_list),
            "extra": json.dumps({
                "mode": mode,
                "baseline": baseline,
                "target": target,
                "version": version,
                "crate": crate,
                "max": max(ratio_list),
                "min": min(ratio_list)
            }),
        })

    all_results = {
        "relative": relative_results,
        "raw": raw_results
    }
    return all_results

def main(argv: list[str]) -> int:
    # In CI stdout is a pipe, which Python block-buffers: progress would reach
    # the log kilobytes late, out of order with stderr, and a job that seems to
    # stop after some line has usually gone on well past it.
    sys.stdout.reconfigure(line_buffering=True)
    parser = argparse.ArgumentParser(
        description="Benchmark relative execution time",
        usage=(
            "%(prog)s [--crate NAME ...] <crates> <target> <output_json> <output_csv>"
        ),
    )
    parser.add_argument("crates_json", type=Path)
    parser.add_argument("target", type=str)
    parser.add_argument("output_json", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument(
        "--crate",
        action="append",
        dest="only",
        metavar="NAME",
        help="Only benchmark the named crate from <crates> (repeatable). "
             "Used to shard the benchmark suite one crate per CI job.",
    )
    parser.add_argument(
        "--no-miri",
        action="store_false",
        dest="miri",
        help="Skip the Miri configurations. Ratios are then only relative to "
             "native. Used where the comparison of interest is against another "
             "build of BorrowSanitizer rather than against Miri.",
    )
    parser.add_argument(
        "--mode",
        action="append",
        dest="modes",
        metavar="NAME",
        choices=[c["name"] for c in ALL_BINARY_CONFIGS],
        help="Only compile and time the named configuration (repeatable). "
             "Without `native`, no ratios are produced, only raw times. Used "
             "for branch comparisons, which only look at `full`.",
    )

    parser.add_argument(
        "--test-timeout",
        type=float,
        default=TEST_TIMEOUT,
        metavar="SECONDS",
        help=f"How long one run of a test may take before it is stopped and "
             f"recorded as timed_out (default: {TEST_TIMEOUT}; Miri gets "
             f"{MIRI_TIMEOUT_FACTOR}x as long).",
    )
    parser.add_argument(
        "--log-url",
        default="",
        metavar="URL",
        help="Where this run's log can be read, e.g. its CI job. Recorded "
             "against every failed test, whose output is printed to the log.",
    )

    args = parser.parse_args(argv)
    for tool in ["cargo", "hyperfine"]:
        require_tool(tool)
    os.environ.setdefault("BSAN_SYMBOLIZER", SYMBOLIZER)

    crates_json = args.crates_json
    if not crates_json.is_file():
        sys.exit(f"Error: invalid config file: {crates_json}")

    binary_configs = ALL_BINARY_CONFIGS
    if args.modes:
        binary_configs = [c for c in ALL_BINARY_CONFIGS if c["name"] in args.modes]

    configs = json.loads(crates_json.read_text())
    if args.only:
        wanted = set(args.only)
        configs = [cfg for cfg in configs if cfg.get("name") in wanted]
        missing = wanted - {cfg.get("name") for cfg in configs}
        if missing:
            sys.exit(f"Error: crate(s) not found in {crates_json}: {', '.join(sorted(missing))}")

    all_results = {}
    with tempfile.TemporaryDirectory() as scratch_str:
        scratch = Path(scratch_str)
        modes = [c["name"] for c in binary_configs] + (
            [c["name"] for c in MIRI_CONFIGS] if args.miri else [])
        for cfg in configs:
            try:
                cfg_results = process_config(cfg, args.target, scratch, miri=args.miri,
                                             binary_configs=binary_configs,
                                             log_url=args.log_url,
                                             timeout=args.test_timeout)
            except Exception as exc:
                # Anything process_config did not anticipate still costs only
                # this crate its results, not the rest of the job.
                output = traceback.format_exc()
                print(output, file=sys.stderr)
                error = describe_failure(output, scratch, args.log_url)
                error["error_message"] = f"benchmarking crashed: {exc}"[:300]
                cfg_results = {"relative": [], "raw": [
                    (args.target, cfg.get("name"), cfg.get("version"), "", mode,
                     "setup_failed", None) + tuple(error.values())
                    for mode in modes]}
            all_results.setdefault("relative", [])
            all_results["relative"] += cfg_results["relative"]
            all_results.setdefault("raw", [])
            all_results["raw"] += cfg_results["raw"]

    args.output_json.write_text(json.dumps(all_results["relative"], indent=4))
    if "raw" in all_results:
        with open(args.output_csv, 'w') as out:
            csv_out=csv.writer(out)
            csv_out.writerow(CSV_HEADERS)
            for row in all_results["raw"]:
                csv_out.writerow(row)

    failed_crates = sorted({f"{r[1]}@{r[2]} ({r[4]}: {r[5]})"
                            for r in all_results.get("raw", []) if not r[3]})
    if failed_crates:
        print("Could not benchmark:")
        for c in failed_crates:
            print(f"- {c}")
    print(f"Results written to {args.output_json} and {args.output_csv}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
