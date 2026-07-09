# This script calculates BorrowSanitizer's relative execution time
# across all test cases for a crate. It produces two output files:
#
# * A JSON file with relative execution times in a format that is
#   compatible with `github-actions-benchmark`
#
# * A CSV file listing the mean execution times of each mode, including
#   both the baselines and tested configurations.
#
# Methodology:
# * Per-test BSan full/no-op runs use `--skip-harness` so libtest/getopts do
#   not emit retags (LLVM pass still runs). vs-native ratios use those wall
#   times directly.
# * A bare `libtest` benchmark builds the empty fixture crate
#   `tests/benches/libtest-empty` *without* `--skip-harness` and times a
#   zero-test launch once per bench run (true harness-only cost).
# * A per-crate `libtest-crate` row does the same on that crate's fully
#   instrumented test binary (harness + discovering that crate's tests).
# * vs-Miri ratios use wall-clock times as-is. Miri always interprets the
#   harness, so skip-harness does not apply there.
import argparse
import statistics
import json
import csv
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

RUNS = 3
WARMUP = 1

REPO_ROOT = Path(__file__).resolve().parents[2]
# Empty crate used for the bare libtest-only benchmark (no #[test] items).
LIBTEST_EMPTY_DIR = REPO_ROOT / "tests" / "benches" / "libtest-empty"
LIBTEST_BARE_NAME = "libtest"
LIBTEST_BARE_CRATE = "libtest-empty"
LIBTEST_BARE_VERSION = "0.1.0"
# Per-crate fully instrumented harness floor (crate test binary, zero matches).
LIBTEST_CRATE_NAME = "libtest-crate"
LIBTEST_FLOOR_FILTER = "__bsan_libtest_floor_nonexistent__"

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
    "env": {"MIRIFLAGS": f"-Zmiri-tree-borrows {MIRI_COMMON_FLAGS}"},
}

# Every Miri configuration.
MIRI_CONFIGS = [MIRI]

# Per-test BorrowSanitizer configurations. `--skip-harness` omits retags in
# libtest/getopts so short tests are not dominated by harness retags.
BSAN_CONFIGS = [
    # Full checking
    {
        "name": "full",
        "cmd": ["cargo", "bsan", "test", "--skip-harness", "--lib"],
        "env": {"RUSTFLAGS": "--cfg=miri"},
    },
    # No-op checking. Instrumentation is inserted, but
    # all memory access checks, retags, and reference count
    # updates are disabled.
    {
        "name": "no-op",
        "cmd": ["cargo", "bsan", "test", "--nop", "--skip-harness", "--lib"],
        "env": {"RUSTFLAGS": "--cfg=miri"},
    }
]

# Fully instrumented harness builds (no `--skip-harness`). Used for bare
# `libtest` and per-crate `libtest-crate` floors, not for per-test timings.
LIBTEST_INSTRUMENTED_CONFIGS = [
    {
        "name": "full",
        "binary": "full-harness",
        "cmd": ["cargo", "bsan", "test", "--lib"],
        "env": {"RUSTFLAGS": "--cfg=miri"},
    },
    {
        "name": "no-op",
        "binary": "nop-harness",
        "cmd": ["cargo", "bsan", "test", "--nop", "--lib"],
        "env": {"RUSTFLAGS": "--cfg=miri"},
    },
]

# Every configuration used for per-test timings.
ALL_BINARY_CONFIGS = [NATIVE] + BSAN_CONFIGS


# Raw timing results are output as a CSV with these headers.
CSV_HEADERS = [
    'target',
    'crate_name',
    'version',
    'test_name',
    'mode',
    'mean_exec_time_seconds'
]

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
    """Creates a copy of the current environment, merged with an `env` mapping from `kwargs`."""
    env = os.environ.copy()
    env.update(kwargs.pop("env", None) or {})
    return env

def run(
    cmd: list[str],
    **kwargs,
) -> subprocess.CompletedProcess:
    """Run a command, raising CalledProcessError on non-zero exit.

    The command inherits the current environment.
    """
    return subprocess.run(cmd, check=True, env=_build_env(kwargs), **kwargs)

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

def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        sys.exit(f"Error: '{name}' is required but not installed.")

def download_crate(crate: str, version: str, dest_dir: Path) -> Path:
    """Downloads <crate>@<version> from crates.io into dest_dir, extracts it,
    and returns the path to the extracted contents."""
    url = f"https://crates.io/api/v1/crates/{crate}/{version}/download"
    tarball = dest_dir / f"{crate}-{version}.crate"

    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as resp, open(tarball, "wb") as out:
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

def compile_test_binary(config: dict, cwd: Path, out_dir: Path, binary_name: str | None = None):
    """Compiles the test binary for the given cargo invocation and copies it into
    `out_dir`. Aborts on compile failure or if no executable is created.
    """
    name = binary_name or config["name"]
    print(f"compiling tests ({name}): {' '.join(config["cmd"])}",
          file=sys.stderr)
    # We need to parse the output JSON to find the name of the test binary.
    msg_json = run_capture(
        config["cmd"] + ["--no-run", "--message-format=json"],
        cwd=cwd,
        env=config.get("env"),
    )
    for msg in TestHarnessJSON(msg_json):
        exe = msg.get("executable")
        target = msg.get("target") or {}
        if exe and target.get("test"):
            print("done.")
            binary = out_dir / name
            shutil.copy2(exe, binary)
            binary.chmod(0o755)
            return

    sys.exit(f"Error: could not locate {name} test binary.")

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

def capture_miri_replay(cwd: Path, t: str, config: dict, scratch: Path) -> Path:
    """Run cargo-miri once to emit a replay script for test filter `t`."""
    replay = scratch / "miri-replay.sh"
    if replay.is_file():
        replay.unlink()

    override_env = { **(config.get("env") or {}) }
    override_env["MIRI"] = str(ensure_miri_wrapper(scratch))
    override_env["BSAN_MIRI_REPLAY"] = str(replay)

    run_capture(["cargo", "miri", "test", "-q", "--lib", "--", "--exact", t, "--nocapture"],
                cwd=cwd, env=override_env)
    if not replay.is_file():
        sys.exit(f"Error: failed to intercept miri invocation for test {t}.")
    return replay

def run_miri_test(cwd: Path, t: str, config: dict, scratch: Path) -> float:
    """Time a single Miri test, excluding `cargo-miri` overhead, by capturing its
    final `miri` invocation as a standalone script."""
    replay = capture_miri_replay(cwd, t, config, scratch)
    return hyperfine_mean(str(replay), config)

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

def hyperfine_mean(cmd, config: dict, **kwargs) -> float:
    """Run hyperfine on a single command and return its mean wall time in
    seconds. Aborts on failure"""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out_json:
        out_path = Path(out_json.name)
    try:
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
        run(
            [
                "hyperfine",
                "--runs", str(RUNS),
                "--warmup", str(WARMUP),
                "--shell=none",
                "--export-json", str(out_path),
                "--show-output",
                cmd,
            ],
            **kwargs
        )
        data = json.loads(out_path.read_text())
        mean = float(data["results"][0]["mean"])
        return mean
    finally:
        out_path.unlink(missing_ok=True)

def require_positive_mean(mean: float, name: str, t: str, bench_name: str) -> None:
    """Abort if a benchmark reported a non-positive mean execution time."""
    if mean <= 0:
        sys.exit(f"Reported 0s mean execution time for {name} on test {t} from {bench_name}")

def _time_zero_test_modes(
    scratch: Path,
    target: str,
    crate: str,
    version: str,
    test_name: str,
    result_label: str,
    *,
    native_binary: str,
    launch_args: str,
    extra: dict,
) -> tuple[dict[str, float], list, list]:
    """Time native + instrumented full/no-op zero-test launches.

    `scratch` must already contain `native_binary` and each
    LIBTEST_INSTRUMENTED_CONFIGS[*]["binary"].
    """
    means: dict[str, float] = {}
    raw_rows = []
    relative_rows = []
    row_start = (target, crate, version, test_name)
    print(f"  -> {test_name} ({result_label})")

    native_bin = scratch / native_binary
    native_mean = hyperfine_mean(
        f"{native_bin} {launch_args}",
        NATIVE,
        env=NATIVE.get("env"),
    )
    require_positive_mean(native_mean, NATIVE["name"], test_name, result_label)
    print(f"    - {NATIVE['name']}={round(native_mean, 8)}s")
    means[NATIVE["name"]] = native_mean
    raw_rows.append(row_start + (NATIVE["name"], native_mean))

    for config in LIBTEST_INSTRUMENTED_CONFIGS:
        binary = scratch / config["binary"]
        mean = hyperfine_mean(
            f"{binary} {launch_args}",
            config,
            env=config.get("env"),
        )
        require_positive_mean(mean, config["name"], test_name, result_label)
        print(f"    - {config['name']}={round(mean, 8)}s")
        means[config["name"]] = mean
        raw_rows.append(row_start + (config["name"], mean))
        ratio = mean / native_mean
        print(f"    - {config['name']} vs {NATIVE['name']} ({test_name}) = {round(ratio, 4)}x")
        relative_rows.append({
            "name": f"{result_label} [{test_name}]",
            "unit": "Mean Relative Execution Time",
            "value": ratio,
            "extra": json.dumps({
                "mode": config["name"],
                "baseline": NATIVE["name"],
                "target": target,
                "version": version,
                "crate": crate,
                "test_name": test_name,
                "skip_harness": False,
                "libtest_seconds": means,
                **extra,
            }),
        })
    return means, raw_rows, relative_rows


def measure_bare_libtest(target: str, scratch: Path) -> tuple[list, list]:
    """Time a true bare libtest harness via the empty fixture crate.

    Builds `tests/benches/libtest-empty` without `--skip-harness` and launches
    the test binary with no tests. This is the suite's `libtest` benchmark.
    """
    if not LIBTEST_EMPTY_DIR.is_dir():
        sys.exit(f"Error: bare libtest fixture missing: {LIBTEST_EMPTY_DIR}")

    bare_scratch = scratch / "bare-libtest"
    bare_scratch.mkdir(parents=True, exist_ok=True)
    src_dir = LIBTEST_EMPTY_DIR
    label = f"{LIBTEST_BARE_CRATE}@{LIBTEST_BARE_VERSION} - {target}"
    print(f"Running bare libtest: {label}")

    compile_test_binary(NATIVE, cwd=src_dir, out_dir=bare_scratch)
    try:
        run(["cargo", "clean", "--quiet"], cwd=src_dir)
    except subprocess.CalledProcessError:
        pass

    for config in LIBTEST_INSTRUMENTED_CONFIGS:
        compile_test_binary(
            config, cwd=src_dir, out_dir=bare_scratch, binary_name=config["binary"]
        )
        try:
            run(["cargo", "clean", "--quiet"], cwd=src_dir)
        except subprocess.CalledProcessError:
            pass

    _means, raw_rows, relative_rows = _time_zero_test_modes(
        bare_scratch,
        target,
        LIBTEST_BARE_CRATE,
        LIBTEST_BARE_VERSION,
        LIBTEST_BARE_NAME,
        label,
        native_binary=NATIVE["name"],
        # Empty crate: no filter needed; suite has zero #[test] items.
        launch_args="--nocapture",
        extra={"bare_libtest": True},
    )
    return raw_rows, relative_rows


def measure_crate_libtest_floor(
    scratch: Path,
    target: str,
    crate: str,
    version: str,
    bench_name: str,
) -> tuple[list, list]:
    """Time this crate's fully instrumented test binary with zero matches.

    Distinct from bare `libtest`: includes discovering/filtering this crate's
    test list under an instrumented harness.
    """
    _means, raw_rows, relative_rows = _time_zero_test_modes(
        scratch,
        target,
        crate,
        version,
        LIBTEST_CRATE_NAME,
        bench_name,
        native_binary=NATIVE["name"],
        launch_args=f"--exact {LIBTEST_FLOOR_FILTER} --nocapture",
        extra={"libtest_crate_floor": True},
    )
    return raw_rows, relative_rows

def process_config(
    cfg: dict,
    target: str,
    scratch: Path,
) -> list:
    crate = cfg.get("name")
    version = cfg.get("version")
    excluded_tests = set(cfg.get("exclude") or [])
    included_tests = cfg.get("include")
    if included_tests is not None:
        included_tests = set(included_tests)

    if not crate or not version:
        sys.exit(f"Error: invalid per-crate config:\n{cfg}")

    bench_name = f"{crate}@{version} - {target}"

    print(f"Running: {bench_name}")
    if excluded_tests:
        print("Excluding:")
        for test_name in excluded_tests:
            print(f"- {test_name}")
    if included_tests is not None:
        print("Including only:")
        for test_name in sorted(included_tests):
            print(f"- {test_name}")

    src_dir = download_crate(crate, version, scratch)

    # Per-test binaries (native + skip-harness full/no-op).
    for config in ALL_BINARY_CONFIGS:
        compile_test_binary(config, cwd=src_dir, out_dir=scratch)
        try:
            run(["cargo", "clean", "--quiet"], cwd=src_dir)
        except subprocess.CalledProcessError:
            pass

    # Fully instrumented harness binaries for the per-crate libtest floor.
    for config in LIBTEST_INSTRUMENTED_CONFIGS:
        compile_test_binary(
            config, cwd=src_dir, out_dir=scratch, binary_name=config["binary"]
        )
        try:
            run(["cargo", "clean", "--quiet"], cwd=src_dir)
        except subprocess.CalledProcessError:
            pass

    all_tests = list_tests(src_dir, ["cargo", "miri", "test", "--"])

    if not all_tests:
        sys.exit(f"Error: no tests discovered for {bench_name}.")
    else:
        print(f"Found {len(all_tests)} tests for {bench_name}.")

    tests = [t for t in all_tests if t not in excluded_tests]
    if included_tests is not None:
        missing = included_tests - set(all_tests)
        if missing:
            sys.exit(
                f"Error: include list references unknown tests for {bench_name}: "
                + ", ".join(sorted(missing))
            )
        tests = [t for t in tests if t in included_tests]
    if not tests:
        sys.exit(f"Error: every discovered test was excluded for {bench_name}.")

    compile_miri_tests(src_dir)

    # vs-native: wall-clock ratios (BSan built with --skip-harness).
    # vs-Miri: wall-clock ratios (Miri always interprets the harness).
    ratios: dict[tuple[str, str], list[float]] = {}
    raw_results = []

    # Per-crate instrumented harness floor (not the bare libtest benchmark).
    crate_libtest_rows, crate_libtest_relative = measure_crate_libtest_floor(
        scratch, target, crate, version, bench_name
    )
    raw_results.extend(crate_libtest_rows)

    for t in tests:
        row_start = (target, crate, version, t)
        print(f"  -> {t}")
        per_test_means: dict[str, float] = {}

        for config in ALL_BINARY_CONFIGS:
            binary = scratch / config["name"]
            mean = hyperfine_mean(f"{binary} --exact {t} --nocapture", config,
                                  env=config.get("env"))
            require_positive_mean(mean, config["name"], t, bench_name)
            print(f"    - {config['name']}={round(mean, 8)}s")
            per_test_means[config["name"]] = mean
            raw_results.append(row_start + (config["name"], mean))

        baselines = {NATIVE["name"]: per_test_means.pop(NATIVE["name"])}

        for miri_config in MIRI_CONFIGS:
            miri_mean = run_miri_test(src_dir, t, miri_config, scratch)
            require_positive_mean(miri_mean, miri_config["name"], t, bench_name)
            print(f"    - {miri_config['name']}={round(miri_mean, 8)}s")
            baselines[miri_config["name"]] = miri_mean
            raw_results.append(row_start + (miri_config["name"], miri_mean))

        for mode, mode_mean in per_test_means.items():
            for baseline, baseline_mean in baselines.items():
                ratio = mode_mean / baseline_mean
                ratios.setdefault((mode, baseline), []).append(ratio)
                print(f"    - {mode} vs {baseline} = {round(ratio, 4)}x")

    relative_results = list(crate_libtest_relative)
    for (mode, baseline), ratio_list in ratios.items():
        if not ratio_list:
            continue
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
                "min": min(ratio_list),
                "skip_harness": True,
            }),
        })

    return {
        "relative": relative_results,
        "raw": raw_results
    }

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark relative execution time",
        usage=(
            "%(prog)s <crates> <target> <output_json> <output_csv>"
        ),
    )
    parser.add_argument("crates_json", type=Path)
    parser.add_argument("target", type=str)
    parser.add_argument("output_json", type=Path)
    parser.add_argument("output_csv", type=Path)

    args = parser.parse_args(argv)
    for tool in ["cargo", "hyperfine"]:
        require_tool(tool)

    crates_json = args.crates_json
    if not crates_json.is_file():
        sys.exit(f"Error: invalid config file: {crates_json}")

    all_results = {}
    with tempfile.TemporaryDirectory() as scratch_str:
        scratch = Path(scratch_str)

        # Bare libtest once per bench run (empty fixture crate).
        bare_raw, bare_relative = measure_bare_libtest(args.target, scratch)
        all_results.setdefault("relative", [])
        all_results["relative"] += bare_relative
        all_results.setdefault("raw", [])
        all_results["raw"] += bare_raw

        for cfg in json.loads(crates_json.read_text()):
            cfg_results = process_config(cfg, args.target, scratch)
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

    print(f"Results written to {args.output_json} and {args.output_csv}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
