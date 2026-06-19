# This script calculates BorrowSanitizer's relative execution time
# across all test cases for a crate. It produces two output files:
#
# * A JSON file with relative execution times in a format that is
#   compatible with `github-actions-benchmark`
#
# * A CSV file listing the mean execution times of each mode, including
#   both the baselines and tested configurations.
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

# Uninstrumented native execution.
NATIVE = {
    "name": "native",
    "cmd": ["cargo", "test", "--lib"],
    "env": {"RUSTFLAGS": "--cfg=bsan"},
}

# Flags shared by every Miri configuration. These disable most forms of
# checking, and ensure deterministic execution.
MIRI_COMMON_FLAGS = (
    "-Zmiri-provenance-gc=0 -Zmiri-mute-stdout-stderr "
    "-Zmiri-disable-data-race-detector -Zmiri-deterministic-concurrency "
    "-Zmiri-disable-alignment-check -Zmiri-ignore-leaks"
)

# Miri with Tree Borrows enabled,and all other checking disabled
# (to the extent possible).
MIRI = {
    "name": "miri-tb",
    "env": {"MIRIFLAGS": f"-Zmiri-tree-borrows {MIRI_COMMON_FLAGS}"},
}

# Miri with Tree Borrows disabled. This is as close to "just interpret" as
# we can get. However, the core interpreter will still check for certain forms
# of UB, like accessese out-of-bounds, use-after-free errors, and uninitialized accesses.
MIRI_BASE = {
    "name": "miri-base",
    "env": {"MIRIFLAGS": f"-Zmiri-disable-stacked-borrows {MIRI_COMMON_FLAGS}"},
}

# Every Miri configuration.
MIRI_CONFIGS = [MIRI, MIRI_BASE]

# BorrowSanitizer configurations.
BSAN_CONFIGS = [
    # Full checking
    {
        "name": "full",
        "cmd": ["cargo", "bsan", "test", "--lib"],
    },
    # No-op checking. Instrumentation is inserted, but
    # all memory access checks, retags, and reference count
    # updates are disabled.
    {
        "name": "no-op",
        "cmd": ["cargo", "bsan", "test", "--nop", "--lib"],
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
    'mean_exec_time_seconds'
]

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

def compile_test_binary(config: dict, cwd: Path, out_dir: Path):
    """Compiles the test binary for the given cargo invocation and copies it into
    `out_dir`. Aborts on compile failure or if no executable is created.
    """
    print(f">>> compiling tests ({config["name"]}): {' '.join(config["cmd"])}",
          file=sys.stderr)
    # We need to parse the output JSON to find the name of the test binary.
    msg_json = run_capture(
        config["cmd"] + ["--no-run", "--message-format=json"],
        cwd=cwd,
        env=config.get("env"),
    )
    for line in msg_json.splitlines():
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        exe = msg.get("executable")
        target = msg.get("target") or {}
        if exe and target.get("test"):
            print(">>> done.")
            binary = out_dir / config["name"]
            shutil.copy2(exe, binary)
            binary.chmod(0o755)
            return

    sys.exit(f"Error: could not locate {config["name"]} test binary.")

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
    print(">>> compiling tests (miri)")
    run_capture(
        ["cargo", "miri", "test", "--no-run", "--message-format=json"],
        cwd=cwd,
    )

def run_miri_test(cwd: Path, t: str, config: dict, scratch: Path) -> float:
    """Time a single Miri test, excluding `cargo-miri` overhead, by capturing its
    final `miri` invocation as a standalone script."""
    replay = scratch / "miri-replay.sh"

    override_env = { **(config.get("env") or {}) }
    override_env["MIRI"] = str(ensure_miri_wrapper(scratch))
    override_env["BSAN_MIRI_REPLAY"] = str(replay)

    # One cargo-miri run generates the replay script for this test's final miri
    # invocation; we then time that script on its own, free of cargo overhead.
    run_capture(["cargo", "miri", "test", "-q", "--lib", "--", "--exact", t, "--nocapture"],
                cwd=cwd, env=override_env)
    if not replay.is_file():
        sys.exit(f"Error: failed to intercept miri invocation for test {t}.")
    return hyperfine_mean(str(replay), config)

def list_tests(test_bin: Path) -> list[str]:
    """Return all #[test] names discovered in the given test binary."""
    out = run_capture([str(test_bin), "--list", "--format=terse"])
    tests = []
    for line in out.splitlines():
        line = line.strip()
        if line.endswith(": test"):
            tests.append(line[:-len(": test")])
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

def process_config(
    cfg: dict,
    target: str,
    scratch: Path,
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

    src_dir = download_crate(crate, version, scratch)
    for config in ALL_BINARY_CONFIGS:
        compile_test_binary(config, cwd=src_dir, out_dir=scratch)
        try:
            run(["cargo", "clean", "--quiet"], cwd=src_dir)
        except subprocess.CalledProcessError:
            pass

    all_tests = list_tests(scratch / NATIVE["name"])
    if not all_tests:
        sys.exit(f"Error: no tests discovered for {bench_name}.")

    tests = [t for t in all_tests if t not in excluded_tests]
    if not tests:
        sys.exit(f"Error: every discovered test was excluded for {bench_name}.")
    compile_miri_tests(src_dir)

    # a mapping from (config, baseline) pairs to mean execution times for each test case
    # for example, we would have `ratios[("no-op", "miri-tb")]` map to the list of
    # mean execution times for our no-op mode relative to Miri with tree borrows enabled.
    ratios: dict[tuple[str, str], list[float]] = {}

    # a raw list of execution times per crate, version, test case, and mode
    raw_results: tuple[str, str, str, str, str, float] = []

    count = 0
    for t in tests:
        count += 1
        if count > 1:
            break
        row_start = (target, crate, version, t)
        print(f"  -> {t}")
        # a mapping from each config to its mean execution time
        per_test_means: dict[str, float] = {}

        # execute every natively-compiled binary and record its mean execution time
        for config in ALL_BINARY_CONFIGS:
            binary = scratch / config["name"]
            mean = hyperfine_mean(f"{binary} --exact {t} --nocapture", config,
                                  env=config.get("env"))
            if mean <= 0:
                sys.exit(f"""Reported 0s mean execution time for
                          {config["name"]} on test {t} from {bench_name}""")
            print(f"    - {config['name']}={round(mean, 8)}s")
            per_test_means[config["name"]] = mean
            raw_results.append(row_start + (config["name"], mean))

        baselines = {NATIVE["name"]: per_test_means.pop(NATIVE["name"])}

        # execute Miri and add each configuration as a baseline for comparison
        for miri_config in MIRI_CONFIGS:
            miri_mean = run_miri_test(src_dir, t, miri_config, scratch)
            if mean <= 0:
                sys.exit(f"""Reported 0s mean execution time for
                          {config["name"]} on test {t} from {bench_name}""")
            print(f"    - {miri_config['name']}={round(miri_mean, 8)}s")
            baselines[miri_config["name"]] = miri_mean
            raw_results.append(row_start + (miri_config["name"], mean))

        for mode, mode_mean in per_test_means.items():
            for baseline, baseline_mean in baselines.items():
                ratio = mode_mean / baseline_mean
                ratios.setdefault((mode, baseline), []).append(ratio)
                print(f"    - {mode} vs {baseline} = {round(ratio, 4)}x")

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