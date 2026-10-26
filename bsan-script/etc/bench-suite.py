# This script was AI generated. It times each crate's whole test suite, 
# rather than each test on its own as `bench.py` does, under three configurations:
#
#   full                BorrowSanitizer, with libtest built with `--cfg=miri`
#   full-libtest-nocfg  BorrowSanitizer, with libtest built without it
#   miri-tb             Miri, with only Tree Borrows checking enabled
#
# A crate's excluded tests are skipped. BorrowSanitizer runs each suite twice:
# once with `--test-threads=1`, and once with libtest's default thread count.
# Miri runs each suite once, with the default thread count, since it executes
# threads one at a time anyway. Each run is timed with hyperfine. It produces a
# CSV with one row per crate, configuration, and thread setting.
import argparse
import csv
import os
import signal
import subprocess
import sys
import tarfile
import tempfile
import traceback
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench  # noqa: E402

# How long one run of a whole suite may take, in seconds. Miri gets
# `bench.MIRI_TIMEOUT_FACTOR` times as long.
SUITE_TIMEOUT = 1800

FULL = next(c for c in bench.BSAN_CONFIGS if c["name"] == "full")
MIRI = bench.MIRI

# Libtest arguments for each thread setting.
THREAD_MODES = {
    "1": ["--test-threads=1"],
    "default": [],
}

# The thread setting Miri is run with.
MIRI_THREADS = "default"

CSV_HEADERS = [
    'crate_name',
    'version',
    'mode',
    'threads',
    'status',
    'mean_exec_time_seconds',
    'error_message',
    'error_location',
    'error_detail',
]

def libtest_nocfg(sysroot: Path) -> dict:
    """Full checking, against a sysroot whose libtest was built without
    `--cfg=miri`, as made by:

      BSAN_SYSROOT=<dir> BSAN_LIBTEST_CFG_MIRI=0 cargo bsan setup

    Such a libtest only differs when `TERM` is set and a terminfo database
    can be found (e.g. through `TERMINFO`), since then it parses it.
    """
    return {
        "name": "full-libtest-nocfg",
        "cmd": FULL["cmd"],
        "env": {**FULL["env"], "BSAN_SYSROOT": str(sysroot)},
    }

def skip_args(cfg: dict) -> list[str]:
    """Libtest arguments that skip each of a crate's excluded tests, and
    nothing else."""
    excluded = dict.fromkeys(cfg.get("exclude") or [])
    if not excluded:
        return []
    return [arg for name in excluded for arg in ["--skip", name]] + ["--exact"]

def time_miri_suite(cwd: Path, harness_args: list[str], scratch: Path,
                    timeout: float) -> tuple[float | None, str, str | None]:
    """Time a whole Miri test suite, excluding `cargo-miri` overhead, by
    replaying its final `miri` invocation (see `bench.MIRI_WRAPPER_TEMPLATE`).
    """
    replay = scratch / "miri-replay.sh"
    replay.unlink(missing_ok=True)
    env = {**MIRI["env"]}
    env["MIRI"] = str(bench.ensure_miri_wrapper(scratch))
    env["BSAN_MIRI_REPLAY"] = str(replay)
    cmd = ["cargo", "miri", "test", "-q", "--lib"]
    if harness_args:
        cmd += ["--"] + harness_args
    status, output = bench.probe(cmd, timeout, cwd=cwd, env=env)
    if status == "test_failed":
        # `-Zmiri-mute-stdout-stderr` hides the suite's own output, including
        # the panic that failed it, so run it once more unmuted to say why.
        flags = env["MIRIFLAGS"].replace("-Zmiri-mute-stdout-stderr", "")
        _, unmuted = bench.probe(cmd, timeout, cwd=cwd, env={**env, "MIRIFLAGS": flags})
        output = unmuted or output
    if status != "success":
        return None, status, output
    if not replay.is_file():
        return None, "bench_failed", None
    return bench.hyperfine_mean(str(replay), MIRI, timeout, probed=True)

def process_crate(cfg: dict, scratch: Path, bsan_configs: list[dict],
                  timeout: float, emit) -> None:
    """Benchmark one crate, passing each CSV row to `emit` as soon as it is
    measured."""
    crate, version = cfg["name"], cfg["version"]
    print(f"Running: {crate}@{version}")
    skips = skip_args(cfg)

    def record(mode: str, threads: str, status: str, mean: float | None,
               output: str | None, src_dir: Path) -> None:
        shown = f"{mean:.4f}s" if mean is not None else status
        print(f"    - {mode} (threads={threads}): {shown}")
        bench.print_failure(f"{mode} (threads={threads})", "(whole suite)", output)
        error = bench.describe_failure(output, src_dir, "", status)
        emit((crate, version, mode, threads, status, mean,
              error["error_message"], error["error_location"],
              error["error_detail"]))

    def record_all(mode: str, failure: bench.CrateFailure, src_dir: Path) -> None:
        settings = [MIRI_THREADS] if mode == MIRI["name"] else THREAD_MODES
        for threads in settings:
            record(mode, threads, failure.status, None, failure.output, src_dir)

    try:
        src_dir = bench.download_crate(crate, version, scratch)
    except (OSError, urllib.error.URLError, tarfile.TarError) as exc:
        failure = bench.CrateFailure("setup_failed",
                                     f"could not download {crate}@{version}: {exc}")
        for config in bsan_configs + [MIRI]:
            record_all(config["name"], failure, scratch)
        return

    for config in bsan_configs:
        try:
            bench.compile_test_binary(config, cwd=src_dir, out_dir=scratch)
        except bench.CrateFailure as failure:
            record_all(config["name"], failure, src_dir)
            continue
        finally:
            bench.run_rc(["cargo", "clean", "--quiet"], cwd=src_dir)
        binary = scratch / config["name"]
        for threads, args in THREAD_MODES.items():
            cmd = bench.shlex.join([str(binary)] + args + skips)
            mean, status, output = bench.hyperfine_mean(
                cmd, config, timeout, env=config.get("env"))
            record(config["name"], threads, status, mean, output, src_dir)

    try:
        bench.compile_miri_tests(src_dir)
    except subprocess.CalledProcessError as exc:
        record_all(MIRI["name"], bench.CrateFailure(
            "build_failed", "tests failed to compile under Miri",
            bench.compiler_output(exc.stdout, exc.stderr)), src_dir)
        return
    mean, status, output = time_miri_suite(
        src_dir, THREAD_MODES[MIRI_THREADS] + skips, scratch,
        timeout * bench.MIRI_TIMEOUT_FACTOR)
    record(MIRI["name"], MIRI_THREADS, status, mean, output, src_dir)

def print_summary(rows: list[tuple]) -> None:
    """Print each crate's BorrowSanitizer times relative to Miri, and to each
    other."""
    means = {(r[0], r[2], r[3]): r[5] for r in rows if r[5] is not None}
    full, nocfg = FULL["name"], "full-libtest-nocfg"
    for crate in dict.fromkeys(r[0] for r in rows):
        miri = means.get((crate, MIRI["name"], MIRI_THREADS))
        for threads in THREAD_MODES:
            parts = []
            for mode, base, base_threads in [(full, MIRI["name"], MIRI_THREADS),
                                             (nocfg, MIRI["name"], MIRI_THREADS),
                                             (nocfg, full, threads)]:
                m = means.get((crate, mode, threads))
                b = miri if base == MIRI["name"] else means.get((crate, base, base_threads))
                if m and b:
                    parts.append(f"{mode} {m / b:.2f}x vs {base}")
            print(f"{crate} (threads={threads}): {', '.join(parts) or 'no ratio'}")

def write_csv(path: Path, rows: list[tuple]) -> None:
    """Replace `path` with `rows`, so that a run stopped part-way through a
    write never leaves a truncated CSV behind."""
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", newline="") as out:
        csv_out = csv.writer(out)
        csv_out.writerow(CSV_HEADERS)
        csv_out.writerows(rows)
    os.replace(tmp, path)

def main(argv: list[str]) -> int:
    sys.stdout.reconfigure(line_buffering=True)
    # By default, SIGTERM and SIGHUP end us without unwinding, which would
    # leave the suite being timed running in its own session (see
    # `bench.run_limited`). As exceptions, they stop it first.
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda signum, _: sys.exit(128 + signum))
    parser = argparse.ArgumentParser(
        description="Time whole test suites under BorrowSanitizer and Miri")
    parser.add_argument("crates_json", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--libtest-nocfg-sysroot", type=Path, required=True,
                        metavar="DIR",
                        help="A BorrowSanitizer sysroot whose libtest was built "
                             "without --cfg=miri.")
    parser.add_argument("--crate", action="append", dest="only", metavar="NAME",
                        help="Only benchmark the named crate (repeatable).")
    parser.add_argument("--suite-timeout", type=float, default=SUITE_TIMEOUT,
                        metavar="SECONDS",
                        help=f"How long one run of a suite may take (default: "
                             f"{SUITE_TIMEOUT}; Miri gets "
                             f"{bench.MIRI_TIMEOUT_FACTOR}x as long).")
    args = parser.parse_args(argv)
    for tool in ["cargo", "hyperfine"]:
        bench.require_tool(tool)
    if not args.libtest_nocfg_sysroot.is_dir():
        sys.exit(f"Error: {args.libtest_nocfg_sysroot} is not a directory")
    bsan_configs = [FULL, libtest_nocfg(args.libtest_nocfg_sysroot.resolve())]

    configs = bench.json.loads(args.crates_json.read_text())
    if args.only:
        wanted = set(args.only)
        configs = [c for c in configs if c["name"] in wanted]
        missing = wanted - {c["name"] for c in configs}
        if missing:
            sys.exit(f"Error: not found: {', '.join(sorted(missing))}")
    print(f"Benchmarking {len(configs)} crate(s): {', '.join(c['name'] for c in configs)}")

    rows: list[tuple] = []

    # Written after every row, so a long run that is stopped keeps what it
    # has measured.
    def emit(row: tuple) -> None:
        rows.append(row)
        write_csv(args.output_csv, rows)

    for cfg in configs:
        with tempfile.TemporaryDirectory() as scratch_str:
            try:
                process_crate(cfg, Path(scratch_str), bsan_configs,
                              args.suite_timeout, emit)
            except Exception as exc:
                output = traceback.format_exc()
                print(output, file=sys.stderr)
                emit((cfg["name"], cfg["version"], "", "", "setup_failed", None,
                      f"benchmarking crashed: {exc}"[:300], "", output))

    print_summary(rows)
    print(f"Results written to {args.output_csv}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
