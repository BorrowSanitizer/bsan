# This script calculates BorrowSanitizer's relative execution time
# across all test cases for a crate, and provides the output in a
# .JSON file.
import argparse
import statistics
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

NATIVE = {
    "name": "native",
    "cmd": ["cargo", "test", "--lib"],
    "runs": 3,
    "warmup": 1
}

MIRI = {
    "name": "miri-tb",
    "env": {
        "MIRIFLAGS": [
            "-Zmiri-tree-borrows",
            "-Zmiri-provenance-gc=0",
            "-Zmiri-mute-stdout-stderr",
            "-Zmiri-disable-data-race-detector",
            "-Zmiri-deterministic-concurrency",
            "-Zmiri-disable-alignment-check"
        ]
    },
    "runs": 3,
    "warmup": 1
}

BSAN_CONFIGS = [
    {
        "name": "full",
        "cmd": ["cargo", "bsan", "test", "--lib"],
        "runs": 3,
        "warmup": 1
    },
    {
        "name": "no-op",
        "cmd": ["cargo", "bsan", "test", "--nop", "--lib"],
        "runs": 3,
        "warmup": 1
    }
]


ALL_BINARY_CONFIGS = [NATIVE] + BSAN_CONFIGS

def _build_env(kwargs: dict) -> dict:
    """Pop an optional `env` mapping from kwargs and merge it on top of a copy
    of the current environment, so callers can override individual variables
    without dropping the inherited ones."""
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

def compile_test_binary(config: dict, cwd: Path, out_dir: Path) -> Path:
    """Compiles the test binary for the given cargo invocation and return its
    path. Aborts on compile failure or if no test executable is produced."""
    print(f">>> compiling tests ({config["name"]}): {' '.join(config["cmd"])}",
          file=sys.stderr)
    # We need to parse the output JSON to find the name of the test binary.
    msg_json = run_capture(
        config["cmd"] + ["--no-run", "--message-format=json"],
        cwd=cwd,
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

def miri_env(config: dict) -> dict:
    """Build the environment overrides for a Miri run, exposing the config's
    `flags` as the MIRIFLAGS variable."""
    return {"MIRIFLAGS": " ".join(config.get("flags") or [])}

def compile_miri_tests(cwd: Path):
    print(">>> compiling tests (miri)")
    run_capture(
        ["cargo", "miri", "test", "--no-run", "--message-format=json"],
        cwd=cwd,
    )
def run_miri_test(cwd: Path, t: str, config: dict):
    cmd = f"cargo miri test -q --lib -- --exact {t} --nocapture"
    return hyperfine_mean(cmd, config, cwd=cwd, env=miri_env(config))

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
    seconds. Aborts the script on failure (no `-i`)."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out_json:
        out_path = Path(out_json.name)
    try:
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
        run(
            [
                "hyperfine",
                "--runs", str(config["runs"]),
                "--warmup", str(config["warmup"]),
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

def process_config(
    cfg: dict,
    target: str,
    scratch: Path,
) -> None:
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

    ratios: dict[tuple[str, str], list[float]] = {}
    for t in tests:
        print(f"  -> {t}")
        per_test_means = {}
        for config in ALL_BINARY_CONFIGS:
            binary = scratch / config["name"]
            mean = hyperfine_mean(f"{binary} --exact {t} --nocapture", config)
            if mean <= 0:
                sys.exit(f"Reported 0s mean execution time for {config['name']} on test {t} from {bench_name}")
            print(f"    - {config['name']}={round(mean, 8)}s")
            per_test_means[config["name"]] = mean

        miri_mean = run_miri_test(src_dir, t, MIRI)
        if miri_mean <= 0:
            sys.exit(f"Reported 0s mean execution time for {MIRI['name']} on test {t} from {bench_name}")
        print(f"    - {MIRI['name']}={round(miri_mean, 8)}s")
        baselines = {
            NATIVE["name"]: per_test_means.pop(NATIVE["name"]),
            MIRI["name"]: miri_mean,
        }

        for mode, mode_mean in per_test_means.items():
            for baseline, baseline_mean in baselines.items():
                ratio = mode_mean / baseline_mean
                ratios.setdefault((mode, baseline), []).append(ratio)
                print(f"      {mode} vs {baseline} = {round(ratio, 4)}x")

    results = []
    for (mode, baseline), ratio_list in ratios.items():
        results.append({
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
    return results

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark relative execution time",
        usage=(
            "%(prog)s <crates> <target> <output>"
        ),
    )
    parser.add_argument("crates_json", type=Path)
    parser.add_argument("target", type=str)
    parser.add_argument("output_json", type=Path)

    args = parser.parse_args(argv)
    for tool in ["cargo", "hyperfine"]:
        require_tool(tool)

    crates_json = args.crates_json
    if not crates_json.is_file():
        sys.exit(f"Error: invalid config file: {crates_json}")

    results = []
    with tempfile.TemporaryDirectory() as scratch_str:
        scratch = Path(scratch_str)
        for cfg in json.loads(crates_json.read_text()):
            results += process_config(cfg, args.target, scratch)

    args.output_json.write_text(json.dumps(results, indent=4))
    print(f"Results written to {args.output_json}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
