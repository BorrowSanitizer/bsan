# This script calculates BorrowSanitizer's relative execution time
# across all test cases for a crate, and provides the output in a 
# .JSON file.
from dataclasses import dataclass
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

HYPERFINE_RUNS = 10
HYPERFINE_WARMUP = 3

# Uninstrumented native execution
NATIVE_CARGO = ["cargo", "test", "--lib"]

# Instrumented native execution in our "nop" mode, which 
# adds in our runtime checks, but does not enable the core Rust
# library with our Tree Borrows implementation. Every check is a
# nop. This is significantly less expensive than running BorrowSanitizer
# in full, and it helps debug issues associated with the LLVM components
# of the tool.
NOP_CARGO = ["cargo", "bsan", "test", "--nop", "--lib"]

def run(
    cmd: list[str],
    **kwargs,
) -> subprocess.CompletedProcess:
    """Run a command, raising CalledProcessError on non-zero exit.

    The command inherits the current environment.
    """
    return subprocess.run(cmd, check=True, env=os.environ.copy(), **kwargs)


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
        env=os.environ.copy(),
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

def compile_test_binary(cargo_cmd: list[str], label: str, cwd: Path, out: Path) -> Path:
    """Compiles the test binary for the given cargo invocation and return its
    path. Aborts on compile failure or if no test executable is produced."""
    print(f">>> compiling test binary ({label}): {' '.join(cargo_cmd)}",
          file=sys.stderr)
    # We need to parse the output JSON to find the name of the test binary.
    msg_json = run_capture(
        cargo_cmd + ["--no-run", "--message-format=json"],
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
            shutil.copy2(exe, out)
            out.chmod(0o755)
            return
        
    sys.exit(f"Error: could not locate {label} test binary.")

def list_tests(test_bin: Path) -> list[str]:
    """Return all #[test] names discovered in the given test binary."""
    out = run_capture([str(test_bin), "--list", "--format=terse"])
    tests = []
    for line in out.splitlines():
        line = line.strip()
        if line.endswith(": test"):
            tests.append(line[:-len(": test")])
    return tests

def hyperfine_mean(command: str) -> float:
    """Run hyperfine on a single command and return its mean wall time in
    seconds. Aborts the script on failure (no `-i`)."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out_json:
        out_path = Path(out_json.name)
    try:
        run(
            [
                "hyperfine",
                "--runs", str(HYPERFINE_RUNS),
                "--warmup", str(HYPERFINE_WARMUP),
                "--shell=none",
                "--export-json", str(out_path),
                command,
            ],
            stdout=subprocess.DEVNULL,
        )
        data = json.loads(out_path.read_text())
        return float(data["results"][0]["mean"])
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

    bench_name = f"{crate}@{version} (nop) - {target}"

    print(f"Running: {bench_name}")
    if excluded_tests:
        print("Excluding:")
        for test_name in excluded_tests:
            print(f"- {test_name}")

    src_dir = download_crate(crate, version, scratch)

    native_bin = scratch / "native_test_bin"
    compile_test_binary(NATIVE_CARGO, "native", cwd=src_dir, out=native_bin)

    try:
        run(["cargo", "clean", "--quiet"], cwd=src_dir)
    except subprocess.CalledProcessError:
        pass

    nop_bin = scratch / "nop_test_bin"
    compile_test_binary(NOP_CARGO, "nop", cwd=src_dir, out=nop_bin)

    all_tests = list_tests(native_bin)
    if not all_tests:
        sys.exit(f"Error: no tests discovered for {bench_name}.")

    tests = [t for t in all_tests if t not in excluded_tests]
    if not tests:
        sys.exit(f"Error: every discovered test was excluded for {bench_name}.")

    ratios: list[float] = []
    for t in tests:
        print(f"  -> {t}")
        n_mean = hyperfine_mean(f"{native_bin} --exact {t} --nocapture")
        i_mean = hyperfine_mean(f"{nop_bin} --exact {t} --nocapture")
        assert(n_mean > 0 and i_mean > 0)
        ratio = i_mean / n_mean
        print(f" - native={n_mean}s  inst={i_mean}s  ratio={ratio}")
        ratios.append(ratio)
        
    result = {
        "name": bench_name,
        "unit": "Median Relative Execution Time",
        "value": statistics.median(ratios),
        "extra": json.dumps({
            "mode": "nop",
            "target": target,
            "version": version,
            "crate": crate
        }),
    }
    return result

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
            result = process_config(cfg, args.target, scratch)
            print(
                f"Median relative execution time for {result["name"]}: {result["value"]}"
            )
            results.append(result)

    args.output_json.write_text(json.dumps(results, indent=4))
    print(f"Results written to {args.output_json}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))