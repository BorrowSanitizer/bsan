
import argparse
import json
import math
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

HYPERFINE_RUNS = 10
HYPERFINE_WARMUP = 3

NATIVE_CARGO = ["cargo", "test", "--lib"]
INSTR_CARGO = ["cargo", "bsan", "test", "--nop", "--lib"]

def _merge_env(extra_env: dict[str, str] | None) -> dict[str, str] | None:
    """Merge extra_env on top of os.environ. Returns None if extra_env is
    None, so subprocess inherits the parent environment unchanged."""
    if extra_env is None:
        return None
    merged = os.environ.copy()
    merged.update(extra_env)
    return merged


def run(
    cmd: list[str],
    *,
    extra_env: dict[str, str] | None = None,
    **kwargs,
) -> subprocess.CompletedProcess:
    """Run a command, raising CalledProcessError on non-zero exit.

    extra_env is merged on top of the current environment (not replacing it).
    """
    return subprocess.run(cmd, check=True, env=_merge_env(extra_env), **kwargs)


def run_capture(
    cmd: list[str],
    *,
    extra_env: dict[str, str] | None = None,
    **kwargs,
) -> str:
    """Run a command and return stdout as a string.

    extra_env is merged on top of the current environment (not replacing it).
    """
    proc = subprocess.run(
        cmd, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=_merge_env(extra_env),
        **kwargs,
    )
    return proc.stdout

def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        sys.exit(f"Error: '{name}' is required but not installed.")

def download_crate(crate: str, version: str, dest_dir: Path) -> Path:
    """Download <crate>@<version> from crates.io into dest_dir, extract it,
    and return the path to the extracted source directory."""
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

def compile_test_binary(cargo_cmd: list[str], label: str, cwd: Path, extra_env: dict[str, str] | None = None) -> Path:
    """Compile the test binary for the given cargo invocation and return its
    path. Aborts on compile failure or if no test executable is produced."""
    print(f">>> compiling test binary ({label}): {' '.join(cargo_cmd)}",
          file=sys.stderr)

    run(cargo_cmd + ["--no-run", "--quiet"], cwd=cwd, extra_env=extra_env)

    msg_json = run_capture(
        cargo_cmd + ["--no-run", "--message-format=json"],
        cwd=cwd,
        extra_env=extra_env
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
            return Path(exe)

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

def hyperfine_mean(out_json: Path, command: str) -> float:
    """Run hyperfine on a single command and return its mean wall time in
    seconds. Aborts the script on failure (no `-i`)."""
    run(
        [
            "hyperfine",
            "--runs", str(HYPERFINE_RUNS),
            "--warmup", str(HYPERFINE_WARMUP),
            "--shell=none",
            "--export-json", str(out_json),
            command,
        ],
        stdout=subprocess.DEVNULL,
    )
    data = json.loads(out_json.read_text())
    return float(data["results"][0]["mean"])

@dataclass
class Aggregate:
    geomean: float
    minimum: float
    maximum: float

def aggregate_ratios(ratios: list[float]) -> Aggregate:
    if not ratios:
        sys.exit("Error: no ratios to aggregate.")
    if any(r <= 0 for r in ratios):
        sys.exit(f"Error: non-positive ratio in {ratios}; cannot take geomean.")
    log_mean = sum(math.log(r) for r in ratios) / len(ratios)
    return Aggregate(
        geomean=math.exp(log_mean),
        minimum=min(ratios),
        maximum=max(ratios),
    )

def upload_to_bencher(
    bench_name: str,
    agg: Aggregate,
    bmf_path: Path,
    bencher_bin: str,
    project: str,
    token: str,
    extra_flags: list[str],
    repo_root: Path,
) -> None:
    """Write a single-datapoint BMF file and hand it off to `bencher run`."""
    bmf_doc = {
        bench_name: {
            "relative_execution_time": {
                "value": agg.geomean,
                "lower_value": agg.minimum,
                "upper_value": agg.maximum,
            }
        }
    }
    bmf_path.write_text(json.dumps(bmf_doc, indent=2))
    print("BMF payload:")
    print(bmf_path.read_text())

    cmd = [
        bencher_bin, "run",
        "--project", project,
        "--token", token,
        "--adapter", "json",
        "--file", str(bmf_path),
        *extra_flags,
    ]
    run(cmd, cwd=repo_root)


def process_config(
    config_path: Path,
    scratch: Path,
    bencher_bin: str,
    project: str,
    token: str,
    extra_flags: list[str],
    repo_root: Path,
) -> None:
    cfg = json.loads(config_path.read_text())
    crate = cfg.get("name")
    version = cfg.get("version")
    excluded_tests = set(cfg.get("exclude") or [])
    if not crate or not version:
        sys.exit(f"Error: {config_path} missing 'name' or 'version'.\n---\n{cfg}\n")

    bench_name = f"{crate}@{version} (nop)"
    print(f"Running: {bench_name}")
    if excluded_tests:
        print(f"Excluding:")
        for test_name in excluded_tests:
            print(f"- {test_name}\n---")

    crate_scratch = scratch / bench_name
    crate_scratch.mkdir(parents=True, exist_ok=True)

    src_dir = download_crate(crate, version, crate_scratch)

    native_built = compile_test_binary(NATIVE_CARGO, "native", cwd=src_dir)
    native_bin = crate_scratch / "native_test_bin"
    shutil.copy2(native_built, native_bin)
    native_bin.chmod(0o755)

    try:
        run(["cargo", "clean", "--quiet"], cwd=src_dir)
    except subprocess.CalledProcessError:
        pass

    instr_built = compile_test_binary(INSTR_CARGO, "instrumented (nop)", cwd=src_dir)
    instr_bin = crate_scratch / "instr_test_bin"
    shutil.copy2(instr_built, instr_bin)
    instr_bin.chmod(0o755)

    all_tests = list_tests(native_bin)
    if not all_tests:
        sys.exit(f"Error: no tests discovered for {bench_name}.")

    tests = [t for t in all_tests if t not in excluded_tests]
    if not tests:
        sys.exit(f"Error: every discovered test was excluded for {bench_name}.")

    ratios: list[float] = []
    for t in tests:
        print(f"  -> {t}")
        safe = "".join(c if c.isalnum() or c == "_" else "_" for c in t)
        n_json = crate_scratch / f"native-{safe}.json"
        i_json = crate_scratch / f"instr-{safe}.json"

        # --shell=none means the command string is split into argv, so
        # spaces are the only separator. Rust test names can't contain
        # spaces, so this is safe.
        n_mean = hyperfine_mean(n_json, f"{native_bin} --exact {t} --nocapture")
        i_mean = hyperfine_mean(i_json, f"{instr_bin} --exact {t} --nocapture")

        assert(n_mean > 0 and i_mean > 0)
        ratio = i_mean / n_mean

        print(f" - native={n_mean}s  inst={i_mean}s  ratio={ratio}")
        ratios.append(ratio)
        
    agg = aggregate_ratios(ratios)
    print(
        f"Geomean ratio for {bench_name}: {agg.geomean}  "
        f"(min={agg.minimum} max={agg.maximum})"
    )
    safe_name = "".join(
        c if c.isalnum() or c in "_.@-" else "_" for c in bench_name
    )
    bmf_path = crate_scratch / f"{safe_name}.bmf.json"
    upload_to_bencher(
       bench_name, agg, bmf_path,
        bencher_bin=bencher_bin,
        project=project,
        token=token,
        extra_flags=extra_flags,
        repo_root=repo_root,
    )

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark relative execution time and upload to bencher.",
        usage=(
            "%(prog)s <config_dir> <bencher_project> <bencher_token> "
            "<bencher_bin> [bencher_flags...]"
        ),
    )
    parser.add_argument("config_dir", type=Path)
    parser.add_argument("bencher_project")
    parser.add_argument("bencher_token")
    parser.add_argument("bencher_bin")
    parser.add_argument(
        "bencher_flags", nargs=argparse.REMAINDER,
        help="Extra flags forwarded to `bencher run`.",
    )
    
    args = parser.parse_args(argv)
    
    for tool in ["cargo", "hyperfine", args.bencher_bin]:
        require_tool(tool)
    if not args.config_dir.is_dir():
        sys.exit(f"Error: config dir '{args.config_dir}' does not exist.")
    configs = sorted(args.config_dir.glob("*.json"))

    if not configs:
        sys.exit(f"Error: no .json configs found in {args.config_dir}")
    repo_root = Path.cwd()

    with tempfile.TemporaryDirectory() as scratch_str:
        scratch = Path(scratch_str)
        for cfg in configs:
            process_config(
                cfg, scratch,
                bencher_bin=args.bencher_bin,
                project=args.bencher_project,
                token=args.bencher_token,
                extra_flags=args.bencher_flags,
                repo_root=repo_root,
            )
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))