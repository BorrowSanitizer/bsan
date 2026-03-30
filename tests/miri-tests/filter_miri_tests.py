import concurrent.futures
import os
import shutil
import subprocess
from pathlib import Path
import tempfile
import csv

# Miri's tests are executed in a variety of configurations.
# We only care about the subset that are useful under a configuration
# that matches BorrowSanitizer's capabilities. The pass/fail outcome under 
# this configuration may be different than the outcome under Miri's custom 
# configuration for each test, so we need to reorganize the tests into new 
# "pass/fail" directories.
SUITES = [
    (
        # the directory that contains the test suite
        Path("./tests/pass"),
        # the destination for failing tests
        Path("./miri-tests/fail"),
        # the destination for passing tests
        Path("./miri-tests/pass"),
        # whether dependencies are required
        False,
    ),
    (
        Path("./tests/fail"),
        Path("./miri-tests/fail"),
        Path("./miri-tests/pass"),
        False,
    ),
]

# This configuration matches BorrowSanitizer and
# also disables features that would interfere with
# data collection here.
MIRIFLAGS = [
    "-Zmiri-tree-borrows",
    # we only want to see Miri's error messages
    "-Zmiri-mute-stdout-stderr",
    # we want to allow `inttoptr` casts
    "-Zmiri-permissive-provenance",
    # we want to ensure that all alignment errors are caught and
    # excluded
    "-Zmiri-symbolic-alignment-check",
]

# For now, BorrowSanitizer only supports these two targets. We
# will exclude tests that do not have the same outcome in each
# target.
TARGETS = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]

# Error messages for tests that have undefined behavior start
# with this prefix
UB_TEXT = "error: Undefined Behavior"

# Miri's test suites are within this directory.
SUITE_DIR = "tests"

# Errors for aliasing violations contain the name of the model
# in their help text
def is_aliasing_ub(txt: str):
    return "Tree Borrows" in txt

# Access out-of-bounds and use-after-free errors have the prefix
# "memory access failed". However, we want to exclude errors for
# dangling pointers that do not have provenance
def is_baseline_ub(txt: str):
    return "memory access failed" in txt


# all forms of UB have this prefix
def had_ub(txt: str):
    return UB_TEXT in txt

# Certain tests have features that make them incompatible
# with BorrowSanitizer, even under our configuration.
TO_EXCLUDE = [
    # We cannot control or otherwise avoid nondeterminism
    "-Zmiri-deterministic-concurrency",
    "-Zmiri-compare-exchange-weak-failure-rate",
    "-Zmiri-deterministic-floats",
    "-Zmiri-address-reuse-cross-thread-rate",
    "-Zmiri-address-reuse-rate",
    # We only want to include target-agnostic behavior
    "//@only-target:",
    # We use a different CFG directive
    "cfg!(miri)",
    "mod utils"
]

def prepare_file(exit_code: int, file_path: Path) -> str:
    lines = file_path.read_text().splitlines()
    output_lines = [f"//@run:{exit_code}"]
    for line in lines:
        if "//~" in line:
            output_lines.append(line.replace("//~", "//miri: ~"))
        elif line.lstrip().startswith("//@"):
            output_lines.append("//miri: @" + line[3:])
        else:
            output_lines.append(line)

    return "\n".join(output_lines) + "\n"

def copy_prepare_file(exit_code: int, src_path: Path, dest_dir: Path):
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / src_path.name
    prepared_content = prepare_file(exit_code, src_path)
    with dest_path.open("w") as f:
        f.write(prepared_content)
    return dest_path

def is_supported(test_file: Path) -> bool:
    text = test_file.read_text()
    for excl in TO_EXCLUDE:
        if excl in text:
            return False
    return True


def run_single_test(test_file: Path, mcli: list, env: dict):
    results = {}   
    supported = is_supported(test_file)
    results["supported"] = supported
    if(supported):
        for target in TARGETS:
            cmd = ["./miri", "run"] + mcli + ["--target", target, str(test_file)]
            proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
            results[target] = {
                "miri_exit_code": proc.returncode,
                "stdout_stderr": proc.stdout + proc.stderr,
            }
    return test_file, results

def process_results(test_file: Path, results, fail_path: Path, pass_path: Path):
    row = {
        "src_file": str(test_file),
        "category": "Excluded",
        "dst_file": ""
    }
    if not results["supported"]:
        return row
    first_res = results[TARGETS[0]]
    consistent = all(
        results[t]["stdout_stderr"] == first_res["stdout_stderr"]
        and results[t]["miri_exit_code"] == first_res["miri_exit_code"]
        for t in TARGETS[1:]
    )
    if not consistent:
        row["category"] = "Target Dependent"
        return row
    
    subdir_path = test_file.relative_to(SUITE_DIR)
    assert len(subdir_path.parts) > 1
    subdir_path = subdir_path.relative_to(subdir_path.parts[0])

    output = first_res["stdout_stderr"]
    exit_code = first_res["miri_exit_code"]

    if had_ub(output):
        is_aliasing = is_aliasing_ub(output)
        is_baseline = is_baseline_ub(output)
        if is_aliasing:
            row["category"] = "Aliasing UB"
        elif is_baseline:
            row["category"] = "Baseline UB"
        else:
            row["category"] = "Other UB"
            return row
        if is_aliasing or is_baseline:
            print(f"UB: {test_file.name}")
            category = fail_path / ("Aliasing UB" if is_aliasing else "Baseline UB")
            subcategory = category / subdir_path
            dest_dir = subcategory.parent
            row["dst_file"] = copy_prepare_file(exit_code, test_file, dest_dir)
    elif exit_code == 0:
        subcategory = pass_path / subdir_path
        dest_dir = subcategory.parent
        row["dst_file"] = copy_prepare_file(exit_code, test_file, dest_dir)
        row["category"] = "Exit " + str(exit_code)
    return row

def run_suite(target_path: Path, fail_path: Path, pass_path: Path, needs_dep: bool):
    mcli = ["--quiet"]
    if not needs_dep:
        mcli.append("--dep")

    env = os.environ.copy()
    env["MIRIFLAGS"] = " ".join(MIRIFLAGS)

    files = list(target_path.rglob("*.rs"))

    # a CSV row for every test
    suite_results = []

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_file = {
            executor.submit(run_single_test, f, mcli, env): f for f in files
        }
        for future in concurrent.futures.as_completed(future_to_file):
            test_file, results = future.result()
            row_data = process_results(test_file, results, fail_path, pass_path)
            print(f"{row_data['category']}: {row_data['src_file']}")
            suite_results.append(row_data)
    return suite_results

if __name__ == "__main__":
    output_dir = Path("./miri-tests")
    if output_dir.exists():
        shutil.rmtree(output_dir)
    for sub_dir in ["fail", "pass"]:
        (output_dir / sub_dir).mkdir(parents=True, exist_ok=True)
    for sub_dir in ["aliasing", "baseline"]:
        for fail_dir in ["fail"]:
            (output_dir / fail_dir / sub_dir).mkdir(parents=True, exist_ok=True)

    all_test_results = []
    for src, fail, pss, dep in SUITES:
        print(f"\n--- Running Suite: {src} ---")
        suite_results = run_suite(src, fail, pss, dep)
        all_test_results.extend(suite_results)
    csv_file_path = (output_dir / "results.csv")
    if all_test_results:
        headers = list(all_test_results[0].keys())
        with open(csv_file_path, mode="w") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=headers)
            writer.writeheader()
            writer.writerows(all_test_results)