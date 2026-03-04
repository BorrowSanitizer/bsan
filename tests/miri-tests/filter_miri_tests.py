import concurrent.futures
import os
import shutil
import subprocess
from pathlib import Path

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

TARGETS = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
UB_TEXT = "error: Undefined Behavior"
TMP_DIR = Path("./miri-tests/tmp")
SUITE_DIR = "tests"


# errors for aliasing violations contain the name of the model
# in their help text
def is_aliasing_ub(txt: str):
    return "Tree Borrows" in txt


# access out-of-bounds and use-after-free errors have the prefix
# "memory access failed". However, we want to exclude errors for
# dangling pointers that do not have provenance
def is_baseline_ub(txt: str):
    return "memory access failed" in txt and "(it has no provenance)" not in txt


# all forms of UB have this prefix
def had_ub(txt: str):
    return UB_TEXT in txt


TO_EXCLUDE = [
    # we do not have the same utility functions as Miri.
    "mod utils;",
    # we have nondeterministic concurrency.
    "-Zmiri-deterministic-concurrency",
]


def test_is_valid(txt: str):
    all(excl not in txt for excl in TO_EXCLUDE)


def prepare_file(exit_code: int, file_path: Path) -> str:
    lines = file_path.read_text().splitlines()
    text = f"//@run:{exit_code}\n"
    for line in lines:
        if "//~" in line:
            text += line.replace("//~", "//miri: ~") + "\n"
        elif line.lstrip().startswith("//@"):
            text += "//miri: @" + line[3:] + "\n"
        else:
            text += line + "\n"
    return text


def copy_prepare_file(exit_code, src_path, dest_dir):
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / src_path.name
    prepared_content = prepare_file(exit_code, src_path)
    with dest_path.open("w") as f:
        f.write(prepared_content)


def run_single_test(test_file: Path, mcli: list, env: dict):
    results = {}
    for target in TARGETS:
        cmd = ["./miri", "run"] + mcli + ["--target", target, str(test_file)]

        proc = subprocess.run(cmd, env=env, capture_output=True, text=True)

        results[target] = {
            "exit_code": proc.returncode,
            "stdout_stderr": proc.stdout + proc.stderr,
        }

    return test_file, results


def process_results(test_file, results, fail_path, pass_path):
    first_res = results[TARGETS[0]]
    consistent = all(
        results[t]["stdout_stderr"] == first_res["stdout_stderr"]
        and results[t]["exit_code"] == first_res["exit_code"]
        for t in TARGETS[1:]
    )
    subdir_path = test_file.relative_to(SUITE_DIR)
    assert len(subdir_path.parts) > 1
    subdir_path = subdir_path.relative_to(subdir_path.parts[0])

    output = first_res["stdout_stderr"]
    exit_code = first_res["exit_code"]

    if consistent:
        if had_ub(output):
            is_aliasing = is_aliasing_ub(output)
            is_baseline = is_baseline_ub(output)
            if is_aliasing or is_baseline:
                print(f"UB: {test_file.name}")
                category = fail_path / ("tree_borrows" if is_aliasing else "baseline")
                subcategory = category / subdir_path
                dest_dir = subcategory.parent
                copy_prepare_file(exit_code, test_file, dest_dir)
        elif exit_code == 0:
            print(f"Passed: {test_file.name}")
            subcategory = pass_path / subdir_path
            dest_dir = subcategory.parent
            copy_prepare_file(exit_code, test_file, dest_dir)


def run_suite(target_dir, fail_dest, pass_dest, needs_dep):
    target_path = Path(target_dir)
    fail_path = Path(fail_dest)
    pass_path = Path(pass_dest)

    mcli = ["--quiet"]
    if not needs_dep:
        mcli.append("--dep")

    env = os.environ.copy()
    env["MIRIFLAGS"] = " ".join(MIRIFLAGS)

    files = list(target_path.rglob("*.rs"))

    # Use ThreadPoolExecutor for I/O bound subprocess management
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_file = {
            executor.submit(run_single_test, f, mcli, env): f for f in files
        }

        for future in concurrent.futures.as_completed(future_to_file):
            test_file, results = future.result()
            process_results(test_file, results, fail_path, pass_path)


if __name__ == "__main__":
    base_dir = Path("./miri-tests")
    if base_dir.exists():
        shutil.rmtree(base_dir)
    for sub_dir in ["fail", "fail-dep", "pass", "pass-dep"]:
        (base_dir / sub_dir).mkdir(parents=True, exist_ok=True)
    for sub_dir in ["tree_borrows", "baseline"]:
        for fail_dir in ["fail", "fail-dep"]:
            (base_dir / fail_dir / sub_dir).mkdir(parents=True, exist_ok=True)
    TMP_DIR.mkdir(exist_ok=True)
    suites = [
        (
            "./tests/pass",
            "./miri-tests/fail",
            "./miri-tests/pass",
            False,
        ),
        (
            "./tests/fail",
            "./miri-tests/fail",
            "./miri-tests/pass",
            False,
        ),
    ]

    for src, fail, pss, dep in suites:
        print(f"\n--- Running Suite: {src} ---")
        run_suite(src, fail, pss, dep)

    # Final cleanup
    if TMP_DIR.exists():
        shutil.rmtree(TMP_DIR)
