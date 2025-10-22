#!/usr/bin/env python3

import difflib
import os
import re
import subprocess
import sys
import argparse

CARGO_EXTRA_FLAGS = os.environ.get("CARGO_EXTRA_FLAGS", "").split()

def fail(msg):
    print(f"\nTEST FAIL: {msg}")
    sys.exit(1)

def cargo_bsan(cmd, quiet=True):
    args = ["cargo", "bsan", cmd] + CARGO_EXTRA_FLAGS
    if quiet:
        args += ["-q"]
    return args

def normalize_stdout(val):
    val = val.replace("src\\", "src/") # normalize paths across platforms
    val = re.sub("\\b\\d+\\.\\d+s\\b", "$TIME", val) # the time keeps changing, obviously
    return val

def check_output(actual, path, regex, name):
    if ARGS.bless:
        # Write the output only if bless is set
        open(path, mode='w').write(actual)
        return True

    expected = ""
    if path is not None:
        expected = open(path).read()

    if regex and re.match(expected, actual) is not None:
        return True
    if expected == actual:
        return True
    print(f"{name} output did not match reference in {path}!")
    print(f"--- BEGIN diff {name} ---")
    for text in difflib.unified_diff(expected.split("\n"), actual.split("\n")):
        print(text)
    print(f"--- END diff {name} ---")
    return False

def test(name, cmd, stdout_ref=None, stderr_ref=None, stdin=b'',
         stdout_regex=False, stderr_regex=False, env=None):
    if env is None:
        env = {}
    print(f"Testing {name}...")
    ## Call `cargo bsan`, capture all output
    (stdout, stderr, returncode) = execute(cmd, env)
    stdout_matches = check_output(stdout, stdout_ref, stdout_regex, "stdout")
    stderr_matches = check_output(stderr, stderr_ref, stderr_regex, "stderr")
    if returncode == 0 and stdout_matches and stderr_matches:
        # All good!
        return
    fail(f"exit code was {returncode}")

def execute(cmd, env=None):
    p_env = os.environ.copy()
    if env is not None:
        p_env.update(env)
    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=p_env,
    )
    (stdout, stderr) = p.communicate()
    stdout = stdout.decode("UTF-8")
    stderr = stderr.decode("UTF-8")
    return (stdout, stderr, p.returncode)

def test_no_rebuild(name, cmd, env=None):
    if env is None:
        env = {}
    print(f"Testing {name}...")
    (stdout, stderr, returncode) = execute(cmd, env)
    if returncode != 0:
        fail("rebuild failed")
    # Also check for 'Running' as a sanity check.
    if stderr.count("Compiling") > 0 or stderr.count("Running") == 0:
        print("--- BEGIN stdout ---")
        print(stdout, end="")
        print("--- END stdout ---")
        print("--- BEGIN stderr ---")
        print(stderr, end="")
        print("--- END stderr ---")
        fail("Something was being rebuilt when it should not be (or we got no output)")

def test_cargo_bsan_setup():
    if "BSAN_SYSROOT" not in os.environ:
        fail("Missing environment variable `BSAN_SYSROOT`.")
    intended_sysroot = os.environ["BSAN_SYSROOT"]

    test("`cargo bsan setup`", cargo_bsan("setup"))

    sysroot_cmd = cargo_bsan("setup") + ["--print-sysroot"]
    (stdout, stderr, returncode) = execute(sysroot_cmd)

    if returncode != 0:
        print("--- BEGIN stderr ---")
        print(stderr, end="")
        print("--- END stderr ---")
        fail("Failed to query sysroot directory.")

    sysroot_dir = stdout.strip()
    if not os.path.exists(sysroot_dir):
        fail("The sysroot dir `{sysroot_dir}` does not exist.")
    elif sysroot_dir != os.environ["BSAN_SYSROOT"]:
        fail(f"""The sysroot dir `{sysroot_dir}` does not match the
              value provided by `BSAN_SYSROOT`: `{intended_sysroot}`.""")

    test("`cargo bsan setup` (no rebuild)",
        cargo_bsan("setup", quiet=False),
        stderr_ref="setup.again.stderr.ref",
        stderr_regex=True
    )

def test_cargo_bsan_run():
    test("`cargo bsan run`",
        cargo_bsan("run"),
        stdout_ref="run.stdout.ref",
    )
    test_no_rebuild("`cargo bsan run` (no rebuild)",
        cargo_bsan("run", quiet=False),
    )

args_parser = argparse.ArgumentParser(description='`cargo bsan` testing')
args_parser.add_argument('--bless', help='bless the reference files', action='store_true')

ARGS = args_parser.parse_args()

os.chdir(os.path.dirname(os.path.realpath(__file__)))

test_cargo_bsan_setup()
test_cargo_bsan_run()

print("\nTEST SUCCESSFUL!")
sys.exit(0)
