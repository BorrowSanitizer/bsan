#!/usr/bin/env python3
"""
Usage: bench_plan.py <crates.json> <targets.json> --sha SHA --main-sha SHA
                     [--main-cache raw.csv]

Print the plan for bench-branch.yml as JSON:

  {"builds": [...], "branch": {"include": [...]}, "main": {"include": [...]}}

`builds` is the matrix of images to build: one per target for each side that
has anything to measure, each with BorrowSanitizer installed from that side's
commit (see bench.Dockerfile). `branch` and `main` are the matrices of the
per-crate bench jobs that run in those images, one job per crate and target.
They are separate matrices because GitHub caps each at 256 jobs; the plan
fails rather than exceed that.

Every crate is benchmarked on the branch (`--sha`), and on the baseline
(`--main-sha`, usually `main`) too when its published results do not already
cover it at that crate version. `--main-cache` is that published CSV, if
there is one.

Build entries carry: label, target, os, ref, image.
Bench entries carry: label, target, os, crate, image.
"""

import argparse
import csv
import json
import sys
from pathlib import Path

# GitHub's limit on the jobs one matrix can generate.
MAX_MATRIX = 256

IMAGE_REPO = "ghcr.io/borrowsanitizer/bsan"


def image(sha, target):
    """The tag of the bench image for `sha` on `target`."""
    return f"{IMAGE_REPO}:bench-{sha}-{target}"


def cached_pairs(path):
    """Return the (target, crate, version) triples that `path` has results for.

    A crate that failed to build on `main` counts: its failure is the result,
    and measuring it again would only fail again.
    """
    if path is None or not path.is_file():
        return set()
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        # A cache written before `status` existed cannot be compared against:
        # it has no way to say which of its tests failed.
        if "status" not in (reader.fieldnames or []):
            return set()
        return {(r["target"], r["crate_name"], r["version"]) for r in reader}


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("crates_json", type=Path)
    ap.add_argument("targets_json", type=Path)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--main-sha", required=True)
    ap.add_argument("--main-cache", type=Path)
    args = ap.parse_args(argv)

    crates = json.loads(args.crates_json.read_text())
    targets = json.loads(args.targets_json.read_text())
    have = cached_pairs(args.main_cache)
    refs = {"branch": args.sha, "main": args.main_sha}

    jobs = {"branch": [], "main": []}
    for t in targets:
        for c in crates:
            sides = ["branch"]
            if (t["target"], c["name"], c["version"]) not in have:
                sides.append("main")
            for label in sides:
                jobs[label].append({
                    "label": label,
                    "target": t["target"],
                    "os": t["os"],
                    "crate": c["name"],
                    "image": image(refs[label], t["target"]),
                })

    for label, entries in jobs.items():
        if len(entries) > MAX_MATRIX:
            sys.exit(f"Error: {len(entries)} {label} jobs ({len(crates)} crates x "
                     f"{len(targets)} targets) is more than the {MAX_MATRIX} one "
                     f"matrix can hold; benchmark fewer crates.")

    builds = []
    for label, entries in jobs.items():
        for t in targets:
            if any(e["target"] == t["target"] for e in entries):
                builds.append({"label": label, "target": t["target"], "os": t["os"],
                               "ref": refs[label], "image": image(refs[label], t["target"])})

    for label, entries in jobs.items():
        print(f"{label}: {len(entries)} job(s)", file=sys.stderr)
    for b in builds:
        print(f"build {b['image']}", file=sys.stderr)
    print(json.dumps({"builds": builds,
                      "branch": {"include": jobs["branch"]},
                      "main": {"include": jobs["main"]}}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
