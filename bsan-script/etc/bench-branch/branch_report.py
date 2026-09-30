#!/usr/bin/env python3
"""
Usage: branch_report.py <output.json> --branch-csv CSV [CSV ...]
                        --main-csv CSV [CSV ...]

Build the dataset behind a per-branch benchmark page from the raw per-test CSVs
`bench.py` writes (target, crate_name, version, test_name, mode, status,
mean_exec_time_seconds): one set measured on the branch, one on `main`.

The page answers one question: did this branch make BorrowSanitizer faster or
slower than `main`? So for each target and each mode it reports per-crate wall
time in seconds for both sides, over a workload both sides completed.

Common tests
    For a given target and mode, a crate's seconds are the SUM of its tests'
    means, restricted to tests that succeeded on BOTH `main` and the branch.
    Without the restriction each side covers whatever it happened to complete,
    so a side that lost tests is credited with less work and looks faster for
    it. Statuses come from the CSV, which records a failure per (test, mode)
    rather than aborting the run.

No calibration
    bench.py measures a test binary directly with an `--exact` filter, so there
    is no per-invocation cargo constant to subtract; every total is a plain sum
    of means.

Everything left out of the common set is reported in `dropped` with its status
on each side, and for each failing side the error bench.py found in its output
and a link to the CI log holding that output, so the page can show which tests
changed behaviour, and why, rather than only how many.

When a CSV is given more than once for the same (target, crate, test, mode),
the last row wins, so fresh `main` results listed after a cached copy replace it.

Earlier runs
    Rerunning a branch adds a line rather than replacing one, so a new commit
    can be compared with the ones before it, and a rerun of the same commit
    shows how far the numbers move between runs. `--previous` is the report
    the branch's page last published; its most recent `--max-runs` runs are
    kept, with their per-test times under `raw`, and every line is summed
    over the tests that succeeded on `main` and in every kept run that
    measured the crate. `dropped` compares only the newest run with `main`.
"""

import argparse
import csv
import hashlib
import json
import math
import sys
import time
from pathlib import Path

# Marks the PR comment this report writes, so a later run edits it in place.
COMMENT_MARKER = "<!-- bsan-branch-benchmarks -->"

# What the baseline is called in text meant to be read: the page's reasons and
# the PR comment. The data always calls that side "main", which it usually is;
# set by --baseline-name.
BASELINE = "main"

# The test name a whole-crate entry is listed under.
WHOLE_CRATE = "(whole crate)"

# A test counts toward a crate's total only with this status on both sides.
COMPARABLE = "success"

REQUIRED = {"target", "crate_name", "version", "test_name", "mode",
            "status", "mean_exec_time_seconds"}


def rounded(v):
    """Six significant figures: far finer than run-to-run noise, and it keeps
    the stored history small."""
    return float(f"{v:.6g}")


def successes(rows, tg, m, crates):
    """{crate: {test: seconds}} for the tests that succeeded with a timing."""
    out = {}
    for (rtg, rm, c, t), r in rows.items():
        if rtg == tg and rm == m and t and c in crates and r["status"] == COMPARABLE:
            v = timing(r)
            if v is not None:
                out.setdefault(c, {})[t] = rounded(v)
    return out


def dataset_id(crates_json):
    """A fingerprint of the benchmarked workload: every crate, version and
    excluded test in crates.json, whatever its order or formatting. Runs are
    only drawn together while it is unchanged, since otherwise their lines sum
    over different tests."""
    crates = sorted((c["name"], c["version"], sorted(c.get("exclude") or []))
                    for c in json.loads(crates_json.read_text()))
    return hashlib.sha256(json.dumps(crates).encode()).hexdigest()[:16]


def load_previous(path):
    """The runs and per-test times of the report a branch last published.

    A report written before runs were kept has neither, so history starts over.
    """
    if path is None or not path.is_file():
        return [], {}
    try:
        prev = json.loads(path.read_text())
    except ValueError:
        return [], {}
    runs, raw = prev.get("runs"), prev.get("raw")
    if not isinstance(runs, list) or not isinstance(raw, dict):
        return [], {}
    return [r for r in runs if r.get("key") in raw], raw


def add_history(data, main_ok, runs, raw, tg, m):
    """Replace one (target, mode)'s lines with one per kept run.

    `main_ok` is {crate: {test: seconds}} on `main`. Each crate's point on
    every line, main's included, is the sum over the tests that succeeded on
    `main` and in every kept run that measured that crate; a run that did not
    measure it has no point there.
    """
    per_run = {r["key"]: raw[r["key"]].get(tg, {}).get(m, {}) for r in runs}
    latest = runs[-1]["key"]
    history = {r["key"]: {} for r in runs}
    main_s, tests = {}, {}
    for crate, main_tests in main_ok.items():
        measured = [k for k, by_crate in per_run.items() if by_crate.get(crate)]
        if latest not in measured:
            continue
        common = set(main_tests)
        for k in measured:
            common &= set(per_run[k][crate])
        if not common:
            continue
        main_s[crate] = sum(main_tests[t] for t in common)
        for k in measured:
            history[k][crate] = sum(per_run[k][crate][t] for t in common)
        # `total` counts the tests the newest run and main were compared over.
        total = data["tests"].get(crate, {}).get("total", len(common))
        tests[crate] = {"kept": len(common), "total": total, "runs": len(measured)}

    data["crates"] = sorted(main_s, key=lambda c: (main_s[c], c))
    data["main"] = main_s
    data["branch"] = history[latest]
    data["history"] = history
    data["tests"] = tests


def mean_geomean(values):
    """The mean and geometric mean of positive numbers."""
    return (sum(values) / len(values),
            math.exp(sum(math.log(v) for v in values) / len(values)))


def write_summary(path, report, page_url):
    """Write the PR comment: a link to the page, and per target the mean and
    geomean of the per-crate totals on `main` and on the newest run.

    Both rows are over the crates both have a point for, so they average the
    same workload; the page's table does the same over every line it draws.
    """
    branch = report["branch"] or "branch"
    commit = (report["commit"] or "")[:8]
    main_commit = f"`{report['mainCommit'][:8]}`" if report["mainCommit"] else "unknown"
    mode = "full" if "full" in report["modes"] else (report["modes"] or ["?"])[0]
    out = [COMMENT_MARKER,
           f"### Benchmarks for `{branch}`",
           "",
           f"[Dashboard]({page_url}) · [workflow run]({report['runUrl']}) · "
           f"`{commit}` against {BASELINE} {main_commit}, under `{mode}`.",
           ""]
    for tg in sorted(report["targets"]):
        data = report["targets"][tg].get(mode)
        out.append(f"**{tg}**")
        out.append("")
        common = [c for c in (data or {}).get("crates", [])
                  if data["main"].get(c, 0) > 0 and data["branch"].get(c, 0) > 0]
        if not common:
            out += [f"No crate has a test that succeeded on both {BASELINE} and the branch.", ""]
            continue
        out += ["| Config | Mean (s) | Geomean (s) |",
                "| ------ | -------- | ----------- |"]
        for name, side in ((BASELINE, "main"), (branch, "branch")):
            mean, geo = mean_geomean([data[side][c] for c in common])
            out.append(f"| {name} | {mean:.3f} | {geo:.3f} |")
        changed = sum(1 for d in data["dropped"] if d["reason"] == "changed")
        note = f"Over {len(common)} crate(s)."
        if changed:
            note += f" {changed} test(s) have a different result than on {BASELINE}; see the dashboard."
        out += ["", note, ""]
    Path(path).write_text("\n".join(out))


def read_rows(paths):
    """Load CSVs into {(target, mode, crate, test): row}; the last row wins.

    A row with no test name records that a whole crate could not be measured
    under that mode (it failed to download, build, or list its tests), and is
    kept under the test name "".
    """
    rows = {}
    for path in paths:
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            missing = REQUIRED - set(reader.fieldnames or [])
            if missing:
                sys.exit(f"Error: {path} is missing column(s): "
                         f"{', '.join(sorted(missing))}")
            for row in reader:
                crate = f"{row['crate_name']}@{row['version']}"
                rows[(row["target"], row["mode"], crate, row["test_name"] or "")] = row
    return rows


def timing(row):
    try:
        v = float(row["mean_exec_time_seconds"])
    except (TypeError, ValueError):
        return None
    return v if v > 0 else None


def status(row):
    return row["status"] if row is not None else "not run"


def error(row):
    """The error bench.py extracted from a failing test, or None.

    Results published before bench.py recorded errors have no error columns.
    """
    if row is None or row.get("status") == COMPARABLE:
        return None
    fields = {"message": row.get("error_message") or "",
              "location": row.get("error_location") or "",
              "url": row.get("log_url") or "",
              "detail": row.get("error_detail") or ""}
    return fields if any(fields.values()) else None


def summary(tests):
    """One status for a side that did measure a crate's tests."""
    if all(r["status"] == COMPARABLE for r in tests.values()):
        return COMPARABLE
    return "some tests failed"


def compare_crate(crate, main_tests, branch_tests, seconds, counts, dropped):
    """Compare one crate: {test: row} on each side, "" for a whole-crate row."""
    main_whole = main_tests.pop("", None)
    branch_whole = branch_tests.pop("", None)

    # When either side has nothing per test, whether because the crate did not
    # build there or because its job never reported, compare the crate as one
    # entry rather than listing every test the other side ran as "not run".
    if main_whole or branch_whole or not main_tests or not branch_tests:
        def side(whole, tests):
            if whole:
                return whole["status"], error(whole)
            if tests:
                return summary(tests), None
            return "not run", None
        (sm, em), (sb, eb) = side(main_whole, main_tests), side(branch_whole, branch_tests)
        if sm == "not run" or sb == "not run":
            missing = [n for n, st in ((BASELINE, sm), ("branch", sb)) if st == "not run"]
            reason = f"no results on {' or '.join(missing)}"
        elif sm != sb:
            reason = "changed"
        else:
            reason = f"{sm} on both"
        dropped.append({"crate": crate, "test": WHOLE_CRATE, "reason": reason,
                        "main": sm, "branch": sb, "errors": {"main": em, "branch": eb}})
        return

    for test in sorted(set(main_tests) | set(branch_tests)):
        m, b = main_tests.get(test), branch_tests.get(test)
        counts.setdefault(crate, {"kept": 0, "total": 0})
        counts[crate]["total"] += 1
        sm, sb = status(m), status(b)

        if sm == sb == COMPARABLE:
            tm, tb = timing(m), timing(b)
            if tm is not None and tb is not None:
                seconds["main"][crate] = seconds["main"].get(crate, 0.0) + tm
                seconds["branch"][crate] = seconds["branch"].get(crate, 0.0) + tb
                counts[crate]["kept"] += 1
                continue
            reason = "success without a timing"
        elif sm == "not run" or sb == "not run":
            reason = f"not run on {BASELINE if sm == 'not run' else 'branch'}"
        elif sm != sb:
            reason = "changed"
        else:
            reason = f"{sm} on both"
        dropped.append({"crate": crate, "test": test, "reason": reason,
                        "main": sm, "branch": sb,
                        "errors": {"main": error(m), "branch": error(b)}})


def build_mode(main_rows, branch_rows, crates):
    """Compare one (target, mode): {(crate, test): row} on each side, over
    `crates`."""
    seconds = {"main": {}, "branch": {}}
    counts = {}
    dropped = []

    for crate in sorted(crates):
        compare_crate(crate,
                      {t: r for (c, t), r in main_rows.items() if c == crate},
                      {t: r for (c, t), r in branch_rows.items() if c == crate},
                      seconds, counts, dropped)

    # A crate with no comparable test has no point on either line.
    kept = sorted((c for c in counts if counts[c]["kept"] > 0),
                  key=lambda c: (seconds["main"][c], c))

    # A test whose result changed between main and the branch is a real finding;
    # the rest is usually a test that is simply unsupported everywhere.
    dropped.sort(key=lambda d: (d["reason"] != "changed", d["crate"], d["test"]))

    return {
        "crates": kept,
        "main": {c: seconds["main"][c] for c in kept},
        "branch": {c: seconds["branch"][c] for c in kept},
        "tests": {c: counts[c] for c in kept},
        "dropped": dropped,
    }


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("output", type=Path)
    ap.add_argument("--branch-csv", type=Path, nargs="+", required=True)
    ap.add_argument("--main-csv", type=Path, nargs="*", default=[])
    ap.add_argument("--branch", default="")
    ap.add_argument("--commit", default="")
    ap.add_argument("--main-commit", default="",
                    help="The commit the baseline was measured at.")
    ap.add_argument("--crates", type=Path,
                    help="The crates.json the run benchmarked; crates in it with no "
                         "results on a side are listed as such.")
    ap.add_argument("--targets", type=Path,
                    help="A JSON list of {\"target\": ...} the run benchmarked.")
    ap.add_argument("--previous", type=Path,
                    help="The data.json the branch's page last published, whose runs "
                         "are kept as earlier lines.")
    ap.add_argument("--max-runs", type=int, default=5,
                    help="How many runs, this one included, to keep (default: 5).")
    ap.add_argument("--run-id", default="",
                    help="Identifies this run; a report for the same run (a re-run "
                         "attempt) replaces the earlier one instead of adding to it.")
    ap.add_argument("--baseline-name", default="main",
                    help="What to call the side given by --main-csv when showing it, "
                         "if it is not `main` (default: main).")
    ap.add_argument("--summary-md", type=Path,
                    help="Also write a Markdown summary, for a PR comment, here.")
    ap.add_argument("--page-url", default="",
                    help="The branch's page, which the summary links to.")
    ap.add_argument("--repo-url", default="")
    ap.add_argument("--run-url", default="")
    args = ap.parse_args(argv)
    global BASELINE
    BASELINE = args.baseline_name or "main"

    branch_rows = read_rows(args.branch_csv)
    main_rows = read_rows(args.main_csv)
    if not branch_rows:
        sys.exit("Error: no rows found in the branch CSVs.")

    # What should have been measured, so a crate or a whole target that never
    # reported, because its job failed, is listed rather than silently missing.
    expected_targets = []
    if args.targets:
        expected_targets = [t["target"] for t in json.loads(args.targets.read_text())]
    expected_crates = None
    if args.crates:
        expected_crates = {f"{c['name']}@{c['version']}"
                           for c in json.loads(args.crates.read_text())}

    targets = sorted(set(expected_targets) | {tg for tg, _, _, _ in branch_rows})
    # The modes this branch is compared under are the ones it measured.
    modes = sorted({m for _, m, _, _ in branch_rows})
    main_keys = {(tg, m) for tg, m, _, _ in main_rows}
    for tg in targets:
        for m in modes:
            if (tg, m) not in main_keys:
                print(f"warning: {m} on {tg} has no results on {BASELINE}", file=sys.stderr)

    generated = int(time.time() * 1000)
    dataset = dataset_id(args.crates) if args.crates else None
    prev_runs, prev_raw = load_previous(args.previous)
    # A run measured over a different crate list is not comparable; the chart
    # starts over when the list changes.
    comparable = [r for r in prev_runs if r.get("dataset") == dataset]
    if len(comparable) < len(prev_runs):
        print(f"{len(prev_runs) - len(comparable)} earlier run(s) dropped: "
              f"measured over a different crate list", file=sys.stderr)
    # `seq` counts the branch's runs, so each keeps the colour it was given on
    # the page as older ones drop off.
    seq = max((r.get("seq", -1) for r in comparable), default=-1) + 1
    run = {"key": args.run_id or str(generated), "seq": seq, "dataset": dataset,
           "commit": args.commit, "generated": generated, "runUrl": args.run_url,
           "mainCommit": args.main_commit}
    runs = ([r for r in comparable if r["key"] != run["key"]] + [run])[-max(1, args.max_runs):]
    raw = {r["key"]: prev_raw[r["key"]] for r in runs[:-1]}
    raw[run["key"]] = {}

    report = {
        "generated": generated,
        "branch": args.branch,
        "commit": args.commit,
        "mainCommit": args.main_commit,
        "baseline": BASELINE,
        "repoUrl": args.repo_url,
        "runUrl": args.run_url,
        "modes": modes,
        "runs": runs,
        "targets": {},
        "raw": raw,
    }
    for tg in targets:
        report["targets"][tg] = {}
        for m in modes:
            side = lambda rows: {(c, t): r for (rtg, rm, c, t), r in rows.items()
                                 if rtg == tg and rm == m}
            branch_side = side(branch_rows)
            # `main`'s published results can cover crates, or crate versions,
            # that this branch no longer benchmarks; those are not a comparison.
            crates = (expected_crates if expected_crates is not None
                      else {c for c, _ in branch_side})
            main_side = {k: r for k, r in side(main_rows).items() if k[0] in crates}
            data = build_mode(main_side, branch_side, crates)
            raw[run["key"]].setdefault(tg, {})[m] = successes(branch_rows, tg, m, crates)
            add_history(data, successes(main_rows, tg, m, crates), runs, raw, tg, m)
            report["targets"][tg][m] = data

    # Compact: with many crates and runs, indentation is most of the file.
    args.output.write_text(json.dumps(report, separators=(",", ":")))
    if args.summary_md:
        write_summary(args.summary_md, report, args.page_url)

    for tg, by_mode in report["targets"].items():
        for m, data in by_mode.items():
            kept = sum(v["kept"] for v in data["tests"].values())
            changed = sum(1 for d in data["dropped"] if d["reason"] == "changed")
            tm = sum(data["main"][c] for c in data["crates"])
            tb = sum(data["branch"][c] for c in data["crates"])
            ratio = f", branch/main = {tb / tm:.3f}x" if tm else ""
            print(f"{tg} {m}: {len(data['crates'])} crate(s), {kept} common test(s), "
                  f"{len(data['dropped'])} dropped ({changed} changed){ratio}")
    print(f"{len(runs)} run(s) kept: " + ", ".join(r["commit"][:8] or r["key"] for r in runs))
    print(f"Report written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
