"use strict";
/* global Chart */

// Main is blue and dashed; the branch's runs are orange, one line each, darker
// the newer the run, so the newest reads first. Blue/orange stays distinct
// under the common colour-vision deficiencies, and the dash means main never
// depends on colour alone. Each line is also named in the legend.
const MAIN_STYLE = { color: "#1f77b4", dash: [6, 4] };
// Oldest to newest; a page keeps at most as many runs as bench.yml's
// MAX_BRANCH_RUNS, and any beyond this share the lightest.
const RUN_COLORS = ["#fdae6b", "#fd8d3c", "#f16913", "#d94801", "#a63603"];

const MARKER_SIZE = 3;
const LINE_WIDTH = 2;
const LINE_ALPHA = 0.85;
// Branches are only benchmarked under `full`; see bench_plan.py.
const MODE = "full";

const DATE_FORMAT_OPTS = {
    day: "numeric", hour: "numeric", minute: "numeric", month: "long",
    timeZoneName: "short", weekday: "long", year: "numeric"
};

function rgba(hex, alpha) {
    const n = parseInt(hex.slice(1), 16);
    return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${alpha})`;
}

// Seconds span from milliseconds to minutes across configurations, so print
// each value at a fixed significance rather than a fixed number of decimals.
function formatSeconds(v) {
    if (!isFinite(v)) return "-";
    if (v >= 100) return v.toFixed(0);
    if (v >= 10) return v.toFixed(1);
    if (v >= 1) return v.toFixed(2);
    return v.toPrecision(3).replace(/0+$/, "").replace(/\.$/, "");
}

function formatRatio(branch, main) {
    if (!(main > 0) || !isFinite(branch)) return "-";
    return `${(branch / main).toFixed(3)}x`;
}

// A log axis in Chart.js 2 emits a tick for every 1..9 in each decade, which
// overprints. Keep the 1/2/5 ladder.
function logTick(value) {
    if (value <= 0) return "";
    const decade = Math.pow(10, Math.floor(Math.log10(value)));
    const mantissa = Math.round(value / decade);
    return [1, 2, 5].includes(mantissa) ? formatSeconds(value) : "";
}

function commitLink(report, sha) {
    if (report.repoUrl && sha) {
        const a = document.createElement("a");
        a.rel = "noopener";
        a.href = `${report.repoUrl}/commit/${sha}`;
        a.textContent = sha.slice(0, 8);
        return a;
    }
    return document.createTextNode((sha || "unknown").slice(0, 8));
}

function el(tag, className, text) {
    const e = document.createElement(tag);
    if (className) e.className = className;
    if (text !== undefined) e.textContent = text;
    return e;
}

let charts = [];

// The runs a report keeps, oldest first, each with its line's label. A report
// written before runs were kept has one, drawn from its `branch` numbers.
function runsOf(report) {
    const runs = (report.runs && report.runs.length) ? report.runs
        : [{ key: null, commit: report.commit, generated: report.generated }];
    const seen = {};
    return runs.map(r => {
        const sha = (r.commit || "").slice(0, 7) || "run";
        seen[sha] = (seen[sha] || 0) + 1;
        const when = r.generated ? new Date(r.generated).toLocaleDateString(
            "en-US", { month: "short", day: "numeric" }) : "";
        const label = `${sha}${seen[sha] > 1 ? ` (run ${seen[sha]})` : ""}` +
            (when ? ` · ${when}` : "");
        return { ...r, label };
    });
}

function runSeries(data, run) {
    return run.key === null ? data.branch : (data.history || {})[run.key] || {};
}

function lineStyle(color, dash, width) {
    return {
        borderColor: rgba(color, LINE_ALPHA),
        backgroundColor: rgba(color, LINE_ALPHA),
        pointBackgroundColor: rgba(color, LINE_ALPHA),
        borderDash: dash,
        borderWidth: width,
        pointRadius: MARKER_SIZE,
        pointHoverRadius: MARKER_SIZE + 2,
        pointHitRadius: 10,
        fill: false,
        lineTension: 0,
        spanGaps: false
    };
}

// Mean and geometric mean of each line's per-crate totals, over the crates
// every line has a point for, so that every row averages the same workload.
// The mean is dominated by the slowest crates; the geomean weighs every crate
// alike, so a change that helps small crates shows there.
function renderSummary(panel, datasets, crates) {
    const common = crates.map((_, i) => i)
        .filter(i => datasets.every(ds => ds.data[i] > 0));
    const table = el("table", "summary-table");
    const head = table.createTHead().insertRow();
    ["Config", "Mean (s)", "Geomean (s)"].forEach(h => {
        const th = document.createElement("th");
        th.textContent = h;
        head.appendChild(th);
    });
    const body = table.createTBody();
    for (const ds of datasets) {
        const values = common.map(i => ds.data[i]);
        const mean = values.reduce((a, v) => a + v, 0) / values.length;
        const geomean = Math.exp(values.reduce((a, v) => a + Math.log(v), 0) / values.length);
        const tr = body.insertRow();
        const name = tr.insertCell();
        const swatch = el("span", "summary-swatch");
        swatch.style.background = ds.borderColor;
        name.appendChild(swatch);
        name.appendChild(document.createTextNode(ds.label));
        tr.insertCell().textContent = values.length ? mean.toFixed(3) : "-";
        tr.insertCell().textContent = values.length ? geomean.toFixed(3) : "-";
    }
    panel.appendChild(table);
    if (common.length < crates.length) {
        panel.appendChild(el("p", "chart-meta",
            `Over the ${common.length} of ${crates.length} crates every line has a point for.`));
    }
}

function renderChart(parent, target, data, mode, runs) {
    const set = el("div", "benchmark-set");
    set.appendChild(el("h2", "benchmark-title", target));
    parent.appendChild(set);

    if (!data || !data.crates.length) {
        set.appendChild(el("p", "benchmark-subtitle",
            `No crate has a test that succeeded under ${mode} on both main and the branch.`));
        return;
    }

    const sum = side => data.crates.reduce((acc, c) => acc + data[side][c], 0);
    const totalMain = sum("main");
    const totalBranch = sum("branch");
    const side = runs.length > 1 ? "newest run" : "branch";
    set.appendChild(el("p", "benchmark-subtitle",
        `${mode}: ${side} ${formatSeconds(totalBranch)}s vs. main ` +
        `${formatSeconds(totalMain)}s over ${data.crates.length} crate(s) ` +
        `(${side}/main = ${formatRatio(totalBranch, totalMain)})`));

    const graphs = el("div", "benchmark-graphs");
    const panel = el("div", "chart-panel");
    const wrap = el("div", "chart-canvas-wrap branch-chart");
    const canvas = document.createElement("canvas");
    canvas.setAttribute("role", "img");
    canvas.setAttribute("aria-label",
        `Per-crate runtime on ${target} under ${mode}, main against the branch`);
    wrap.appendChild(canvas);
    panel.appendChild(wrap);
    graphs.appendChild(panel);
    set.appendChild(graphs);

    const offset = RUN_COLORS.length - runs.length;
    const datasets = [{
        label: "main",
        data: data.crates.map(c => data.main[c]),
        ...lineStyle(MAIN_STYLE.color, MAIN_STYLE.dash, LINE_WIDTH)
    }].concat(runs.map((run, i) => {
        const series = runSeries(data, run);
        const newest = i === runs.length - 1;
        return {
            label: newest && runs.length > 1 ? `${run.label} (newest)` : run.label,
            // A run that did not measure a crate has a gap there.
            data: data.crates.map(c => (c in series ? series[c] : null)),
            ...lineStyle(RUN_COLORS[Math.max(0, offset + i)], [],
                newest ? LINE_WIDTH : LINE_WIDTH - 0.5)
        };
    }));

    renderSummary(panel, datasets, data.crates);

    charts.push(new Chart(canvas.getContext("2d"), {
        type: "line",
        data: { labels: data.crates, datasets },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            legend: { position: "top", labels: { boxWidth: 12, usePointStyle: true } },
            tooltips: {
                mode: "index",
                intersect: false,
                callbacks: {
                    label: (item, d) =>
                        `${d.datasets[item.datasetIndex].label}: ${formatSeconds(item.yLabel)}s`,
                    afterBody: (items) => {
                        const c = data.crates[items[0].index];
                        const t = data.tests[c];
                        const counted = t ? `${t.kept} of ${t.total} tests counted` +
                            (runs.length > 1 ? " (those every run passed)" : "") : "";
                        return [
                            `${side}/main: ${formatRatio(data.branch[c], data.main[c])}`,
                            counted
                        ];
                    }
                }
            },
            scales: {
                xAxes: [{
                    scaleLabel: {
                        display: true,
                        labelString: "Crate  (Ordered by main, ascending)"
                    },
                    ticks: { autoSkip: false, maxRotation: 90, minRotation: 90 },
                    gridLines: { display: false }
                }],
                yAxes: [{
                    type: "logarithmic",
                    scaleLabel: {
                        display: true,
                        labelString: "Testbench Runtime, Seconds  (Log Scale)"
                    },
                    ticks: { callback: logTick },
                    gridLines: { color: "rgba(0,0,0,0.15)", borderDash: [1, 3] }
                }]
            }
        }
    }));
}

function renderCharts(report, mode) {
    charts.forEach(c => c.destroy());
    charts = [];
    const main = document.getElementById("main");
    main.innerHTML = "";
    for (const target of Object.keys(report.targets).sort()) {
        renderChart(main, target, report.targets[target][mode], mode, runsOf(report));
    }
}

function statusClass(status) {
    return status === "success" ? "status-success"
        : status === "not run" ? "status-missing" : "status-failed";
}

// Only link to CI logs, never to whatever else ends up in the data.
function safeUrl(url) {
    return /^https:\/\/github\.com\//.test(url || "") ? url : "";
}

// Where a failing test's error points and a link to the CI log its output was
// printed to (search it for "FAILED"), with the error text one click away.
function renderError(cell, err) {
    const url = safeUrl(err.url);
    if (err.location || url) {
        const line = el("div", "error-links");
        if (err.location) line.appendChild(el("span", "error-location", err.location));
        if (url) {
            const log = el("a", "error-log", "log");
            log.href = url;
            log.rel = "noopener";
            log.target = "_blank";
            log.title = "The CI job this test failed in; search its log for FAILED";
            line.appendChild(log);
        }
        cell.appendChild(line);
    }
    if (err.message || err.detail) {
        const details = el("details", "error-details");
        details.appendChild(el("summary", "", err.message || "output"));
        if (err.detail) details.appendChild(el("pre", "", err.detail));
        cell.appendChild(details);
    }
}

function renderDropped(report, mode) {
    const table = document.getElementById("dropped-table");
    const summary = document.getElementById("dropped-summary");
    table.innerHTML = "";

    const rows = [];
    for (const target of Object.keys(report.targets).sort()) {
        const data = report.targets[target][mode];
        for (const d of (data && data.dropped) || []) rows.push({ target, ...d });
    }
    const changed = rows.filter(d => d.reason === "changed").length;

    if (!rows.length) {
        summary.textContent =
            `Under ${mode}, every test succeeded on both main and the branch.`;
        summary.className = "chart-meta dropped-empty";
        return;
    }
    summary.className = "chart-meta";
    summary.textContent =
        `Under ${mode}, ${rows.length} test(s) are left out of the totals below; ` +
        `${changed} of them have a different result on the branch than on main.`;

    const head = table.insertRow();
    ["Target", "Crate", "Test", "Reason", "main", "branch"].forEach(h => {
        const th = document.createElement("th");
        th.textContent = h;
        head.appendChild(th);
    });

    for (const row of rows) {
        const tr = table.insertRow();
        tr.className = `reason-${row.reason === "changed" ? "changed" : "other"}`;
        tr.insertCell().textContent = row.target;
        tr.insertCell().textContent = row.crate;
        const test = tr.insertCell();
        test.textContent = row.test;
        test.className = "test-name";
        const reason = tr.insertCell();
        reason.textContent = row.reason;
        reason.className = "reason";
        for (const side of ["main", "branch"]) {
            const cell = tr.insertCell();
            cell.className = `status-cell ${statusClass(row[side])}`;
            cell.appendChild(el("div", "status", row[side]));
            const err = row.errors && row.errors[side];
            if (err) renderError(cell, err);
        }
    }
}

function render(report, mode) {
    renderCharts(report, mode);
    renderDropped(report, mode);
}

function init(report) {
    document.getElementById("branch-name").textContent = report.branch || "unknown";
    document.getElementById("commit-link").appendChild(commitLink(report, report.commit));
    document.getElementById("last-update").textContent =
        new Date(report.generated).toLocaleString("en-US", DATE_FORMAT_OPTS);

    const mainCommits = document.getElementById("main-commits");
    const shas = report.mainCommits || [];
    if (!shas.length) mainCommits.textContent = "unknown";
    shas.forEach((sha, i) => {
        if (i) mainCommits.appendChild(document.createTextNode(", "));
        mainCommits.appendChild(commitLink(report, sha));
    });

    if (report.runUrl) {
        document.getElementById("run-link").href = report.runUrl;
    } else {
        document.getElementById("run-sep").hidden = true;
    }

    const dl = document.getElementById("dl-button");
    dl.hidden = false;
    dl.onclick = () => {
        const blob = new Blob([JSON.stringify(report, null, 2)],
            { type: "application/json;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "data.json";
        a.click();
        URL.revokeObjectURL(url);
    };

    render(report, MODE);
}

fetch("data.json")
    .then(r => {
        if (!r.ok) throw new Error(`data.json: HTTP ${r.status}`);
        return r.json();
    })
    .then(init)
    .catch(err => {
        const main = document.getElementById("main");
        main.innerHTML = "";
        main.appendChild(el("div", "empty-state",
            `Could not load benchmark data (${err.message}).`));
    });
