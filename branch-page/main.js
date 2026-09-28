"use strict";
/* global Chart */

// One colour per side, the same on every chart. Blue/orange stays distinct
// under the common colour-vision deficiencies, and main is also dashed so the
// two lines never depend on colour alone.
const SIDES = [
    { key: "main", label: "main", color: "#1f77b4", dash: [6, 4] },
    { key: "branch", label: "branch", color: "#ff7f0e", dash: [] }
];

const MARKER_SIZE = 3;
const LINE_WIDTH = 2;
const LINE_ALPHA = 0.85;
const DEFAULT_MODE = "full";

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

function renderChart(parent, target, data, mode) {
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
    set.appendChild(el("p", "benchmark-subtitle",
        `${mode}: branch ${formatSeconds(totalBranch)}s vs. main ` +
        `${formatSeconds(totalMain)}s over ${data.crates.length} crate(s) ` +
        `(branch/main = ${formatRatio(totalBranch, totalMain)})`));

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

    const datasets = SIDES.map(s => ({
        label: s.label,
        data: data.crates.map(c => data[s.key][c]),
        borderColor: rgba(s.color, LINE_ALPHA),
        backgroundColor: rgba(s.color, LINE_ALPHA),
        pointBackgroundColor: rgba(s.color, LINE_ALPHA),
        borderDash: s.dash,
        borderWidth: LINE_WIDTH,
        pointRadius: MARKER_SIZE,
        pointHoverRadius: MARKER_SIZE + 2,
        pointHitRadius: 10,
        fill: false,
        lineTension: 0
    }));

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
                        return [
                            `branch/main: ${formatRatio(data.branch[c], data.main[c])}`,
                            t ? `${t.kept} of ${t.total} tests counted` : ""
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
        renderChart(main, target, report.targets[target][mode], mode);
    }
}

function statusClass(status) {
    return status === "success" ? "status-success"
        : status === "not run" ? "status-missing" : "status-failed";
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
        `Under ${mode}, ${rows.length} test(s) are left out of the totals above; ` +
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
            cell.textContent = row[side];
            cell.className = statusClass(row[side]);
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

    const select = document.getElementById("mode-select");
    for (const m of report.modes) {
        const opt = document.createElement("option");
        opt.value = m;
        opt.textContent = m;
        select.appendChild(opt);
    }
    select.value = report.modes.includes(DEFAULT_MODE) ? DEFAULT_MODE : report.modes[0];
    select.addEventListener("change", () => render(report, select.value));

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

    render(report, select.value);
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
