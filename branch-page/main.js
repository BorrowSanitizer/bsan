"use strict";
/* global Chart */

// Matplotlib's tab10, in order, so a branch page and a locally produced
// plot_by_crate plot colour the same series the same way.
const TAB10 = [
    "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd",
    "#8c564b", "#e377c2", "#7f7f7f", "#bcbd22", "#17becf"
];

// plot_by_crate draws seconds with marker="o", ms=3, lw=0.8, alpha=0.8.
const MARKER_SIZE = 3;
const LINE_WIDTH = 1.2;
const LINE_ALPHA = 0.8;

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

// A log axis in Chart.js 2 emits a tick for every 1..9 in each decade, which
// overprints. Keep the 1/2/5 ladder, the convention matplotlib's LogLocator
// uses for a minor-tick subset.
function logTick(value) {
    if (value <= 0) return "";
    const decade = Math.pow(10, Math.floor(Math.log10(value)));
    const mantissa = Math.round(value / decade);
    return [1, 2, 5].includes(mantissa) ? formatSeconds(value) : "";
}

let chart = null;

function renderChart(report, target) {
    const data = report.targets[target];
    const main = document.getElementById("main");
    main.innerHTML = "";

    if (!data || !data.crates.length) {
        const empty = document.createElement("div");
        empty.className = "empty-state";
        empty.textContent =
            "No crate has a test that every configuration ran with the same result.";
        main.appendChild(empty);
        chart = null;
        return;
    }

    const set = document.createElement("div");
    set.className = "benchmark-set";
    set.innerHTML =
        '<h2 class="benchmark-title">Unsafe Crate Testbench Runtimes</h2>' +
        `<p class="benchmark-subtitle">${target}</p>` +
        '<div class="benchmark-graphs"><div class="chart-panel">' +
        '<div class="chart-canvas-wrap"><canvas id="seconds-chart"></canvas></div>' +
        "</div></div>";
    main.appendChild(set);

    const datasets = report.modes.map((mode, i) => ({
        label: mode,
        data: data.crates.map(c => data.seconds[mode][c]),
        borderColor: rgba(TAB10[i % TAB10.length], LINE_ALPHA),
        backgroundColor: rgba(TAB10[i % TAB10.length], LINE_ALPHA),
        pointBackgroundColor: rgba(TAB10[i % TAB10.length], LINE_ALPHA),
        borderWidth: LINE_WIDTH,
        pointRadius: MARKER_SIZE,
        pointHoverRadius: MARKER_SIZE + 2,
        fill: false,
        lineTension: 0
    }));

    if (chart) chart.destroy();
    chart = new Chart(document.getElementById("seconds-chart").getContext("2d"), {
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
                    afterTitle: (items) => {
                        const t = data.tests[data.crates[items[0].index]];
                        return t ? `${t.kept} of ${t.total} tests counted` : "";
                    }
                }
            },
            scales: {
                xAxes: [{
                    scaleLabel: {
                        display: true,
                        labelString: `Crate  (Ordered by ${report.modes[0]}, ascending)`
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
    });
}

function renderDropped(report, target) {
    const data = report.targets[target];
    const table = document.getElementById("dropped-table");
    const summary = document.getElementById("dropped-summary");
    table.innerHTML = "";

    const dropped = (data && data.dropped) || [];
    const disagreed = dropped.filter(d => d.reason === "disagreed").length;

    if (!dropped.length) {
        summary.textContent =
            "Every test ran with the same result under every configuration.";
        summary.className = "chart-meta dropped-empty";
        return;
    }
    summary.className = "chart-meta";
    summary.textContent =
        `${dropped.length} test(s) left out of the totals above, ` +
        `${disagreed} because the configurations disagreed.`;

    const head = table.insertRow();
    ["Crate", "Test", "Reason"].concat(report.modes).forEach(h => {
        const th = document.createElement("th");
        th.textContent = h;
        head.appendChild(th);
    });

    for (const row of dropped) {
        const tr = table.insertRow();
        tr.className = `reason-${row.reason === "disagreed" ? "disagreed" : "other"}`;
        tr.insertCell().textContent = row.crate;
        const test = tr.insertCell();
        test.textContent = row.test;
        test.className = "test-name";
        const reason = tr.insertCell();
        reason.textContent = row.reason;
        reason.className = "reason";
        for (const mode of report.modes) {
            const status = row.statuses[mode] || "not run";
            const cell = tr.insertCell();
            cell.textContent = status;
            cell.className = status === "success" ? "status-success"
                : status === "not run" ? "status-missing" : "status-failed";
        }
    }
}

function render(report, target) {
    renderChart(report, target);
    renderDropped(report, target);
}

function init(report) {
    document.getElementById("branch-name").textContent = report.branch || "unknown";
    document.getElementById("last-update").textContent =
        new Date(report.generated).toLocaleString("en-US", DATE_FORMAT_OPTS);

    const commit = document.getElementById("commit-link");
    if (report.commit && report.repoUrl) {
        const a = document.createElement("a");
        a.rel = "noopener";
        a.href = `${report.repoUrl}/commit/${report.commit}`;
        a.textContent = report.commit.slice(0, 8);
        commit.appendChild(a);
    } else {
        commit.textContent = (report.commit || "unknown").slice(0, 8);
    }

    if (report.runUrl) {
        document.getElementById("run-link").href = report.runUrl;
    } else {
        document.getElementById("run-sep").hidden = true;
    }

    const select = document.getElementById("target-select");
    const targets = Object.keys(report.targets).sort();
    for (const t of targets) {
        const opt = document.createElement("option");
        opt.value = t;
        opt.textContent = t;
        select.appendChild(opt);
    }
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

    render(report, targets[0]);
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
        const empty = document.createElement("div");
        empty.className = "empty-state";
        empty.textContent = `Could not load benchmark data (${err.message}).`;
        main.appendChild(empty);
    });
