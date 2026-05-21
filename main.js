"use strict";
/* global Chart */
// The primary color of the chart
const COLOR = "#ff3838";

// The background color of the chart,
// underneath the line. (Add alpha for #rrggbbaa)
const BG_COLOR = COLOR + "60";

// ex: Monday, May 18, 2026 at 10:03 AM EDT
const DATE_FORMAT_OPTS = {
    day: "numeric",
    hour: "numeric",
    minute: "numeric",
    month: "long",
    timeZoneName: "short",
    weekday: "long",
    year: "numeric"
};

const DEFAULT_CHART_OPTS = {
    elements: {
        line: {
            borderWidth: 2,
            tension: 0.15
        },
        point: {
            hoverRadius: 5,
            radius: 3
        }
    },
    legend: {
        display: false
    },
    maintainAspectRatio: false,
    responsive: true
};

// Initializes the data, returning a list of objects
// that each contain the `name` of the benchmark configuration
// and an array `dataSet` containing each measurement.
// As a side-effect, enables UI elements if data is present.
function initDatasets() {
    function collectBenchesPerTestCase(entries) {
        function parseExtra(extraStr) {
            if (!extraStr) return null;
            try {
                return JSON.parse(extraStr);
            } catch {
                return null;
            }
        }

        const map = new Map();
        for (const entry of entries) {
            const {
                commit,
                date,
                tool,
                benches
            } = entry;
            
            for (const bench of benches) {
                const result = {
                    commit,
                    date,
                    tool,
                    bench: { ...bench } 
                };
                
                result.bench.extra = parseExtra(result.bench.extra);
                
                const arr = map.get(result.bench.name);
                if (arr === undefined) {
                    map.set(result.bench.name, [result]);
                } else {
                    arr.push(result);
                }
            }
        }
        return map;
    }

    const data = window.BENCHMARK_DATA;
    const dl_button = document.getElementById('dl-button');
    const last_update = document.getElementById('last-update');

    if (data != undefined) {
        const date = new Date(data.lastUpdate);
        const date_string = date.toLocaleString("en-US", DATE_FORMAT_OPTS);
        last_update.textContent = date_string;
        dl_button.hidden = false;

        // Render footer
        dl_button.onclick = () => {
            const jsonString = JSON.stringify(data, null, 2);
            const blob = new Blob([jsonString], { type: 'application/json;charset=utf-8' });
            const dataUrl = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = dataUrl;
            a.download = 'data.json';
            a.click();
            
            URL.revokeObjectURL(dataUrl);
        };

        // Prepare data points for charts
        return Object.keys(data.entries).map(name => ({
            name,
            dataSet: collectBenchesPerTestCase(data.entries[name]),
        }));

    } else {
        dl_button.hidden = true;
        last_update.textContent = "Unknown";
        return [];
    }
}

function sortedUnique(values) {
    return Array.from(new Set(values)).sort((a, b) => a.localeCompare(b));
}

// Populates each of the drop-down menus in the navbar
// with the available filtering options, based on the contents
// of the dataset.
function populateControls(dataSets, render) {

    function populateSelect(select, values, allLabel) {
        select.innerHTML = '';
        const allOption = document.createElement('option');
        allOption.value = '';
        allOption.textContent = allLabel;
        select.appendChild(allOption);
        for (const value of values) {
            const option = document.createElement('option');
            option.value = value;
            option.textContent = value;
            select.appendChild(option);
        }
    }

    const crateSelect = document.getElementById('crate-select');
    const targetSelect = document.getElementById('target-select');
    const modeSelect = document.getElementById('mode-select');

    const parsedDataSets = [];
    for (const { dataSet } of dataSets) {
        for (const benches of dataSet.values()) {
            const parsed = benches
                .map(d => d.bench.extra)
                .filter(Boolean);
            parsedDataSets.push(...parsed);
        }
    }
    
    if (parsedDataSets.length > 0) {
        populateSelect(crateSelect, sortedUnique(parsedDataSets.map(d => d.crate)), 'All crates');
        populateSelect(targetSelect, sortedUnique(parsedDataSets.map(d => d.target)), 'All targets');
        populateSelect(modeSelect, sortedUnique(parsedDataSets.map(d => d.mode)), 'All modes');

        crateSelect.addEventListener('change', render);
        targetSelect.addEventListener('change', render);
        modeSelect.addEventListener('change', render);
    } else {
        const missing = 'No data';
        populateSelect(crateSelect, [], missing);
        crateSelect.disabled = true;

        populateSelect(targetSelect, [], missing);
        targetSelect.disabled = true;

        populateSelect(modeSelect, [], missing);
        modeSelect.disabled = true;
    }
}

function filterDataset(dataset, filters) {
   return dataset.filter((d) => {
        return (!filters.crate  || d.bench.extra?.crate === filters.crate)  &&
               (!filters.target || d.bench.extra?.target === filters.target) &&
               (!filters.mode   || d.bench.extra?.mode === filters.mode);
   });
}

function formatBenchExtra(bench) {
    const metadata = bench.extra;
    if (!metadata) {
        return [];
    }
    return [
        'crate: ' + metadata.crate,
        'mode: ' + metadata.mode,
        'target: ' + metadata.target,
        'version: ' + metadata.version,
    ];
}

function renderAllCharts(dataSets) {

    function renderGraph(parent, name, dataset) {
        const panel = document.createElement('section');
        panel.className = 'chart-panel';
        parent.appendChild(panel);

        const title = document.createElement('h2');
        title.className = 'chart-title';
        title.textContent = name;
        panel.appendChild(title);

        const latestMetadata = dataset[dataset.length - 1]?.bench.extra ?? null;
        const meta = document.createElement('p');
        meta.className = 'chart-meta';
        meta.textContent = latestMetadata ?
            latestMetadata.crate + '@' + latestMetadata.version + ' - ' + latestMetadata.mode + ' - ' + latestMetadata.target :
            'No data points';
        panel.appendChild(meta);

        const canvasWrap = document.createElement('div');
        canvasWrap.className = 'chart-canvas-wrap';
        panel.appendChild(canvasWrap);

        const canvas = document.createElement('canvas');
        canvas.className = 'benchmark-chart';
        canvasWrap.appendChild(canvas);

        const data = {
            labels: dataset.map(d => d.commit.id.slice(0, 7)),
            datasets: [{
                label: name,
                data: dataset.map(d => d.bench.value),
                borderColor: COLOR,
                backgroundColor: BG_COLOR
            }],
        };
        
        const options = {
            ...DEFAULT_CHART_OPTS,
            scales: {
                xAxes: [{
                    scaleLabel: {
                        display: true,
                        labelString: 'commit',
                    },
                }],
                yAxes: [{
                    scaleLabel: {
                        display: true,
                        labelString: dataset.length > 0 ? dataset[0].bench.unit : '',
                    },
                    ticks: {
                        beginAtZero: true,
                        callback: value => Number(value).toLocaleString(undefined, {
                            maximumFractionDigits: 3
                        }),
                    }
                }],
            },
            tooltips: {
                callbacks: {
                    afterTitle: items => {
                        const { index } = items[0];
                        const data = dataset[index];
                        return '\n' + data.commit.message 
                            + '\n\n' + data.commit.timestamp 
                            + ' committed by @' 
                            + data.commit.committer.username 
                            + '\n';
                    },
                    label: item => {
                        let label = item.value;
                        const { range, unit } = dataset[item.index].bench;
                        label += ' ' + unit;
                        if (range) {
                            label += ' (' + range + ')';
                        }
                        return label;
                    },
                    afterLabel: item => {
                        return formatBenchExtra(dataset[item.index].bench);
                    }
                }
            },
            onClick: (_mouseEvent, activeElems) => {
                if (activeElems.length === 0) {
                    return;
                }
                const index = activeElems[0]._index;
                const url = dataset[index].commit.url;
                window.open(url, '_blank');
            },
        };
        
        new Chart(canvas, {
            type: 'line',
            data,
            options,
        });
    }

    function renderBenchSet(name, benchSet, main, filters) {
        const setElem = document.createElement('div');
        setElem.className = 'benchmark-set';
        main.appendChild(setElem);

        const nameElem = document.createElement('h1');
        nameElem.className = 'benchmark-title';
        nameElem.textContent = name;
        setElem.appendChild(nameElem);

        const count = Array.from(benchSet.values()).reduce((total, benches) => {
            return total + filterDataset(benches, filters).length;
        }, 0);

        const subtitleElem = document.createElement('p');
        subtitleElem.className = 'benchmark-subtitle';
        subtitleElem.textContent = count + ' data point' + (count === 1 ? '' : 's');
        setElem.appendChild(subtitleElem);

        const graphsElem = document.createElement('div');
        graphsElem.className = 'benchmark-graphs';
        setElem.appendChild(graphsElem);

        for (const [benchName, benches] of benchSet.entries()) {
            const filtered = filterDataset(benches, filters);
            if (filtered.length > 0) {
                renderGraph(graphsElem, benchName, filtered);
            }
        }

        if (graphsElem.children.length === 0) {
            setElem.remove();
            return false;
        }
        return true;
    }

    const main = document.getElementById('main');
    main.innerHTML = '';
    const filters = {
        crate: document.getElementById('crate-select').value,
        target: document.getElementById('target-select').value,
        mode: document.getElementById('mode-select').value,
    };

    let rendered = 0;
    for (const { name, dataSet } of dataSets) {
        rendered += renderBenchSet(name, dataSet, main, filters) ? 1 : 0;
    }
    
    if (rendered === 0) {
        const empty = document.createElement('div');
        empty.className = 'empty-state';
        empty.textContent = 'No benchmark data matches the selected filters.';
        main.appendChild(empty);
    }
}

const dataSets = initDatasets();
populateControls(dataSets, () => renderAllCharts(dataSets));
renderAllCharts(dataSets);