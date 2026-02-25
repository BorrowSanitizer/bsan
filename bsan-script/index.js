let showMiri = false;

const createChart = (architecture, benchmark_with_suffix, chartType) => {
  const chartsDiv = document.getElementById("charts");
  chartsDiv.innerHTML = ""; // Clear previous charts

  const archData = window.benchmarkData[architecture];

  if (!archData) {
    chartsDiv.innerHTML = `<p>No data found for architecture: ${architecture}</p>`;
    return;
  }

  const data = archData[benchmark_with_suffix];

  if (!data) {
    chartsDiv.innerHTML = `<p>No data found for benchmark: ${benchmark_with_suffix}</p>`;
    return;
  }

  const benchmark = benchmark_with_suffix.replace("-results", "");

  const tool_map = {
    [`./target/release/${benchmark}`]: "native",
    [`./${benchmark}`]: "BorrowSanitizer",
    [`cargo +nightly miri run -p programs --bin ${benchmark}`]: "Miri",
  };

  const calculate_tool_transform = {
    "calculate": JSON.stringify(tool_map) + "[datum.command]",
    "as": "Tool"
  };

  const baseSpec = {
    "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
    "width": 600,
    "height": 400,
    "data": {
      "values": data.results
    },
    "transform": [
      {"flatten": ["times"]},
      calculate_tool_transform,
      {"filter": showMiri ? "datum.Tool !== null" : "datum.Tool !== 'Miri'"}
    ]
  };

  const boxPlotSpec = {
    ...baseSpec,
    "title": "Benchmark Execution Time Comparison",
    "mark": {
      "type": "boxplot",
      "extent": "min-max",
      "size": 50,
      "box": {
        "stroke": "black",
        "strokeWidth": 2,
        "fillOpacity": 0.5
      },
      "median": {
        "stroke": "black",
        "strokeWidth": 3
      }
    },
    "encoding": {
      "x": {
        "field": "Tool",
        "type": "nominal",
        "title": "Tool",
        "sort": {"op": "median", "field": "times", "order": "ascending"}
      },
      "y": {
        "field": "times",
        "type": "quantitative",
        "title": "Execution Time (s)",
        "scale": {"type": "log"},
        "axis": {"format": ".4f"}
      },
      "color": {
        "field": "Tool",
        "type": "nominal",
        "scale": {"scheme": "tableau10"}
      }
    }
  };

  const scatterPlotSpec = {
    ...baseSpec,
    "title": "Benchmark Execution Time Comparison",
    "layer": [
      {
        "mark": {
          "type": "point",
          "opacity": 0.6,
          "filled": true,
          "stroke": "black",
          "strokeWidth": 0.5
        },
        "encoding": {
          "color": {
            "field": "Tool",
            "type": "nominal",
            "scale": {"scheme": "tableau10"},
            "legend": {
              "title": "Tool",
              "orient": "bottom",
              "direction": "horizontal"
            }
          },
          "tooltip": [
            {"field": "Tool", "type": "nominal", "title": "Test"},
            {"field": "times", "type": "quantitative", "format": ".4f", "title": "Time (s)"}
          ]
        }
      },
      {
        "mark": {
          "type": "rule",
          "color": "skyblue",
          "opacity": 0.7,
          "size": 3
        },
        "encoding": {
          "y": {
            "aggregate": "mean",
            "field": "times"
          }
        }
      }
    ],
    "encoding": {
      "x": {
        "field": "Tool",
        "type": "nominal",
        "title": "Tool",
        "sort": {"op": "median", "field": "times", "order": "ascending"}
      },
      "y": {
        "field": "times",
        "type": "quantitative",
        "title": "Execution Time (s)",
        "scale": {"type": "linear"},
        "axis": {"format": ".4f"}
      }
    }
  };

  const timeSeriesSpec = {
    ...baseSpec,
    "title": "Execution Time per Run with Average",
    "transform": [
      ...baseSpec.transform,
      {
        "window": [{"op": "row_number", "as": "run_number"}],
        "groupby": ["Tool"]
      }
    ],
    "layer": [
      {
        "mark": {
          "type": "point",
          "filled": true,
          "opacity": 0.3
        },
        "encoding": {
          "x": {
            "field": "run_number",
            "type": "quantitative",
            "title": "Run Number",
            "axis": {
              "labelAngle": 0
            }
          },
          "y": {
            "field": "times",
            "type": "quantitative",
            "title": "Execution Time (s)",
            "scale": {"zero": false},
            "axis": {"format": ".4f"}
          },
          "color": {
            "field": "Tool",
            "type": "nominal",
            "title": "Tool"
          }
        }
      },
      {
        "mark": {
          "type": "rule",
          "size": 3,
          "opacity": 0.8
        },
        "encoding": {
          "y": {
            "aggregate": "mean",
            "field": "times"
          },
          "color": {
            "field": "Tool",
            "type": "nominal"
          }
        }
      }
    ]
  };

  if (showMiri) {
    timeSeriesSpec.layer[0].encoding.y.scale.type = "log";
    scatterPlotSpec.encoding.y.scale.type = "log";
  }

  let spec;
  switch (chartType) {
    case "box":
      spec = boxPlotSpec;
      break;
    case "scatter":
      spec = scatterPlotSpec;
      break;
    case "time":
      spec = timeSeriesSpec;
      break;
  }

  const chartContainer = document.createElement("div");
  chartsDiv.appendChild(chartContainer);
  vegaEmbed(chartContainer, spec);
};

const main = () => {
  const archSelect = document.getElementById("arch-select");
  const benchmarkSelect = document.getElementById("benchmark-select");
  const chartTypeSelect = document.getElementById("chart-type-select");
  const miriToggle = document.getElementById("miri-toggle");

  const populateBenchmarks = (architecture) => {
    benchmarkSelect.innerHTML = "";
    const benchmarks = Object.keys(window.benchmarkData[architecture] || {});
    for (const benchmark of benchmarks) {
      const option = document.createElement("option");
      option.value = benchmark;
      option.textContent = benchmark;
      benchmarkSelect.appendChild(option);
    }
  };

  const updateChart = () => {
    const selectedArch = archSelect.value;
    const selectedBenchmark = benchmarkSelect.value;
    const selectedChartType = chartTypeSelect.value;
    createChart(selectedArch, selectedBenchmark, selectedChartType);
  };

  const updateMiriButton = () => {
    miriToggle.textContent = showMiri ? "Miri: On" : "Miri: Off";
  };

  archSelect.addEventListener("change", () => {
    populateBenchmarks(archSelect.value);
    updateChart();
  });

  benchmarkSelect.addEventListener("change", updateChart);
  chartTypeSelect.addEventListener("change", updateChart);

  miriToggle.addEventListener("click", () => {
    showMiri = !showMiri;
    updateMiriButton();
    updateChart();
  });

  // Initial load
  if (window.benchmarkData) {
    const initialArch = archSelect.value;
    populateBenchmarks(initialArch);
    updateMiriButton();
    updateChart();
  } else {
    document.getElementById("charts").innerHTML = "<p>Benchmark data not loaded. Please ensure data.js is present.</p>";
  }
};

main();