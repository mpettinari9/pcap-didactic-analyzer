let protocolChart;
let timelineChart;

export function renderInitialCharts() {
  const protocolCtx = document.getElementById("protocolChart");
  const timelineCtx = document.getElementById("timelineChart");

  if (!protocolCtx || !timelineCtx) return;

  protocolChart = new Chart(protocolCtx, {
    type: "doughnut",
    data: {
      labels: ["In attesa di analisi"],
      datasets: [
        {
          data: [1],
          backgroundColor: ["#d7e2ff"],
          borderWidth: 0,
        },
      ],
    },
    options: {
      plugins: { legend: { position: "bottom" } },
      maintainAspectRatio: false,
    },
  });

  timelineChart = new Chart(timelineCtx, {
    type: "line",
    data: {
      labels: ["t0", "t1", "t2", "t3"],
      datasets: [
        {
          label: "Pacchetti",
          data: [0, 0, 0, 0],
          borderColor: "#3662ff",
          backgroundColor: "rgba(54, 98, 255, 0.12)",
          fill: true,
          tension: 0.3,
        },
      ],
    },
    options: {
      plugins: { legend: { display: false } },
      maintainAspectRatio: false,
      scales: {
        y: { beginAtZero: true },
      },
    },
  });
}

export function destroyCharts() {
  protocolChart?.destroy();
  timelineChart?.destroy();
}

export function updateChartsFromAnalysis(analysis) {
  if (!protocolChart || !timelineChart) return;

  const labels = analysis.protocolDistribution.map((item) => item.protocol);
  const values = analysis.protocolDistribution.map((item) => item.count);

  const palette = [
    "#3662ff",
    "#00a3a3",
    "#f59e0b",
    "#ef4444",
    "#8b5cf6",
    "#10b981",
    "#ec4899",
    "#94a3b8",
  ];

  protocolChart.data.labels = labels.length ? labels : ["Nessun protocollo"];
  protocolChart.data.datasets[0].data = values.length ? values : [1];
  protocolChart.data.datasets[0].backgroundColor = labels.length
    ? labels.map((_, idx) => palette[idx % palette.length])
    : ["#d7e2ff"];
  protocolChart.update();

  const timelineLabels = analysis.timeline.map((item) => item.label);
  const timelineValues = analysis.timeline.map((item) => item.count);
  timelineChart.data.labels = timelineLabels.length ? timelineLabels : ["t0"];
  timelineChart.data.datasets[0].data = timelineValues.length ? timelineValues : [0];
  timelineChart.update();
}
