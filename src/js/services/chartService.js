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
