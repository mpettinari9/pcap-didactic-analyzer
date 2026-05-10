function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function updateUploadStatus(message, status = "idle") {
  const uploadStatus = document.getElementById("uploadStatus");
  uploadStatus.className = `status ${status}`;
  uploadStatus.textContent = message;
}

export function renderFileAccepted(file) {
  updateUploadStatus(
    `File pronto: ${file.name} (${formatBytes(file.size)}).`,
    "success",
  );
}

export function renderSamples(samples) {
  const list = document.getElementById("samplesList");
  list.innerHTML = "";

  for (const sample of samples) {
    const item = document.createElement("li");
    item.className = "sample-item";
    item.innerHTML = `
      <p class="sample-name">${sample.title || sample.name}</p>
      <p class="sample-description">${sample.description}</p>
      <button class="sample-load-button" data-sample-id="${sample.id}" type="button">
        Carica sample
      </button>
    `;
    list.append(item);
  }
}

export function renderAnalysisPlaceholder(fileName) {
  const placeholder = document.getElementById("analysisPlaceholder");
  placeholder.innerHTML = `
    <strong>File caricato:</strong> ${fileName}<br />
    Lo scheletro e pronto: nel prossimo step parseremo i pacchetti e mostreremo
    spiegazioni didattiche su 3 livelli (cosa vedo, cosa significa, perche e importante).
  `;
}

export function renderAnalysisResults(analysis) {
  const placeholder = document.getElementById("analysisPlaceholder");
  const explanationsHtml = analysis.explanations
    .map(
      (item) => `
      <article class="didactic-card">
        <h3>${item.protocol} (${item.count})</h3>
        <p><strong>Cosa vedo:</strong> ${item.whatYouSee}</p>
        <p><strong>Cosa significa:</strong> ${item.whatItMeans}</p>
        <p><strong>Perche e importante:</strong> ${item.whyItMatters}</p>
      </article>
    `,
    )
    .join("");

  const flowHtml = analysis.topFlows
    .map((flow) => `<li><code>${flow.flow}</code> - ${flow.count} pacchetti</li>`)
    .join("");

  const insightsHtml = (analysis.trafficInsights || [])
    .map((insight) => `<li>${insight}</li>`)
    .join("");

  placeholder.innerHTML = `
    <div class="analysis-summary">
      <p><strong>File:</strong> ${analysis.fileName}</p>
      <p><strong>Pacchetti analizzati:</strong> ${analysis.packetCount}</p>
      <p><strong>Flussi principali:</strong></p>
      <ul class="flow-list">${flowHtml || "<li>Nessun flusso disponibile.</li>"}</ul>
    </div>
    <div class="insights-box">
      <p><strong>Interpretazione automatica:</strong></p>
      <ul class="insights-list">${insightsHtml || "<li>Nessun insight disponibile.</li>"}</ul>
    </div>
    <div class="didactic-grid">
      ${explanationsHtml || "<p>Nessuna spiegazione disponibile.</p>"}
    </div>
  `;
}
