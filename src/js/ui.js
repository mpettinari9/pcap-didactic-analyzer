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
      <p class="sample-name">${sample.name}</p>
      <p class="sample-description">${sample.description}</p>
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
