import { setCurrentFile, setSamples } from "./state.js";
import {
  updateUploadStatus,
  renderAnalysisResults,
  renderFileAccepted,
  renderSamples,
} from "./ui.js";
import {
  analyzeCaptureFile,
  buildAnalysisFromPacketSummaries,
  ensureParserLibraryAvailable,
  filterPacketSummaries,
  isSupportedCaptureFile,
} from "./services/pcapParser.js";
import {
  destroyCharts,
  renderInitialCharts,
  updateChartsFromAnalysis,
} from "./services/chartService.js";

let cachedSamples = [];
let currentRawAnalysis = null;

function renderFilterRows(count) {
  const container = document.getElementById("filtersContainer");
  container.innerHTML = "";

  for (let idx = 0; idx < count; idx += 1) {
    const row = document.createElement("div");
    row.className = "filter-row";
    row.innerHTML = `
      <select class="filter-type">
        <option value="custom">Custom filter</option>
        <option value="wireshark">Wireshark filter</option>
      </select>
      <input class="filter-value" type="text" placeholder="Inserisci filtro..." />
    `;
    container.append(row);
  }
}

function getSelectedFilters() {
  const rows = [...document.querySelectorAll(".filter-row")];
  return rows.map((row) => ({
    type: row.querySelector(".filter-type")?.value || "custom",
    value: row.querySelector(".filter-value")?.value || "",
  }));
}

function applyInteractiveFilters() {
  if (!currentRawAnalysis?.packetSummaries) return;

  const timeStart = Number(document.getElementById("timeStartRange").value);
  const timeEnd = Number(document.getElementById("timeEndRange").value);
  const startSec = Math.min(timeStart, timeEnd);
  const endSec = Math.max(timeStart, timeEnd);

  const timeFilteredPackets = currentRawAnalysis.packetSummaries.filter(
    (packet) => packet.offsetSec >= startSec && packet.offsetSec <= endSec,
  );
  const selectedFilters = getSelectedFilters();
  const finalPackets = filterPacketSummaries(timeFilteredPackets, selectedFilters);
  const filteredAnalysis = buildAnalysisFromPacketSummaries(currentRawAnalysis.fileName, finalPackets);

  document.getElementById("timeRangeLabel").textContent = `${startSec}s - ${endSec}s`;
  renderAnalysisResults(filteredAnalysis);
  updateChartsFromAnalysis(filteredAnalysis);
}

function setupTimeRangeControls(analysis) {
  const startInput = document.getElementById("timeStartRange");
  const endInput = document.getElementById("timeEndRange");
  const maxSec = analysis.timeRangeSec?.max || 0;

  startInput.min = "0";
  endInput.min = "0";
  startInput.max = String(maxSec);
  endInput.max = String(maxSec);
  startInput.value = "0";
  endInput.value = String(maxSec);
  document.getElementById("timeRangeLabel").textContent = `0s - ${maxSec}s`;
}

async function initializeSamplesSection() {
  try {
    const response = await fetch("./src/data/samples/manifest.json");
    if (!response.ok) throw new Error("Manifest non trovato");
    const samples = await response.json();
    cachedSamples = samples;
    setSamples(samples);
    renderSamples(samples);
  } catch (_error) {
    cachedSamples = [];
    setSamples([]);
    renderSamples([]);
  }
}

async function processCaptureFile(file) {
  setCurrentFile(file);
  renderFileAccepted(file);
  updateUploadStatus("Analisi in corso...", "idle");

  try {
    const analysis = await analyzeCaptureFile(file);
    currentRawAnalysis = analysis;
    setupTimeRangeControls(analysis);
    applyInteractiveFilters();
    updateUploadStatus("Analisi completata con successo.", "success");
  } catch (error) {
    updateUploadStatus(
      `Errore durante l'analisi: ${error.message || "errore sconosciuto"}.`,
      "error",
    );
  }
}

async function handleFileSelection(event) {
  const file = event.target.files?.[0];
  if (!file) {
    updateUploadStatus("Nessun file selezionato.", "idle");
    return;
  }

  if (!isSupportedCaptureFile(file.name)) {
    updateUploadStatus(
      "Formato non supportato. Carica un file .pcap o .pcapng.",
      "error",
    );
    return;
  }

  const parserStatus = await ensureParserLibraryAvailable();
  if (!parserStatus.ready) {
    updateUploadStatus(
      "Parser non disponibile. Controlla la connessione e riprova.",
      "error",
    );
    return;
  }

  await processCaptureFile(file);
}

async function handleDroppedFile(file) {
  if (!file) return;

  if (!isSupportedCaptureFile(file.name)) {
    updateUploadStatus(
      "Formato non supportato. Carica un file .pcap o .pcapng.",
      "error",
    );
    return;
  }

  const parserStatus = await ensureParserLibraryAvailable();
  if (!parserStatus.ready) {
    updateUploadStatus(
      "Parser non disponibile. Controlla la connessione e riprova.",
      "error",
    );
    return;
  }

  await processCaptureFile(file);
}

async function handleSampleClick(event) {
  const button = event.target.closest(".sample-load-button");
  if (!button) return;

  const sampleId = button.dataset.sampleId;
  const sample = cachedSamples.find((item) => item.id === sampleId);
  if (!sample) {
    updateUploadStatus("Sample non trovato nel manifest.", "error");
    return;
  }

  const parserStatus = await ensureParserLibraryAvailable();
  if (!parserStatus.ready) {
    updateUploadStatus(
      "Parser non disponibile. Controlla la connessione e riprova.",
      "error",
    );
    return;
  }

  updateUploadStatus(`Caricamento sample ${sample.fileName}...`, "idle");
  try {
    const response = await fetch(`./src/data/samples/${sample.fileName}`);
    if (!response.ok) throw new Error("File sample non disponibile");
    const blob = await response.blob();
    const file = new File([blob], sample.fileName, { type: "application/octet-stream" });
    await processCaptureFile(file);
  } catch (error) {
    updateUploadStatus(
      `Impossibile caricare il sample: ${error.message || "errore sconosciuto"}.`,
      "error",
    );
  }
}

function attachEventListeners() {
  const input = document.getElementById("pcapInput");
  const samplesList = document.getElementById("samplesList");
  const dropzone = document.getElementById("uploadDropzone");
  const filterCountSelect = document.getElementById("filterCountSelect");
  const filtersContainer = document.getElementById("filtersContainer");
  const timeStartRange = document.getElementById("timeStartRange");
  const timeEndRange = document.getElementById("timeEndRange");
  input.addEventListener("change", handleFileSelection);
  samplesList.addEventListener("click", handleSampleClick);
  filterCountSelect.addEventListener("change", () => {
    renderFilterRows(Number(filterCountSelect.value));
    applyInteractiveFilters();
  });
  filtersContainer.addEventListener("input", applyInteractiveFilters);
  timeStartRange.addEventListener("input", applyInteractiveFilters);
  timeEndRange.addEventListener("input", applyInteractiveFilters);

  ["dragenter", "dragover"].forEach((eventName) => {
    dropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      event.stopPropagation();
      dropzone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach((eventName) => {
    dropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      event.stopPropagation();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", async (event) => {
    const file = event.dataTransfer?.files?.[0];
    await handleDroppedFile(file);
  });
}

async function bootstrap() {
  await initializeSamplesSection();
  renderFilterRows(1);
  destroyCharts();
  renderInitialCharts();
  attachEventListeners();
}

bootstrap();
