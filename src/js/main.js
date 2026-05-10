import { setCurrentFile, setSamples } from "./state.js";
import {
  updateUploadStatus,
  renderAnalysisResults,
  renderFileAccepted,
  renderSamples,
} from "./ui.js";
import {
  analyzeCaptureFile,
  ensureParserLibraryAvailable,
  isSupportedCaptureFile,
} from "./services/pcapParser.js";
import {
  destroyCharts,
  renderInitialCharts,
  updateChartsFromAnalysis,
} from "./services/chartService.js";

let cachedSamples = [];

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
    renderAnalysisResults(analysis);
    updateChartsFromAnalysis(analysis);
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
  input.addEventListener("change", handleFileSelection);
  samplesList.addEventListener("click", handleSampleClick);

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
  destroyCharts();
  renderInitialCharts();
  attachEventListeners();
}

bootstrap();
