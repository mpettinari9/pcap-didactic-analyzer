import { setCurrentFile, setSamples } from "./state.js";
import {
  updateUploadStatus,
  renderAnalysisPlaceholder,
  renderFileAccepted,
  renderSamples,
} from "./ui.js";
import {
  ensureParserLibraryAvailable,
  isSupportedCaptureFile,
} from "./services/pcapParser.js";
import {
  destroyCharts,
  renderInitialCharts,
} from "./services/chartService.js";

const DEFAULT_SAMPLES = [
  {
    name: "dns-http-basic.pcap",
    description: "Navigazione web base con richieste DNS e traffico HTTP.",
  },
  {
    name: "tls-handshake-demo.pcapng",
    description: "Esempio di handshake TLS per introdurre la cifratura.",
  },
  {
    name: "icmp-troubleshooting.pcap",
    description: "Ping, echo request/reply e diagnostica con ICMP.",
  },
];

function initializeSamplesSection() {
  setSamples(DEFAULT_SAMPLES);
  renderSamples(DEFAULT_SAMPLES);
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

  setCurrentFile(file);
  renderFileAccepted(file);
  renderAnalysisPlaceholder(file.name);
}

function attachEventListeners() {
  const input = document.getElementById("pcapInput");
  input.addEventListener("change", handleFileSelection);
}

function bootstrap() {
  initializeSamplesSection();
  destroyCharts();
  renderInitialCharts();
  attachEventListeners();
}

bootstrap();
