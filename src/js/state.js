export const appState = {
  currentFile: null,
  analysis: null,
  samples: [],
};

export function setCurrentFile(file) {
  appState.currentFile = file;
}

export function setSamples(samples) {
  appState.samples = samples;
}

export function setAnalysis(analysis) {
  appState.analysis = analysis;
}
