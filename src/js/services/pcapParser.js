const SUPPORTED_EXTENSIONS = [".pcap", ".pcapng"];

export function isSupportedCaptureFile(fileName) {
  const lowerName = fileName.toLowerCase();
  return SUPPORTED_EXTENSIONS.some((ext) => lowerName.endsWith(ext));
}

export async function ensureParserLibraryAvailable() {
  try {
    // Browser-friendly ESM entrypoint for @cto.af/pcap-ng-parser.
    await import("https://esm.sh/@cto.af/pcap-ng-parser");
    return { ready: true, source: "@cto.af/pcap-ng-parser" };
  } catch (error) {
    return {
      ready: false,
      source: "@cto.af/pcap-ng-parser",
      error,
    };
  }
}
