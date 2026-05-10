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

function readUint32(view, offset, littleEndian) {
  return view.getUint32(offset, littleEndian);
}

function readPcapPackets(arrayBuffer) {
  const view = new DataView(arrayBuffer);
  if (view.byteLength < 24) return [];

  const magic = view.getUint32(0, false);
  let littleEndian;
  if (magic === 0xa1b2c3d4 || magic === 0xa1b23c4d) {
    littleEndian = false;
  } else if (magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1) {
    littleEndian = true;
  } else {
    throw new Error("File pcap non valido.");
  }

  const packets = [];
  let offset = 24;
  while (offset + 16 <= view.byteLength) {
    const tsSec = readUint32(view, offset, littleEndian);
    const tsUsec = readUint32(view, offset + 4, littleEndian);
    const inclLen = readUint32(view, offset + 8, littleEndian);
    const packetStart = offset + 16;
    const packetEnd = packetStart + inclLen;

    if (packetEnd > view.byteLength) break;

    packets.push({
      timestampMs: tsSec * 1000 + Math.floor(tsUsec / 1000),
      data: new Uint8Array(arrayBuffer, packetStart, inclLen),
    });

    offset = packetEnd;
  }

  return packets;
}

function readPcapngPackets(arrayBuffer) {
  const view = new DataView(arrayBuffer);
  const bytes = new Uint8Array(arrayBuffer);
  const packets = [];
  let offset = 0;
  let currentEndian = true;

  while (offset + 12 <= view.byteLength) {
    const blockType = view.getUint32(offset, true);
    const blockLengthLe = view.getUint32(offset + 4, true);
    const blockLengthBe = view.getUint32(offset + 4, false);

    let blockLength = blockLengthLe;
    currentEndian = true;
    if (blockLength < 12 || offset + blockLength > view.byteLength) {
      blockLength = blockLengthBe;
      currentEndian = false;
    }
    if (blockLength < 12 || offset + blockLength > view.byteLength) break;

    if (blockType === 0x0a0d0d0a && offset + 12 <= view.byteLength) {
      const bom = view.getUint32(offset + 8, true);
      currentEndian = bom === 0x4d3c2b1a ? false : true;
    }

    if (blockType === 0x00000006 && blockLength >= 32) {
      const tsHigh = view.getUint32(offset + 12, currentEndian);
      const tsLow = view.getUint32(offset + 16, currentEndian);
      const capLen = view.getUint32(offset + 20, currentEndian);
      const packetStart = offset + 28;
      const packetEnd = packetStart + capLen;
      if (packetEnd <= offset + blockLength - 4 && packetEnd <= view.byteLength) {
        const timestampMicro = tsHigh * 4294967296 + tsLow;
        packets.push({
          timestampMs: Math.floor(timestampMicro / 1000),
          data: bytes.slice(packetStart, packetEnd),
        });
      }
    } else if (blockType === 0x00000003 && blockLength >= 20) {
      const capLen = view.getUint32(offset + 12, currentEndian);
      const packetStart = offset + 16;
      const packetEnd = packetStart + capLen;
      if (packetEnd <= offset + blockLength - 4 && packetEnd <= view.byteLength) {
        packets.push({
          timestampMs: Date.now(),
          data: bytes.slice(packetStart, packetEnd),
        });
      }
    }

    offset += blockLength;
  }

  return packets;
}

function identifyApplicationProtocol(srcPort, dstPort) {
  const known = new Map([
    [53, "DNS"],
    [80, "HTTP"],
    [443, "TLS"],
    [123, "NTP"],
  ]);
  return known.get(srcPort) || known.get(dstPort) || null;
}

function decodeAsciiPrefix(bytes, maxLen = 32) {
  const len = Math.min(bytes.length, maxLen);
  let out = "";
  for (let i = 0; i < len; i += 1) {
    const b = bytes[i];
    out += b >= 32 && b <= 126 ? String.fromCharCode(b) : ".";
  }
  return out;
}

function detectByPayload(l4Payload, l4Protocol, srcPort, dstPort) {
  if (!l4Payload || l4Payload.length < 2) return null;

  // DNS over UDP/TCP: header starts with transaction ID + flags.
  if ((l4Protocol === "UDP" || l4Protocol === "TCP") && (srcPort === 53 || dstPort === 53)) {
    return "DNS";
  }

  // TLS handshake records start with content-type 0x16 and major version 0x03.
  if (
    l4Protocol === "TCP" &&
    l4Payload.length >= 5 &&
    l4Payload[0] === 0x16 &&
    l4Payload[1] === 0x03 &&
    l4Payload[2] <= 0x04
  ) {
    return "TLS";
  }

  // HTTP cleartext methods and response prefix.
  const httpHints = ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/"];
  const asciiPrefix = decodeAsciiPrefix(l4Payload, 12);
  if (l4Protocol === "TCP" && httpHints.some((hint) => asciiPrefix.startsWith(hint))) {
    return "HTTP";
  }

  // Fallback based on well-known ports.
  return identifyApplicationProtocol(srcPort, dstPort);
}

function parsePacket(packetBytes) {
  if (packetBytes.length < 14) return null;

  const etherType = (packetBytes[12] << 8) | packetBytes[13];
  if (etherType !== 0x0800) return { protocols: ["Other"], flow: "L2/Other" };
  if (packetBytes.length < 34) return { protocols: ["IPv4"], flow: "IPv4 truncated" };

  const ipOffset = 14;
  const ihl = (packetBytes[ipOffset] & 0x0f) * 4;
  const protocolNumber = packetBytes[ipOffset + 9];

  const srcIp = `${packetBytes[ipOffset + 12]}.${packetBytes[ipOffset + 13]}.${packetBytes[ipOffset + 14]}.${packetBytes[ipOffset + 15]}`;
  const dstIp = `${packetBytes[ipOffset + 16]}.${packetBytes[ipOffset + 17]}.${packetBytes[ipOffset + 18]}.${packetBytes[ipOffset + 19]}`;

  const protocols = ["IPv4"];
  let flow = `${srcIp} -> ${dstIp}`;

  if (protocolNumber === 6 && packetBytes.length >= ipOffset + ihl + 4) {
    protocols.push("TCP");
    const srcPort = (packetBytes[ipOffset + ihl] << 8) | packetBytes[ipOffset + ihl + 1];
    const dstPort = (packetBytes[ipOffset + ihl + 2] << 8) | packetBytes[ipOffset + ihl + 3];
    const tcpDataOffset = ((packetBytes[ipOffset + ihl + 12] >> 4) & 0x0f) * 4;
    const l4PayloadOffset = ipOffset + ihl + tcpDataOffset;
    const l4Payload = l4PayloadOffset < packetBytes.length
      ? packetBytes.slice(l4PayloadOffset)
      : new Uint8Array();
    flow = `${srcIp}:${srcPort} -> ${dstIp}:${dstPort}`;
    const appProto = detectByPayload(l4Payload, "TCP", srcPort, dstPort);
    if (appProto) protocols.push(appProto);
  } else if (protocolNumber === 17 && packetBytes.length >= ipOffset + ihl + 4) {
    protocols.push("UDP");
    const srcPort = (packetBytes[ipOffset + ihl] << 8) | packetBytes[ipOffset + ihl + 1];
    const dstPort = (packetBytes[ipOffset + ihl + 2] << 8) | packetBytes[ipOffset + ihl + 3];
    const l4PayloadOffset = ipOffset + ihl + 8;
    const l4Payload = l4PayloadOffset < packetBytes.length
      ? packetBytes.slice(l4PayloadOffset)
      : new Uint8Array();
    flow = `${srcIp}:${srcPort} -> ${dstIp}:${dstPort}`;
    const appProto = detectByPayload(l4Payload, "UDP", srcPort, dstPort);
    if (appProto) protocols.push(appProto);
  } else if (protocolNumber === 1) {
    protocols.push("ICMP");
  } else {
    protocols.push("Other");
  }

  return { protocols, flow };
}

function normalizeHostPair(flow) {
  const [left, right] = flow.split("->").map((part) => part.trim());
  if (!left || !right) return "Unknown";
  const srcHost = left.includes(":") ? left.split(":")[0] : left;
  const dstHost = right.includes(":") ? right.split(":")[0] : right;
  return `${srcHost} -> ${dstHost}`;
}

function buildDidacticExplanation(protocol, count, totalPackets) {
  const ratio = totalPackets > 0 ? ((count / totalPackets) * 100).toFixed(1) : "0.0";
  const base = {
    protocol,
    count,
    whatYouSee: `Vedi ${count} pacchetti ${protocol}, pari al ${ratio}% del traffico analizzato.`,
    whatItMeans: "",
    whyItMatters: "",
  };

  const protocolHints = {
    TCP: [
      "TCP indica comunicazioni affidabili orientate alla connessione.",
      "E importante per capire performance, ritrasmissioni e stabilita applicativa.",
    ],
    UDP: [
      "UDP indica traffico veloce senza handshake e senza garanzia di consegna.",
      "E utile per riconoscere servizi time-sensitive come DNS, streaming e VoIP.",
    ],
    DNS: [
      "DNS mostra la risoluzione dei nomi in indirizzi IP.",
      "Capire DNS aiuta a individuare latenze, errori di risoluzione o domini sospetti.",
    ],
    HTTP: [
      "HTTP rappresenta richieste e risposte web in chiaro.",
      "E fondamentale per studiare flussi applicativi e contenuti non cifrati.",
    ],
    TLS: [
      "TLS indica traffico cifrato, tipicamente HTTPS.",
      "E importante per distinguere handshake, cifratura attiva e sicurezza della sessione.",
    ],
    ICMP: [
      "ICMP segnala messaggi di rete e diagnostica (es. ping).",
      "Aiuta a capire raggiungibilita, errori e problemi di routing.",
    ],
    IPv4: [
      "IPv4 e il livello rete che incapsula i protocolli superiori.",
      "Serve come base per interpretare indirizzi sorgente/destinazione e percorsi.",
    ],
    Other: [
      "Sono presenti pacchetti non classificati nelle categorie principali.",
      "Possono indicare protocolli meno comuni o traffico da analizzare piu a fondo.",
    ],
  };

  const hint = protocolHints[protocol] || protocolHints.Other;
  base.whatItMeans = hint[0];
  base.whyItMatters = hint[1];
  return base;
}

export async function analyzeCaptureFile(file) {
  const extension = file.name.toLowerCase().endsWith(".pcapng") ? "pcapng" : "pcap";
  const arrayBuffer = await file.arrayBuffer();

  const packets = extension === "pcapng" ? readPcapngPackets(arrayBuffer) : readPcapPackets(arrayBuffer);
  if (packets.length === 0) {
    throw new Error("Nessun pacchetto leggibile trovato nel file.");
  }

  const protocolCounts = new Map();
  const flowCounts = new Map();
  const hostFlowCounts = new Map();
  const timeline = [];

  const firstTs = packets[0].timestampMs || Date.now();
  const lastTs = packets[packets.length - 1].timestampMs || firstTs + packets.length;
  const durationMs = Math.max(1, lastTs - firstTs);
  const bucketSize = Math.max(1000, Math.ceil(durationMs / 12));

  for (const packet of packets) {
    const parsed = parsePacket(packet.data);
    if (!parsed) continue;

    for (const proto of parsed.protocols) {
      protocolCounts.set(proto, (protocolCounts.get(proto) || 0) + 1);
    }

    flowCounts.set(parsed.flow, (flowCounts.get(parsed.flow) || 0) + 1);
    const hostPair = normalizeHostPair(parsed.flow);
    hostFlowCounts.set(hostPair, (hostFlowCounts.get(hostPair) || 0) + 1);

    const ts = packet.timestampMs || firstTs;
    const bucket = Math.floor((ts - firstTs) / bucketSize);
    timeline[bucket] = (timeline[bucket] || 0) + 1;
  }

  const protocolsSorted = [...protocolCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([protocol, count]) => ({ protocol, count }));

  const explanations = protocolsSorted
    .slice(0, 8)
    .map((entry) => buildDidacticExplanation(entry.protocol, entry.count, packets.length));

  const topFlows = [...flowCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([flow, count]) => ({ flow, count }));

  const topHostFlows = [...hostFlowCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([flow, count]) => ({ flow, count }));

  return {
    fileName: file.name,
    packetCount: packets.length,
    protocolDistribution: protocolsSorted,
    explanations,
    topFlows,
    topHostFlows,
    timeline: timeline.map((count = 0, idx) => ({
      label: `${idx * Math.round(bucketSize / 1000)}s`,
      count,
    })),
  };
}
