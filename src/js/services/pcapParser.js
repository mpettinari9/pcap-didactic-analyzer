const SUPPORTED_EXTENSIONS = [".pcap", ".pcapng"];
const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_IPV6 = 0x86dd;
const ETHERTYPE_VLAN_8021Q = 0x8100;
const ETHERTYPE_VLAN_8021AD = 0x88a8;

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
    [5353, "DNS"],
    [80, "HTTP"],
    [443, "TLS"],
    [853, "TLS"],
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
  if (!l4Payload || l4Payload.length < 2) {
    return identifyApplicationProtocol(srcPort, dstPort);
  }

  // DNS over UDP/TCP: header starts with transaction ID + flags.
  if ((l4Protocol === "UDP" || l4Protocol === "TCP") && (srcPort === 53 || dstPort === 53)) {
    return "DNS";
  }
  if ((l4Protocol === "UDP" || l4Protocol === "TCP") && (srcPort === 5353 || dstPort === 5353)) {
    return "DNS";
  }
  if (
    (l4Protocol === "UDP" || l4Protocol === "TCP") &&
    l4Payload.length >= 12 &&
    (l4Payload[2] & 0x80) <= 0x80
  ) {
    const qdCount = (l4Payload[4] << 8) | l4Payload[5];
    const anCount = (l4Payload[6] << 8) | l4Payload[7];
    if (qdCount > 0 || anCount > 0) return "DNS";
  }
  if (l4Protocol === "TCP" && l4Payload.length >= 14) {
    // DNS over TCP prepends a two-byte length field before the DNS header.
    const dnsLen = (l4Payload[0] << 8) | l4Payload[1];
    if (dnsLen >= 12 && dnsLen <= l4Payload.length - 2) {
      const qdCount = (l4Payload[6] << 8) | l4Payload[7];
      const anCount = (l4Payload[8] << 8) | l4Payload[9];
      if (qdCount > 0 || anCount > 0) return "DNS";
    }
  }

  // TLS handshake records start with content-type 0x16 and major version 0x03.
  if (
    l4Protocol === "TCP" &&
    l4Payload.length >= 5 &&
    [0x14, 0x15, 0x16, 0x17].includes(l4Payload[0]) &&
    l4Payload[1] === 0x03 &&
    l4Payload[2] <= 0x04
  ) {
    return "TLS";
  }

  // HTTP cleartext methods and response prefix.
  const httpHints = [
    "GET ",
    "POST ",
    "PUT ",
    "DELETE ",
    "HEAD ",
    "OPTIONS ",
    "PATCH ",
    "CONNECT ",
    "HTTP/",
  ];
  const asciiPrefix = decodeAsciiPrefix(l4Payload, 12);
  if (l4Protocol === "TCP" && httpHints.some((hint) => asciiPrefix.startsWith(hint))) {
    return "HTTP";
  }

  // Fallback based on well-known ports.
  return identifyApplicationProtocol(srcPort, dstPort);
}

function parseL4Info(packetBytes, networkOffset, srcIp, dstIp, protocolNumber) {
  const protocols = [];
  let flow = `${srcIp} -> ${dstIp}`;
  let srcPort = null;
  let dstPort = null;
  let l4Protocol = "Other";
  let appProtocol = null;

  if (protocolNumber === 6 && packetBytes.length >= networkOffset + 20) {
    protocols.push("TCP");
    l4Protocol = "TCP";
    srcPort = (packetBytes[networkOffset] << 8) | packetBytes[networkOffset + 1];
    dstPort = (packetBytes[networkOffset + 2] << 8) | packetBytes[networkOffset + 3];
    const tcpDataOffset = ((packetBytes[networkOffset + 12] >> 4) & 0x0f) * 4;
    if (tcpDataOffset >= 20) {
      const l4PayloadOffset = networkOffset + tcpDataOffset;
      const l4Payload = l4PayloadOffset < packetBytes.length
        ? packetBytes.slice(l4PayloadOffset)
        : new Uint8Array();
      appProtocol = detectByPayload(l4Payload, "TCP", srcPort, dstPort);
    } else {
      appProtocol = identifyApplicationProtocol(srcPort, dstPort);
    }
    flow = `${srcIp}:${srcPort} -> ${dstIp}:${dstPort}`;
    if (appProtocol) protocols.push(appProtocol);
  } else if (protocolNumber === 17 && packetBytes.length >= networkOffset + 8) {
    protocols.push("UDP");
    l4Protocol = "UDP";
    srcPort = (packetBytes[networkOffset] << 8) | packetBytes[networkOffset + 1];
    dstPort = (packetBytes[networkOffset + 2] << 8) | packetBytes[networkOffset + 3];
    const l4PayloadOffset = networkOffset + 8;
    const l4Payload = l4PayloadOffset < packetBytes.length
      ? packetBytes.slice(l4PayloadOffset)
      : new Uint8Array();
    flow = `${srcIp}:${srcPort} -> ${dstIp}:${dstPort}`;
    appProtocol = detectByPayload(l4Payload, "UDP", srcPort, dstPort);
    if (appProtocol) protocols.push(appProtocol);
  } else if (protocolNumber === 1 || protocolNumber === 58) {
    protocols.push("ICMP");
    l4Protocol = "ICMP";
  } else {
    protocols.push("Other");
  }

  return { protocols, flow, srcPort, dstPort, l4Protocol, appProtocol };
}

function formatIPv6Address(bytes, offset) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) {
    const value = (bytes[offset + i] << 8) | bytes[offset + i + 1];
    groups.push(value.toString(16));
  }
  return groups.join(":");
}

function parseIPv4Packet(packetBytes, ipOffset) {
  if (packetBytes.length < ipOffset + 20) {
    return {
      protocols: ["IPv4"],
      flow: "IPv4 truncated",
      srcIp: null,
      dstIp: null,
      srcPort: null,
      dstPort: null,
      l4Protocol: "IPv4",
      appProtocol: null,
    };
  }

  const ihl = (packetBytes[ipOffset] & 0x0f) * 4;
  if (ihl < 20 || packetBytes.length < ipOffset + ihl) {
    return {
      protocols: ["IPv4"],
      flow: "IPv4 malformed",
      srcIp: null,
      dstIp: null,
      srcPort: null,
      dstPort: null,
      l4Protocol: "IPv4",
      appProtocol: null,
    };
  }

  const protocolNumber = packetBytes[ipOffset + 9];
  const srcIp = `${packetBytes[ipOffset + 12]}.${packetBytes[ipOffset + 13]}.${packetBytes[ipOffset + 14]}.${packetBytes[ipOffset + 15]}`;
  const dstIp = `${packetBytes[ipOffset + 16]}.${packetBytes[ipOffset + 17]}.${packetBytes[ipOffset + 18]}.${packetBytes[ipOffset + 19]}`;
  const parsedL4 = parseL4Info(packetBytes, ipOffset + ihl, srcIp, dstIp, protocolNumber);

  return {
    protocols: ["IPv4", ...parsedL4.protocols],
    flow: parsedL4.flow,
    srcIp,
    dstIp,
    srcPort: parsedL4.srcPort,
    dstPort: parsedL4.dstPort,
    l4Protocol: parsedL4.l4Protocol,
    appProtocol: parsedL4.appProtocol,
  };
}

function parseIPv6Packet(packetBytes, ipOffset) {
  if (packetBytes.length < ipOffset + 40) {
    return {
      protocols: ["IPv6"],
      flow: "IPv6 truncated",
      srcIp: null,
      dstIp: null,
      srcPort: null,
      dstPort: null,
      l4Protocol: "IPv6",
      appProtocol: null,
    };
  }

  const nextHeader = packetBytes[ipOffset + 6];
  const srcIp = formatIPv6Address(packetBytes, ipOffset + 8);
  const dstIp = formatIPv6Address(packetBytes, ipOffset + 24);
  const parsedL4 = parseL4Info(packetBytes, ipOffset + 40, srcIp, dstIp, nextHeader);

  return {
    protocols: ["IPv6", ...parsedL4.protocols],
    flow: parsedL4.flow,
    srcIp,
    dstIp,
    srcPort: parsedL4.srcPort,
    dstPort: parsedL4.dstPort,
    l4Protocol: parsedL4.l4Protocol,
    appProtocol: parsedL4.appProtocol,
  };
}

function getEtherTypeAndPayloadOffset(packetBytes) {
  if (packetBytes.length < 14) return { etherType: null, payloadOffset: null };

  let etherType = (packetBytes[12] << 8) | packetBytes[13];
  let payloadOffset = 14;

  if ((etherType === ETHERTYPE_VLAN_8021Q || etherType === ETHERTYPE_VLAN_8021AD) && packetBytes.length >= 18) {
    etherType = (packetBytes[16] << 8) | packetBytes[17];
    payloadOffset = 18;
  }

  return { etherType, payloadOffset };
}

function parsePacket(packetBytes) {
  if (packetBytes.length < 14) return null;

  const { etherType, payloadOffset } = getEtherTypeAndPayloadOffset(packetBytes);
  if (etherType === null || payloadOffset === null) return null;

  if (etherType === ETHERTYPE_IPV4) {
    return parseIPv4Packet(packetBytes, payloadOffset);
  }

  if (etherType === ETHERTYPE_IPV6) {
    return parseIPv6Packet(packetBytes, payloadOffset);
  }

  return {
    protocols: ["Other"],
    flow: "L2/Other",
    srcIp: null,
    dstIp: null,
    srcPort: null,
    dstPort: null,
    l4Protocol: "Other",
    appProtocol: null,
  };
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

function getProtocolCount(protocolCounts, protocolName) {
  return protocolCounts.get(protocolName) || 0;
}

function generateTrafficInsights(protocolCounts, totalPackets, topHostFlows, timeline) {
  const insights = [];
  if (!totalPackets) return insights;

  const dns = getProtocolCount(protocolCounts, "DNS");
  const http = getProtocolCount(protocolCounts, "HTTP");
  const tls = getProtocolCount(protocolCounts, "TLS");
  const icmp = getProtocolCount(protocolCounts, "ICMP");
  const tcp = getProtocolCount(protocolCounts, "TCP");
  const udp = getProtocolCount(protocolCounts, "UDP");

  const dnsRatio = (dns / totalPackets) * 100;
  const tlsRatio = (tls / totalPackets) * 100;
  const icmpRatio = (icmp / totalPackets) * 100;

  if (dnsRatio > 25) {
    insights.push(
      "Il traffico DNS e elevato: potrebbe indicare fase di bootstrap, scansione di domini o molte applicazioni che risolvono nomi in parallelo.",
    );
  }

  if (tlsRatio > 20 && http === 0) {
    insights.push(
      "Il traffico e prevalentemente cifrato (TLS) con poco o nessun HTTP in chiaro: scenario tipico di navigazione web moderna su HTTPS.",
    );
  }

  if (http > 0 && tls > 0) {
    insights.push(
      "Sono presenti sia HTTP in chiaro sia TLS cifrato: utile per confrontare servizi legacy e servizi protetti nella stessa cattura.",
    );
  }

  if (icmpRatio > 10) {
    insights.push(
      "La quota ICMP e significativa: potrebbe essere in corso attivita di diagnostica (ping/traceroute) o verifica di raggiungibilita.",
    );
  }

  if (tcp > udp * 2) {
    insights.push(
      "TCP domina rispetto a UDP: la rete sembra orientata a sessioni affidabili (web, API, trasferimenti dati).",
    );
  } else if (udp > tcp) {
    insights.push(
      "UDP supera TCP: possibile presenza di servizi realtime, DNS intenso o protocolli non orientati alla connessione.",
    );
  }

  if (topHostFlows.length > 0 && topHostFlows[0].count > totalPackets * 0.35) {
    insights.push(
      `Un singolo flusso host-to-host pesa molto (${topHostFlows[0].flow}): potrebbe essere il canale principale della sessione osservata.`,
    );
  }

  const peakBucket = timeline.reduce(
    (best, current) => (current.count > best.count ? current : best),
    { label: "0s", count: 0 },
  );
  if (peakBucket.count > 0) {
    insights.push(
      `Picco di traffico osservato intorno a ${peakBucket.label}, con ${peakBucket.count} pacchetti nel bucket temporale.`,
    );
  }

  if (insights.length === 0) {
    insights.push(
      "Il traffico appare bilanciato tra i protocolli rilevati: un buon caso didattico per studiare il comportamento generale della rete.",
    );
  }

  return insights.slice(0, 5);
}

function buildTimeline(packetSummaries) {
  if (packetSummaries.length === 0) return [];
  const maxOffsetSec = Math.max(...packetSummaries.map((packet) => packet.offsetSec));
  const bucketSizeSec = Math.max(1, Math.ceil(maxOffsetSec / 12));
  const buckets = [];

  for (const packet of packetSummaries) {
    const bucket = Math.floor(packet.offsetSec / bucketSizeSec);
    buckets[bucket] = (buckets[bucket] || 0) + 1;
  }

  return buckets.map((count = 0, idx) => ({
    label: `${idx * bucketSizeSec}s`,
    count,
  }));
}

function matchesCustomFilter(packet, expression) {
  const expr = expression.trim();
  const parts = expr.split(":");
  if (parts.length !== 2) return true;

  const key = parts[0].trim().toLowerCase();
  const value = parts[1].trim().toLowerCase();
  if (!value) return true;

  if (key === "protocol") return packet.protocols.some((proto) => proto.toLowerCase() === value);
  if (key === "host") return `${packet.srcIp || ""} ${packet.dstIp || ""}`.toLowerCase().includes(value);
  if (key === "port") return `${packet.srcPort || ""} ${packet.dstPort || ""}`.includes(value);
  if (key === "flow") return packet.flow.toLowerCase().includes(value);
  return true;
}

function matchesWiresharkLikeFilter(packet, expression) {
  const expr = expression.trim().toLowerCase();
  if (!expr) return true;
  if (["tcp", "udp", "icmp", "dns", "http", "tls", "ipv4"].includes(expr)) {
    return packet.protocols.map((proto) => proto.toLowerCase()).includes(expr);
  }

  const [left, right] = expr.split("==");
  if (!left || !right) return true;
  const key = left.trim();
  const value = right.trim();

  if (key === "ip.addr") return packet.srcIp === value || packet.dstIp === value;
  if (key === "tcp.port" || key === "udp.port" || key === "port") {
    const targetPort = Number(value);
    return packet.srcPort === targetPort || packet.dstPort === targetPort;
  }
  return true;
}

export function filterPacketSummaries(packetSummaries, filters) {
  if (!filters || filters.length === 0) return packetSummaries;

  return packetSummaries.filter((packet) =>
    filters.every((filterItem) => {
      if (!filterItem?.value?.trim()) return true;
      if (filterItem.type === "custom") {
        return matchesCustomFilter(packet, filterItem.value);
      }
      return matchesWiresharkLikeFilter(packet, filterItem.value);
    }),
  );
}

export function buildAnalysisFromPacketSummaries(fileName, packetSummaries) {
  const protocolCounts = new Map();
  const flowCounts = new Map();
  const hostFlowCounts = new Map();

  for (const packet of packetSummaries) {
    for (const proto of packet.protocols) {
      protocolCounts.set(proto, (protocolCounts.get(proto) || 0) + 1);
    }

    flowCounts.set(packet.flow, (flowCounts.get(packet.flow) || 0) + 1);
    const hostPair = normalizeHostPair(packet.flow);
    hostFlowCounts.set(hostPair, (hostFlowCounts.get(hostPair) || 0) + 1);
  }

  const protocolsSorted = [...protocolCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([protocol, count]) => ({ protocol, count }));

  const explanations = protocolsSorted
    .slice(0, 8)
    .map((entry) => buildDidacticExplanation(entry.protocol, entry.count, packetSummaries.length));

  const topFlows = [...flowCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([flow, count]) => ({ flow, count }));

  const topHostFlows = [...hostFlowCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([flow, count]) => ({ flow, count }));

  const timelineBuckets = buildTimeline(packetSummaries);
  const trafficInsights = generateTrafficInsights(
    protocolCounts,
    packetSummaries.length,
    topHostFlows,
    timelineBuckets,
  );

  return {
    fileName,
    packetCount: packetSummaries.length,
    protocolDistribution: protocolsSorted,
    explanations,
    topFlows,
    topHostFlows,
    trafficInsights,
    timeline: timelineBuckets,
  };
}

export async function analyzeCaptureFile(file) {
  const extension = file.name.toLowerCase().endsWith(".pcapng") ? "pcapng" : "pcap";
  const arrayBuffer = await file.arrayBuffer();

  const packets = extension === "pcapng" ? readPcapngPackets(arrayBuffer) : readPcapPackets(arrayBuffer);
  if (packets.length === 0) {
    throw new Error("Nessun pacchetto leggibile trovato nel file.");
  }

  const firstTs = packets[0].timestampMs || Date.now();
  const packetSummaries = [];

  for (const packet of packets) {
    const parsed = parsePacket(packet.data);
    if (!parsed) continue;
    const ts = packet.timestampMs || firstTs;
    packetSummaries.push({
      ...parsed,
      timestampMs: ts,
      offsetSec: Math.max(0, Math.floor((ts - firstTs) / 1000)),
    });
  }

  const analysis = buildAnalysisFromPacketSummaries(file.name, packetSummaries);
  analysis.packetSummaries = packetSummaries;
  analysis.timeRangeSec = {
    min: 0,
    max: packetSummaries.length > 0 ? Math.max(...packetSummaries.map((packet) => packet.offsetSec)) : 0,
  };
  return analysis;
}
