import fs from 'fs';
import path from 'path';
import { parsePcap } from '../src/parser.js';
import { runDetections } from '../src/detection.js';
import { processIocs } from '../src/modules/ioc_extractor.js';
import { calculateSecurityScore, normalizeFinding } from '../src/modules/score_engine.js';

function createPcapHeader() {
  const buf = new Uint8Array(24);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, 0xa1b2c3d4, true); // Magic LE
  dv.setUint16(4, 2, true);          // Version major
  dv.setUint16(6, 4, true);          // Version minor
  dv.setInt32(8, 0, true);           // timezone offset
  dv.setUint32(12, 0, true);         // sigfigs
  dv.setUint32(16, 65535, true);     // snaplen
  dv.setUint32(20, 1, true);         // linktype (Ethernet)
  return buf;
}

function createPcapRecord(packetBytes, tsSec, tsUsec = 0) {
  const recHeader = new Uint8Array(16);
  const dv = new DataView(recHeader.buffer);
  dv.setUint32(0, tsSec, true);
  dv.setUint32(4, tsUsec, true);
  dv.setUint32(8, packetBytes.length, true);
  dv.setUint32(12, packetBytes.length, true);

  const fullRecord = new Uint8Array(16 + packetBytes.length);
  fullRecord.set(recHeader, 0);
  fullRecord.set(packetBytes, 16);
  return fullRecord;
}

function parseIp(ipStr) {
  return ipStr.split('.').map(Number);
}

function parseMac(macStr) {
  return macStr.split(':').map(h => parseInt(h, 16));
}

function buildEthHeader(srcMac, dstMac, ethertype) {
  const buf = new Uint8Array(14);
  buf.set(parseMac(dstMac), 0);
  buf.set(parseMac(srcMac), 6);
  const dv = new DataView(buf.buffer);
  dv.setUint16(12, ethertype, false);
  return buf;
}

function buildIpHeader(srcIp, dstIp, proto, payloadLen) {
  const buf = new Uint8Array(20);
  buf[0] = 0x45;
  buf[1] = 0x00;
  const dv = new DataView(buf.buffer);
  dv.setUint16(2, 20 + payloadLen, false);
  dv.setUint16(4, 0x1234, false);
  dv.setUint16(6, 0x4000, false);
  buf[8] = 64;
  buf[9] = proto;
  buf.set(parseIp(srcIp), 12);
  buf.set(parseIp(dstIp), 16);
  return buf;
}

function buildTcpPacket(srcIp, dstIp, srcPort, dstPort, flags) {
  const eth = buildEthHeader('00:11:22:33:44:55', '66:77:88:99:AA:BB', 0x0800);
  const ip = buildIpHeader(srcIp, dstIp, 6, 20);

  const tcp = new Uint8Array(20);
  const dv = new DataView(tcp.buffer);
  dv.setUint16(0, srcPort, false);
  dv.setUint16(2, dstPort, false);
  dv.setUint32(4, 1000, false);
  dv.setUint32(8, 0, false);
  tcp[12] = (5 << 4);
  tcp[13] = flags;
  dv.setUint16(14, 64240, false);

  const pkt = new Uint8Array(eth.length + ip.length + tcp.length);
  pkt.set(eth, 0);
  pkt.set(ip, eth.length);
  pkt.set(tcp, eth.length + ip.length);
  return pkt;
}

console.log('Generating 50,000 packet synthetic PCAP file (6.1MB raw / 50k packets)...');
const records = [createPcapHeader()];
const baseTs = 1700000000;

for (let i = 0; i < 50000; i++) {
  const a = (i % 100) + 1;
  const b = Math.floor(i / 100) % 100 + 1;
  const srcIp = `172.16.${a}.${b}`;
  const dstIp = `10.0.0.1`;
  const pkt = buildTcpPacket(srcIp, dstIp, 1024 + (i % 60000), 80 + (i % 100), 0x02);
  const sec = baseTs + Math.floor(i / 1000);
  const usec = (i % 1000) * 1000;
  records.push(createPcapRecord(pkt, sec, usec));
}

const totalSize = records.reduce((sum, r) => sum + r.length, 0);
console.log(`PCAP total size: ${(totalSize / 1024 / 1024).toFixed(2)} MB (${records.length - 1} packet records)`);

const finalBuf = new Uint8Array(totalSize);
let offset = 0;
for (const r of records) {
  finalBuf.set(r, offset);
  offset += r.length;
}

console.log('\n--- Step 1: Parsing 50,000-packet PCAP ---');
const buffer = finalBuf.buffer;
const parsed = parsePcap(buffer);
console.log(`parsePcap() result: totalPackets=${parsed.stats.totalPackets}, packets.length=${parsed.packets.length}`);

const pcapFindings = runDetections(parsed.packets, parsed.stats);
const normalized = pcapFindings.map(f => ({
  id: `PCAP-${String(f.id).toUpperCase()}`,
  title: f.name,
  severity: (f.severity || 'LOW').toUpperCase(),
  category: 'Network Attack',
  description: f.summary || f.description || 'Suspicious network traffic pattern detected.',
  src: f.src || '',
  dst: f.dst || '',
  source: (f.src || f.dst) ? `${f.src || '*'} → ${f.dst || '*'}` : 'Network Stream',
  recommendation: f.mitigation || 'Inspect network flow logs.',
  attackWindow: f.attackWindow || null,
  indicators: f.indicators || []
}));

const pcapIocs = {
  ips: Array.from(new Set(parsed.packets.flatMap(p => [p.ipSrc, p.ipDst]).filter(Boolean))),
  domains: [],
  urls: [],
  emails: [],
  hashes: []
};

const rawResult = {
  metadata: { fileName: '50k_high_diversity.pcap', fileSize: totalSize, targetType: 'Network Capture (.pcap)', privacyMode: '🔒 100% LOCAL' },
  findings: normalized,
  iocs: pcapIocs,
  _rawPackets: parsed.packets,
  stats: parsed.stats,
  artifacts: { packetsCount: parsed.packets.length, duration: parsed.stats.duration }
};

const processedIocs = processIocs(rawResult.iocs);
const combinedFindings = [...rawResult.findings, ...processedIocs.findings].map(normalizeFinding);
const scoreInfo = calculateSecurityScore(combinedFindings);

function buildGraphData(packets, findings) {
  if (!packets || packets.length === 0) return { nodes: [], edges: [] };
  const flaggedIPs = new Set();
  for (const f of findings) {
    if (f.src && !f.src.includes(' ')) flaggedIPs.add(f.src);
    if (f.dst && !f.dst.includes(' ')) flaggedIPs.add(f.dst);
  }
  const nodeMap = {};
  const edgeMap = {};
  for (const p of packets) {
    if (!p.ipSrc || !p.ipDst) continue;
    for (const ip of [p.ipSrc, p.ipDst]) {
      if (!nodeMap[ip]) nodeMap[ip] = { ip, packets: 0, bytes: 0, flagged: flaggedIPs.has(ip) };
    }
    nodeMap[p.ipSrc].packets++;
    nodeMap[p.ipDst].packets++;
    nodeMap[p.ipSrc].bytes += p.inclLen || 0;
    const eKey = `${p.ipSrc}->${p.ipDst}`;
    if (!edgeMap[eKey]) edgeMap[eKey] = {
      src: p.ipSrc, dst: p.ipDst,
      packets: 0, bytes: 0,
      flagged: flaggedIPs.has(p.ipSrc) || flaggedIPs.has(p.ipDst)
    };
    edgeMap[eKey].packets++;
    edgeMap[eKey].bytes += p.inclLen || 0;
  }
  let nodes = Object.values(nodeMap);
  let edges = Object.values(edgeMap);
  if (nodes.length > 60) {
    nodes.sort((a, b) => b.packets - a.packets);
    const kept = new Set(nodes.slice(0, 60).map(n => n.ip));
    for (const ip of flaggedIPs) kept.add(ip);
    nodes = nodes.filter(n => kept.has(n.ip));
    edges = edges.filter(e => kept.has(e.src) && kept.has(e.dst));
  }
  return { nodes, edges };
}

// BEFORE FIX: Object containing full raw packets array + un-sanitized stats
const unoptimizedPayload = {
  metadata: rawResult.metadata,
  scoreInfo,
  findings: combinedFindings,
  iocs: processedIocs.iocs || processedIocs,
  packets: parsed.packets, // RAW 50,000 PACKET ARRAY
  stats: rawResult.stats,
  artifacts: rawResult.artifacts,
  privacyMode: 'CLIENT_SIDE_LOCAL'
};

const unoptimizedStr = JSON.stringify(unoptimizedPayload);
console.log('\n=== BEFORE FIX (Unoptimized Payload with raw packets[]) ===');
console.log(`Total JSON string length: ${unoptimizedStr.length.toLocaleString()} chars (~${(unoptimizedStr.length / 1024 / 1024).toFixed(2)} MB)`);
console.log('Top-level key breakdown:');
Object.keys(unoptimizedPayload).forEach(k => {
  const s = JSON.stringify(unoptimizedPayload[k]);
  console.log(`  - ${k}: ${s.length.toLocaleString()} chars (${(s.length / 1024).toFixed(1)} KB)`);
});

// AFTER FIX: Aggregated-only payload with cleanStats (omitting flowBytes and raw packets array)
const graphData = buildGraphData(rawResult._rawPackets || [], combinedFindings);
const cleanStats = rawResult.stats ? {
  totalPackets: rawResult.stats.totalPackets,
  duration: rawResult.stats.duration,
  uniqueHosts: rawResult.stats.uniqueHosts,
  protocolCounts: rawResult.stats.protocolCounts,
  topSrcIPs: rawResult.stats.topSrcIPs,
  topDstPorts: rawResult.stats.topDstPorts,
  timelineBuckets: rawResult.stats.timelineBuckets,
  firstTs: rawResult.stats.firstTs,
  lastTs: rawResult.stats.lastTs,
  linktype: rawResult.stats.linktype,
  snaplen: rawResult.stats.snaplen
} : null;

const optimizedPayload = {
  metadata: rawResult.metadata,
  scoreInfo,
  findings: combinedFindings,
  iocs: processedIocs.iocs || processedIocs,
  stats: cleanStats,
  graphData,
  artifacts: rawResult.artifacts,
  privacyMode: 'CLIENT_SIDE_LOCAL'
};

const optimizedStr = JSON.stringify(optimizedPayload);
console.log('\n=== AFTER FIX (Optimized Payload with cleanStats & graphData, NO raw packets) ===');
console.log(`Total JSON string length: ${optimizedStr.length.toLocaleString()} chars (~${(optimizedStr.length / 1024).toFixed(1)} KB)`);
console.log('Top-level key breakdown:');
Object.keys(optimizedPayload).forEach(k => {
  const s = JSON.stringify(optimizedPayload[k]);
  console.log(`  - ${k}: ${s.length.toLocaleString()} chars (${(s.length / 1024).toFixed(1)} KB)`);
});

console.log('\n=== VERIFICATION SUMMARY ===');
console.log(`1. Total Packets Count in stats: ${optimizedPayload.stats.totalPackets}`);
console.log(`2. Storage Reduction Factor: ${(unoptimizedStr.length / optimizedStr.length).toFixed(1)}x reduction`);
console.log(`3. Under 5MB Browser Quota Limit (5,242,880 chars): ${optimizedStr.length < 5242880 ? 'YES' : 'NO'}`);
