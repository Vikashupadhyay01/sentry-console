/**
 * Sentry Console — Threat Detection Engine
 * Scans parsed packet list for 7 threat categories.
 * Each finding: { id, name, severity, src, dst, summary, indicators[], mitigation, packetIndices[] }
 */

import { TCP_FLAGS } from './parser.js';

// ─── Severity helpers ─────────────────────────────────────────────────────────
const SEV = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

// Sensitive ports for brute-force detection
const SENSITIVE_PORTS = {
  22:   'SSH',
  23:   'Telnet',
  21:   'FTP',
  3389: 'RDP',
  3306: 'MySQL',
  5432: 'PostgreSQL',
  445:  'SMB',
  1433: 'MSSQL',
  5900: 'VNC',
};

/**
 * Run all detections on a parsed packet list.
 * @param {Array} packets — output from parsePcap()
 * @param {Object} stats  — output from parsePcap()
 * @returns {Array} findings
 */
export function runDetections(packets, stats) {
  const findings = [];
  let id = 1;

  const add = (finding) => {
    finding.id = id++;
    findings.push(finding);
  };

  detectPortScan(packets, stats, add);
  detectSynFlood(packets, stats, add);
  detectIcmpFlood(packets, stats, add);
  detectBruteForce(packets, stats, add);
  detectArpSpoofing(packets, stats, add);
  detectDnsAmplification(packets, stats, add);
  detectDataExfiltration(packets, stats, add);

  // Sort: critical first
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => sevOrder[a.severity] - sevOrder[b.severity]);

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. PORT SCAN DETECTION
// ─────────────────────────────────────────────────────────────────────────────
function detectPortScan(packets, stats, add) {
  // Group by src→dst pair, collect distinct dst ports in 5-second windows
  const pairPorts = {}; // "src|dst" -> { ts -> Set<port> }

  for (const p of packets) {
    if (!p.ipSrc || !p.ipDst || p.dstPort == null) continue;
    if (p.ipProto !== 6) continue; // TCP only

    const key = `${p.ipSrc}|${p.ipDst}`;
    if (!pairPorts[key]) pairPorts[key] = {};

    const bucket = Math.floor(p.timestamp / 5); // 5-second windows
    if (!pairPorts[key][bucket]) pairPorts[key][bucket] = new Set();
    pairPorts[key][bucket].add(p.dstPort);
  }

  for (const [key, windows] of Object.entries(pairPorts)) {
    const [src, dst] = key.split('|');

    for (const [bucket, portSet] of Object.entries(windows)) {
      const distinctPorts = portSet.size;
      if (distinctPorts < 15) continue;

      const severity = distinctPorts >= 50  ? SEV.CRITICAL
                     : distinctPorts >= 30  ? SEV.HIGH
                     : SEV.MEDIUM;

      const sortedPorts = [...portSet].sort((a, b) => a - b);

      add({
        name: 'Port Scan Detected',
        severity,
        src,
        dst,
        summary: `Host ${src} scanned ${distinctPorts} distinct ports on ${dst} within a 5-second window, indicating automated reconnaissance or vulnerability scanning activity.`,
        indicators: [
          `Source IP: ${src}`,
          `Target IP: ${dst}`,
          `Distinct destination ports in 5s window: ${distinctPorts}`,
          `Port range sample: ${sortedPorts.slice(0, 10).join(', ')}${sortedPorts.length > 10 ? '...' : ''}`,
          `Time window: ~${Number(bucket) * 5}s – ${Number(bucket) * 5 + 5}s into capture`,
        ],
        mitigation: `Block ${src} at the perimeter firewall. Enable port scan detection on IDS/IPS. Verify no internal reconnaissance tool is misconfigured. If external, consider adding the source to a threat intelligence blocklist.`,
        attackWindow: { startSec: Number(bucket) * 5, endSec: Number(bucket) * 5 + 5 },
      });
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. SYN FLOOD DETECTION
// ─────────────────────────────────────────────────────────────────────────────
function detectSynFlood(packets, stats, add) {
  // Count SYN-only vs SYN-ACK per dst IP in 1-second buckets
  const dstBuckets = {}; // dst -> { bucket -> { syn, synAck } }

  for (const p of packets) {
    if (!p.ipDst || p.ipProto !== 6 || p.tcpFlags == null) continue;

    const isSyn    = (p.tcpFlags & TCP_FLAGS.SYN) !== 0;
    const isAck    = (p.tcpFlags & TCP_FLAGS.ACK) !== 0;
    const isSynOnly   = isSyn && !isAck;
    const isSynAck    = isSyn && isAck;

    if (!isSynOnly && !isSynAck) continue;

    const dst = p.ipDst;
    if (!dstBuckets[dst]) dstBuckets[dst] = {};
    const bucket = Math.floor(p.timestamp);
    if (!dstBuckets[dst][bucket]) dstBuckets[dst][bucket] = { syn: 0, synAck: 0, sources: new Set() };

    if (isSynOnly) {
      dstBuckets[dst][bucket].syn++;
      dstBuckets[dst][bucket].sources.add(p.ipSrc);
    }
    if (isSynAck) dstBuckets[dst][bucket].synAck++;
  }

  for (const [dst, buckets] of Object.entries(dstBuckets)) {
    for (const [bucket, counts] of Object.entries(buckets)) {
      const { syn, synAck, sources } = counts;
      if (syn < 80) continue;

      const completionRate = syn === 0 ? 1 : synAck / syn;
      if (completionRate > 0.3) continue; // normal traffic

      const severity = syn >= 500 || completionRate < 0.05 ? SEV.CRITICAL : SEV.HIGH;

      add({
        name: 'TCP SYN Flood',
        severity,
        src: sources.size === 1 ? [...sources][0] : `${sources.size} sources (possible spoofed)`,
        dst,
        summary: `Destination ${dst} received ${syn} SYN packets in one second with only a ${(completionRate * 100).toFixed(1)}% handshake completion rate, consistent with a SYN flood denial-of-service attack.`,
        indicators: [
          `Target IP: ${dst}`,
          `SYN packets in 1s: ${syn}`,
          `SYN-ACK responses: ${synAck}`,
          `Handshake completion rate: ${(completionRate * 100).toFixed(1)}%`,
          `Distinct source IPs: ${sources.size}`,
          `Time: ~${bucket}s into capture`,
        ],
        mitigation: `Enable SYN cookies on the target host. Configure rate limiting for SYN packets on border routers. Deploy stateful firewall inspection. Consider upstream scrubbing/DDoS protection services if attack is volumetric.`,
        attackWindow: { startSec: Number(bucket), endSec: Number(bucket) + 1 },
      });
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. ICMP FLOOD DETECTION
// ─────────────────────────────────────────────────────────────────────────────
function detectIcmpFlood(packets, stats, add) {
  // Count ICMP echo requests (type 8) per dst in 1-second windows
  const dstBuckets = {}; // dst -> { bucket -> { count, sources } }

  for (const p of packets) {
    if (!p.ipDst || p.ipProto !== 1) continue;
    if (p.icmpType !== 8) continue; // echo request only

    const dst = p.ipDst;
    if (!dstBuckets[dst]) dstBuckets[dst] = {};
    const bucket = Math.floor(p.timestamp);
    if (!dstBuckets[dst][bucket]) dstBuckets[dst][bucket] = { count: 0, sources: new Set() };
    dstBuckets[dst][bucket].count++;
    dstBuckets[dst][bucket].sources.add(p.ipSrc);
  }

  for (const [dst, buckets] of Object.entries(dstBuckets)) {
    for (const [bucket, data] of Object.entries(buckets)) {
      if (data.count < 40) continue;

      const severity = data.count >= 200 ? SEV.CRITICAL : SEV.HIGH;

      add({
        name: 'ICMP Flood (Ping Flood)',
        severity,
        src: data.sources.size === 1 ? [...data.sources][0] : `${data.sources.size} sources`,
        dst,
        summary: `Host ${dst} received ${data.count} ICMP echo requests in one second from ${data.sources.size} source(s), consistent with a ping flood denial-of-service attack.`,
        indicators: [
          `Target IP: ${dst}`,
          `ICMP echo requests in 1s: ${data.count}`,
          `Distinct sources: ${data.sources.size}`,
          `Time window: ~${bucket}s into capture`,
        ],
        mitigation: `Configure firewall to rate-limit or block inbound ICMP echo requests. Enable ICMP rate limiting on border routers. For distributed floods, contact upstream provider for traffic scrubbing.`,
        attackWindow: { startSec: Number(bucket), endSec: Number(bucket) + 1 },
      });
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. BRUTE-FORCE DETECTION
// ─────────────────────────────────────────────────────────────────────────────
function detectBruteForce(packets, stats, add) {
  // Count distinct TCP connection attempts (SYN) from one src to sensitive port
  const attempts = {}; // "src|dst|port" -> { count, times[] }

  for (const p of packets) {
    if (!p.ipSrc || !p.ipDst || p.dstPort == null) continue;
    if (p.ipProto !== 6) continue;
    if (!(p.tcpFlags & TCP_FLAGS.SYN) || (p.tcpFlags & TCP_FLAGS.ACK)) continue; // SYN-only
    if (!SENSITIVE_PORTS[p.dstPort]) continue;

    const key = `${p.ipSrc}|${p.ipDst}|${p.dstPort}`;
    if (!attempts[key]) attempts[key] = { count: 0, timestamps: [] };
    attempts[key].count++;
    attempts[key].timestamps.push(p.timestamp);
  }

  for (const [key, data] of Object.entries(attempts)) {
    if (data.count < 15) continue;

    const [src, dst, portStr] = key.split('|');
    const port = Number(portStr);
    const serviceName = SENSITIVE_PORTS[port];

    const severity = data.count >= 100 ? SEV.CRITICAL
                   : data.count >= 50  ? SEV.HIGH
                   : SEV.MEDIUM;

    const span = data.timestamps[data.timestamps.length - 1] - data.timestamps[0];
    const rate = span > 0 ? (data.count / span).toFixed(2) : '∞';

    add({
      name: `Brute Force — ${serviceName} (Port ${port})`,
      severity,
      src,
      dst,
      summary: `Host ${src} made ${data.count} TCP SYN connection attempts to ${serviceName} (port ${port}) on ${dst} over ${span.toFixed(1)}s, strongly suggesting automated credential brute-forcing.`,
      indicators: [
        `Source IP: ${src}`,
        `Target IP: ${dst}`,
        `Target service: ${serviceName} (port ${port})`,
        `SYN attempts: ${data.count}`,
        `Duration: ${span.toFixed(1)} seconds`,
        `Rate: ${rate} attempts/sec`,
      ],
      mitigation: `Block ${src} at firewall. Enable account lockout policies on the target service. Implement fail2ban or equivalent. Consider moving the service to a non-standard port. Enable MFA on the target service.`,
      attackWindow: { startSec: Math.floor(data.timestamps[0] - stats.firstTs), endSec: Math.ceil(data.timestamps[data.timestamps.length - 1] - stats.firstTs) },
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. ARP SPOOFING DETECTION
// ─────────────────────────────────────────────────────────────────────────────
function detectArpSpoofing(packets, stats, add) {
  // Track IP → Set<MAC> from ARP replies (opcode 2)
  const ipToMacs = {}; // ip -> { mac -> count }

  for (const p of packets) {
    if (!p.arp || p.arp.opcode !== 2) continue; // ARP reply only
    const ip  = p.arp.senderIP;
    const mac = p.arp.senderMAC;
    if (!ipToMacs[ip]) ipToMacs[ip] = {};
    ipToMacs[ip][mac] = (ipToMacs[ip][mac] || 0) + 1;
  }

  for (const [ip, macs] of Object.entries(ipToMacs)) {
    const macList = Object.keys(macs);
    if (macList.length < 2) continue;

    const macDetails = macList.map(m => `${m} (${macs[m]} replies)`);

    add({
      name: 'ARP Spoofing / Cache Poisoning',
      severity: SEV.CRITICAL,
      src: macList[1], // the likely attacker (second claimant)
      dst: ip,
      summary: `IP address ${ip} is being claimed by ${macList.length} different MAC addresses in ARP reply packets, indicating ARP cache poisoning. An attacker may be performing a man-in-the-middle attack to intercept traffic.`,
      indicators: [
        `Conflicting IP: ${ip}`,
        `MAC addresses claiming this IP:`,
        ...macDetails.map(m => `  • ${m}`),
        `Total conflicting ARP replies: ${Object.values(macs).reduce((a, b) => a + b, 0)}`,
      ],
      mitigation: `Enable Dynamic ARP Inspection (DAI) on managed switches. Deploy static ARP entries for critical hosts. Use ARP spoofing detection tools (e.g., arpwatch). Segment the network with VLANs to limit blast radius.`,
      attackWindow: null,
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. DNS AMPLIFICATION / EXCESSIVE QUERIES
// ─────────────────────────────────────────────────────────────────────────────
function detectDnsAmplification(packets, stats, add) {
  // DNS = UDP port 53
  const dnsQueriesPerSrc = {}; // src -> { count, dsts }

  for (const p of packets) {
    if (!p.ipSrc || p.ipProto !== 17) continue;
    if (p.dstPort !== 53 && p.srcPort !== 53) continue;
    if (p.dstPort !== 53) continue; // outbound queries only

    if (!dnsQueriesPerSrc[p.ipSrc]) dnsQueriesPerSrc[p.ipSrc] = { count: 0, dsts: new Set() };
    dnsQueriesPerSrc[p.ipSrc].count++;
    dnsQueriesPerSrc[p.ipSrc].dsts.add(p.ipDst);
  }

  for (const [src, data] of Object.entries(dnsQueriesPerSrc)) {
    if (data.count < 10) continue;

    const severity = data.count >= 50 ? SEV.HIGH : SEV.MEDIUM;

    add({
      name: 'Excessive DNS Query Volume',
      severity,
      src,
      dst: [...data.dsts].slice(0, 3).join(', '),
      summary: `Host ${src} generated ${data.count} DNS queries to ${data.dsts.size} resolver(s) during the capture window. This may indicate DNS tunneling, domain generation algorithm (DGA) malware, or misconfigured software.`,
      indicators: [
        `Source IP: ${src}`,
        `Total DNS queries: ${data.count}`,
        `Unique DNS resolvers queried: ${data.dsts.size}`,
        `Resolvers: ${[...data.dsts].join(', ')}`,
      ],
      mitigation: `Capture and inspect DNS query content for long/random subdomains (DGA/tunneling). Block unauthorized external DNS resolvers. Enforce DNS-over-HTTPS policy. Enable DNS query logging for further forensic analysis.`,
      attackWindow: null,
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. DATA EXFILTRATION (LARGE TRANSFER)
// ─────────────────────────────────────────────────────────────────────────────
function detectDataExfiltration(packets, stats, add) {
  if (!stats.flowBytes) return;

  const THRESHOLD_MB = 0.5; // flag flows > 500 KB
  const THRESHOLD_BYTES = THRESHOLD_MB * 1024 * 1024;

  for (const [flow, bytes] of Object.entries(stats.flowBytes)) {
    if (bytes < THRESHOLD_BYTES) continue;

    const [src, dst] = flow.split('->');
    const mb = (bytes / 1048576).toFixed(2);

    const severity = bytes > 10 * 1048576 ? SEV.HIGH : SEV.MEDIUM;

    add({
      name: 'Large Data Transfer (Possible Exfiltration)',
      severity,
      src,
      dst,
      summary: `${mb} MB was transferred from ${src} to ${dst} in this capture window, which may indicate data exfiltration or unauthorized bulk transfer activity.`,
      indicators: [
        `Source IP: ${src}`,
        `Destination IP: ${dst}`,
        `Total bytes transferred: ${bytes.toLocaleString()} bytes (${mb} MB)`,
        `Threshold: ${THRESHOLD_MB} MB`,
      ],
      mitigation: `Inspect payload content for sensitive data patterns (DLP). Verify if the destination is an authorized cloud/backup service. Enable egress filtering and data loss prevention (DLP) policies. Alert on outbound transfers exceeding defined thresholds.`,
      attackWindow: null,
    });
  }
}
