/**
 * Sentry Console — PCAP Binary Parser
 * Parses classic libpcap format (not pcapng) using DataView/ArrayBuffer.
 * No external dependencies.
 */

export const MAGIC_LE        = 0xa1b2c3d4; // native little-endian pcap
export const MAGIC_BE        = 0xd4c3b2a1; // big-endian / byte-swapped pcap
export const MAGIC_PCAPNG    = 0x0a0d0d0a; // pcapng — must reject

// Protocol numbers
const PROTO_ICMP = 1;
const PROTO_TCP  = 6;
const PROTO_UDP  = 17;

// EtherTypes
const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_ARP  = 0x0806;
const ETHERTYPE_VLAN = 0x8100;

// TCP flag masks
export const TCP_FLAGS = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
  URG: 0x20,
};

/**
 * Parse a .pcap ArrayBuffer.
 * @param {ArrayBuffer} buffer
 * @param {Function} [onProgress] callback(pct 0-100)
 * @returns {{ globalHeader, packets[], stats }}
 */
export function parsePcap(inputBuffer, onProgress) {
  let buffer;
  if (ArrayBuffer.isView(inputBuffer)) {
    buffer = inputBuffer.buffer.slice(inputBuffer.byteOffset, inputBuffer.byteOffset + inputBuffer.byteLength);
  } else {
    buffer = inputBuffer;
  }

  console.log('[Sentry] parsePcap() called — buffer size:', buffer.byteLength, 'bytes');

  if (buffer.byteLength < 24) {
    throw new Error('INVALID_FORMAT: File is too small to be a valid pcap (< 24 bytes).');
  }

  const dv = new DataView(buffer);

  // ── Read raw first 4 bytes for diagnosis ────────────────────────────────────
  const byte0 = dv.getUint8(0), byte1 = dv.getUint8(1),
        byte2 = dv.getUint8(2), byte3 = dv.getUint8(3);
  const rawHex = [byte0, byte1, byte2, byte3]
    .map(b => b.toString(16).padStart(2, '0')).join(' ');
  console.log(`[Sentry] First 4 bytes (raw): ${rawHex}`);

  // ── Check for pcapng magic (0x0a0d0d0a — byte-order independent) ─────────
  // The SHB block type 0x0a0d0d0a is the same in both endiannesses
  const firstWordLE = dv.getUint32(0, true);
  const firstWordBE = dv.getUint32(0, false);
  if (firstWordLE === MAGIC_PCAPNG || firstWordBE === MAGIC_PCAPNG) {
    console.log('[Sentry] PCAPNG format magic detected — delegating to parsePcapng()');
    return parsePcapng(buffer, onProgress);
  }

  // ── Detect endianness ──────────────────────────────────────────────────────
  // A classic pcap global header starts with magic number 0xa1b2c3d4.
  // If the file is little-endian, bytes on disk are: d4 c3 b2 a1
  //   → reading those 4 bytes as LE uint32 gives 0xa1b2c3d4 = MAGIC_LE
  // If the file is big-endian, bytes on disk are: a1 b2 c3 d4
  //   → reading those 4 bytes as LE uint32 gives 0xd4c3b2a1 = MAGIC_BE
  //
  // Nanosecond-resolution variants use 0xa1b23c4d (LE) / 0x4d3cb2a1 (BE)
  // but we treat them as LE/BE respectively (timestamps just happen to be ns).
  let le; // true = little-endian file
  if (firstWordLE === MAGIC_LE || firstWordLE === 0xa1b23c4d) {
    // Bytes on disk: d4 c3 b2 a1  → little-endian file
    le = true;
    console.log('[Sentry] Magic: 0xa1b2c3d4 (LE) → little-endian pcap detected, le=true');
  } else if (firstWordLE === MAGIC_BE || firstWordLE === 0x4d3cb2a1) {
    // Bytes on disk: a1 b2 c3 d4  → big-endian file
    le = false;
    console.log('[Sentry] Magic: 0xd4c3b2a1 (BE-swapped) → big-endian pcap detected, le=false');
  } else {
    console.error('[Sentry] Unrecognized magic number:', '0x' + firstWordLE.toString(16));
    throw new Error(
      `INVALID_FORMAT: Unrecognized file format (magic=0x${firstWordLE.toString(16).toUpperCase()}). Only classic .pcap files are supported.`
    );
  }

  const r16 = (o) => dv.getUint16(o, le);
  const r32 = (o) => dv.getUint32(o, le);

  // ── Global header (24 bytes) ───────────────────────────────────────────────
  const globalHeader = {
    magic:        r32(0),
    versionMajor: r16(4),
    versionMinor: r16(6),
    thiszone:     dv.getInt32(8, le),
    sigfigs:      r32(12),
    snaplen:      r32(16),
    linktype:     r32(20),
  };

  console.log('[Sentry] Global header:', {
    magic: '0x' + globalHeader.magic.toString(16),
    version: `${globalHeader.versionMajor}.${globalHeader.versionMinor}`,
    snaplen: globalHeader.snaplen,
    linktype: globalHeader.linktype,
  });

  if (globalHeader.linktype !== 1) {
    console.warn(`[Sentry] Link type ${globalHeader.linktype} — only Ethernet (1) is fully dissected; other fields may be empty`);
  }

  // Clamp snaplen: 0 means unlimited in some tools; cap at 256 KiB
  const maxPacketLen = (globalHeader.snaplen > 0 && globalHeader.snaplen <= 262144)
    ? globalHeader.snaplen
    : 262144;

  // ── Packet record loop ─────────────────────────────────────────────────────
  const packets = [];
  let offset = 24; // global header is 24 bytes
  const totalBytes = buffer.byteLength;
  let lastProgressPct = 0;

  while (offset + 16 <= totalBytes) {
    const tsSec   = r32(offset);
    const tsUsec  = r32(offset + 4);
    const inclLen = r32(offset + 8);  // captured bytes in this record
    const origLen = r32(offset + 12); // original length on wire

    offset += 16; // advance past record header

    // Sanity-check inclLen before slicing
    if (inclLen > maxPacketLen) {
      console.warn(`[Sentry] Packet at offset ${offset - 16}: inclLen=${inclLen} exceeds maxPacketLen=${maxPacketLen} — skipping record (possible corrupt/wrong-endian read)`);
      break;
    }
    if (offset + inclLen > totalBytes) {
      console.warn(`[Sentry] Truncated packet record at offset ${offset} (need ${inclLen} bytes, only ${totalBytes - offset} remain) — stopping`);
      break;
    }

    const packetData = buffer.slice(offset, offset + inclLen);
    offset += inclLen;

    const parsed = parsePacket(packetData, tsSec, tsUsec, inclLen, origLen, le);
    packets.push(parsed);

    // Progress callback every ~2%
    const pct = Math.floor((offset / totalBytes) * 100);
    if (pct >= lastProgressPct + 2) {
      lastProgressPct = pct;
      onProgress && onProgress(pct);
    }
  }

  onProgress && onProgress(100);
  console.log(`[Sentry] Parsing complete — ${packets.length} packets read`);

  // ── Build stats ────────────────────────────────────────────────────────────
  const stats = buildStats(packets, globalHeader);

  return { globalHeader, packets, stats };
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-packet dissection
// ─────────────────────────────────────────────────────────────────────────────

function parsePacket(buffer, tsSec, tsUsec, inclLen, origLen, fileLE) {
  const pkt = {
    tsSec,
    tsUsec,
    timestamp: tsSec + tsUsec / 1e6,
    inclLen,
    origLen,
    // Ethernet
    ethSrc: null,
    ethDst: null,
    ethertype: null,
    // ARP
    arp: null,
    // IPv4
    ipSrc: null,
    ipDst: null,
    ipProto: null,
    ipTTL: null,
    ipTotalLen: null,
    // Transport
    srcPort: null,
    dstPort: null,
    tcpFlags: null,
    icmpType: null,
    icmpCode: null,
    // UDP/TCP payload length
    payloadLen: 0,
  };

  if (buffer.byteLength < 14) return pkt;

  const dv = new DataView(buffer);
  const r16 = (o) => dv.getUint16(o, false); // network byte order = big-endian
  const r32 = (o) => dv.getUint32(o, false);

  // ── Ethernet II ───────────────────────────────────────────────────────────
  pkt.ethDst = macBytes(dv, 0);
  pkt.ethSrc = macBytes(dv, 6);
  let ethertype = r16(12);
  let ethPayloadOffset = 14;

  // Handle 802.1Q VLAN tag
  if (ethertype === ETHERTYPE_VLAN) {
    if (buffer.byteLength < 18) return pkt;
    ethertype = r16(16);
    ethPayloadOffset = 18;
  }
  pkt.ethertype = ethertype;

  // ── ARP ───────────────────────────────────────────────────────────────────
  if (ethertype === ETHERTYPE_ARP) {
    if (buffer.byteLength < ethPayloadOffset + 28) return pkt;
    const ao = ethPayloadOffset;
    pkt.arp = {
      htype:      r16(ao),
      ptype:      r16(ao + 2),
      opcode:     r16(ao + 6),
      senderMAC:  macBytes(dv, ao + 8),
      senderIP:   ipStr(dv, ao + 14),
      targetMAC:  macBytes(dv, ao + 18),
      targetIP:   ipStr(dv, ao + 24),
    };
    pkt.ipSrc = pkt.arp.senderIP;
    pkt.ipDst = pkt.arp.targetIP;
    return pkt;
  }

  // ── IPv4 ──────────────────────────────────────────────────────────────────
  if (ethertype !== ETHERTYPE_IPV4) return pkt;
  if (buffer.byteLength < ethPayloadOffset + 20) return pkt;

  const io = ethPayloadOffset;
  const ihl = (dv.getUint8(io) & 0x0f) * 4;
  pkt.ipTotalLen = r16(io + 2);
  pkt.ipProto    = dv.getUint8(io + 9);
  pkt.ipTTL      = dv.getUint8(io + 8);
  pkt.ipSrc      = ipStr(dv, io + 12);
  pkt.ipDst      = ipStr(dv, io + 16);

  const transportOffset = io + ihl;

  // ── TCP ───────────────────────────────────────────────────────────────────
  if (pkt.ipProto === PROTO_TCP) {
    if (buffer.byteLength < transportOffset + 20) return pkt;
    pkt.srcPort  = r16(transportOffset);
    pkt.dstPort  = r16(transportOffset + 2);
    const dataOffset = ((dv.getUint8(transportOffset + 12) >> 4) & 0xf) * 4;
    pkt.tcpFlags = dv.getUint8(transportOffset + 13);
    pkt.payloadLen = Math.max(0,
      (pkt.ipTotalLen || 0) - ihl - dataOffset);
  }

  // ── UDP ───────────────────────────────────────────────────────────────────
  else if (pkt.ipProto === PROTO_UDP) {
    if (buffer.byteLength < transportOffset + 8) return pkt;
    pkt.srcPort    = r16(transportOffset);
    pkt.dstPort    = r16(transportOffset + 2);
    const udpLen   = r16(transportOffset + 4);
    pkt.payloadLen = Math.max(0, udpLen - 8);
  }

  // ── ICMP ──────────────────────────────────────────────────────────────────
  else if (pkt.ipProto === PROTO_ICMP) {
    if (buffer.byteLength < transportOffset + 4) return pkt;
    pkt.icmpType = dv.getUint8(transportOffset);
    pkt.icmpCode = dv.getUint8(transportOffset + 1);
  }

  return pkt;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function macBytes(dv, offset) {
  return Array.from({ length: 6 }, (_, i) =>
    dv.getUint8(offset + i).toString(16).padStart(2, '0')
  ).join(':');
}

function ipStr(dv, offset) {
  return `${dv.getUint8(offset)}.${dv.getUint8(offset+1)}.${dv.getUint8(offset+2)}.${dv.getUint8(offset+3)}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stats aggregation
// ─────────────────────────────────────────────────────────────────────────────

function buildStats(packets, globalHeader) {
  if (packets.length === 0) {
    return {
      totalPackets: 0, duration: 0, uniqueHosts: 0,
      protocolCounts: {}, topSrcIPs: [], topDstPorts: [],
      timelineBuckets: [], firstTs: 0, lastTs: 0,
    };
  }

  const firstTs = packets[0].timestamp;
  const lastTs  = packets[packets.length - 1].timestamp;
  const duration = Math.max(lastTs - firstTs, 0.001);

  // Protocol counts
  const protoCounts = { TCP: 0, UDP: 0, ICMP: 0, ARP: 0, Other: 0 };
  const srcIPMap   = {};
  const dstPortMap = {};
  const hostSet    = new Set();
  const flowBytes  = {}; // "src->dst" => bytes

  for (const p of packets) {
    // Protocol
    if (p.arp)            protoCounts.ARP++;
    else if (p.ipProto === PROTO_TCP)  protoCounts.TCP++;
    else if (p.ipProto === PROTO_UDP)  protoCounts.UDP++;
    else if (p.ipProto === PROTO_ICMP) protoCounts.ICMP++;
    else                               protoCounts.Other++;

    // IPs
    if (p.ipSrc) { hostSet.add(p.ipSrc); srcIPMap[p.ipSrc]  = (srcIPMap[p.ipSrc]  || 0) + 1; }
    if (p.ipDst) { hostSet.add(p.ipDst); }

    // Ports
    if (p.dstPort != null) dstPortMap[p.dstPort] = (dstPortMap[p.dstPort] || 0) + 1;

    // Flow bytes
    if (p.ipSrc && p.ipDst) {
      const key = `${p.ipSrc}->${p.ipDst}`;
      flowBytes[key] = (flowBytes[key] || 0) + (p.inclLen || 0);
    }
  }

  // Timeline: 1-second buckets
  const bucketCount = Math.max(Math.ceil(duration) + 1, 1);
  const timelineBuckets = new Array(bucketCount).fill(0);
  for (const p of packets) {
    const bucket = Math.min(Math.floor(p.timestamp - firstTs), bucketCount - 1);
    timelineBuckets[bucket]++;
  }

  // Top src IPs
  const topSrcIPs = Object.entries(srcIPMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15)
    .map(([ip, count]) => ({ ip, count }));

  // Top dst ports
  const topDstPorts = Object.entries(dstPortMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15)
    .map(([port, count]) => ({ port: Number(port), count }));

  return {
    totalPackets: packets.length,
    duration,
    uniqueHosts: hostSet.size,
    protocolCounts: protoCounts,
    topSrcIPs,
    topDstPorts,
    timelineBuckets,
    firstTs,
    lastTs,
    flowBytes,
    linktype: globalHeader.linktype,
    snaplen:  globalHeader.snaplen,
  };
}

/**
 * Parse a PCAPNG format ArrayBuffer.
 * Parses SHB (0x0A0D0D0A), IDB (0x00000001), and EPB (0x00000006) blocks.
 */
export function parsePcapng(buffer, onProgress) {
  console.log('[Sentry] parsePcapng() called — buffer size:', buffer.byteLength, 'bytes');

  const dv = new DataView(buffer);
  let offset = 0;
  let le = true; // default little endian

  const packets = [];
  let globalHeader = { linktype: 1, snaplen: 65535, versionMajor: 1, versionMinor: 0 };
  const totalBytes = buffer.byteLength;

  while (offset + 8 <= totalBytes) {
    const blockType = dv.getUint32(offset, true);
    let blockLen = dv.getUint32(offset + 4, true);

    // If blockType === 0x0A0D0D0A (Section Header Block)
    if (blockType === 0x0A0D0D0A || dv.getUint32(offset, false) === 0x0A0D0D0A) {
      // Byte Order Magic at offset + 8: 0x1A2B3C4D
      const bomLE = dv.getUint32(offset + 8, true);
      if (bomLE === 0x1A2B3C4D) {
        le = true;
      } else {
        le = false;
      }
      blockLen = dv.getUint32(offset + 4, le);
    } else {
      blockLen = dv.getUint32(offset + 4, le);
    }

    if (blockLen < 12 || offset + blockLen > totalBytes) {
      break; // Safe exit on EOF or corrupt block length
    }

    // Enhanced Packet Block (EPB - 0x00000006)
    const typeLE = dv.getUint32(offset, le);
    if (typeLE === 0x00000006 && blockLen >= 32) {
      const tsHigh = dv.getUint32(offset + 12, le);
      const tsLow  = dv.getUint32(offset + 16, le);
      const inclLen = dv.getUint32(offset + 20, le);
      const origLen = dv.getUint32(offset + 24, le);

      const timestamp = (tsHigh * 4294967296 + tsLow) / 1000000.0;
      const pktDataOffset = offset + 28;

      if (pktDataOffset + inclLen <= totalBytes) {
        const pktBytes = new Uint8Array(buffer, pktDataOffset, inclLen);
        // parsePacket expects (buffer, tsSec, tsUsec, inclLen, origLen, fileLE)
        const tsSec = Math.floor(timestamp);
        const tsUsec = Math.round((timestamp - tsSec) * 1e6);
        const parsedPkt = parsePacket(pktBytes, tsSec, tsUsec, inclLen, origLen, le);
        packets.push(parsedPkt);
      }
    }

    // Advance to next block (aligned to 32-bit boundary)
    const padding = (4 - (blockLen % 4)) % 4;
    offset += blockLen + padding;
  }

  const stats = buildStats(packets, globalHeader);
  return { globalHeader, packets, stats };
}
