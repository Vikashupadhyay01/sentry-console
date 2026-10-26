import fs from 'fs';
import path from 'path';

/**
 * Generate a synthetic binary .pcap file containing all 7 attack categories:
 * 1. Port Scan
 * 2. SYN Flood
 * 3. ICMP Flood
 * 4. Brute Force
 * 5. ARP Spoofing
 * 6. DNS Amplification / Tunneling
 * 7. Data Exfiltration
 */

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
  dv.setUint16(12, ethertype, false); // Big endian network byte order
  return buf;
}

function buildIpHeader(srcIp, dstIp, proto, payloadLen) {
  const buf = new Uint8Array(20);
  buf[0] = 0x45; // IPv4, IHL=5
  buf[1] = 0x00; // DSCP
  const dv = new DataView(buf.buffer);
  dv.setUint16(2, 20 + payloadLen, false);
  dv.setUint16(4, 0x1234, false);
  dv.setUint16(6, 0x4000, false); // Don't fragment
  buf[8] = 64; // TTL
  buf[9] = proto;
  buf.set(parseIp(srcIp), 12);
  buf.set(parseIp(dstIp), 16);
  return buf;
}

function buildTcpPacket(srcIp, dstIp, srcPort, dstPort, flags, payload = new Uint8Array(0)) {
  const eth = buildEthHeader('00:11:22:33:44:55', '66:77:88:99:AA:BB', 0x0800);
  const tcpLen = 20 + payload.length;
  const ip = buildIpHeader(srcIp, dstIp, 6, tcpLen);

  const tcp = new Uint8Array(20 + payload.length);
  const dv = new DataView(tcp.buffer);
  dv.setUint16(0, srcPort, false);
  dv.setUint16(2, dstPort, false);
  dv.setUint32(4, 1000, false); // seq
  dv.setUint32(8, 0, false);    // ack
  tcp[12] = (5 << 4);           // data offset 5 (20 bytes)
  tcp[13] = flags;
  dv.setUint16(14, 64240, false); // window
  if (payload.length > 0) {
    tcp.set(payload, 20);
  }

  const pkt = new Uint8Array(eth.length + ip.length + tcp.length);
  pkt.set(eth, 0);
  pkt.set(ip, eth.length);
  pkt.set(tcp, eth.length + ip.length);
  return pkt;
}

function buildIcmpPacket(srcIp, dstIp, type = 8, code = 0) {
  const eth = buildEthHeader('00:11:22:33:44:55', '66:77:88:99:AA:BB', 0x0800);
  const icmp = new Uint8Array(8);
  icmp[0] = type;
  icmp[1] = code;
  const ip = buildIpHeader(srcIp, dstIp, 1, icmp.length);

  const pkt = new Uint8Array(eth.length + ip.length + icmp.length);
  pkt.set(eth, 0);
  pkt.set(ip, eth.length);
  pkt.set(icmp, eth.length + ip.length);
  return pkt;
}

function buildArpReply(senderMac, senderIp, targetMac, targetIp) {
  const eth = buildEthHeader(senderMac, 'FF:FF:FF:FF:FF:FF', 0x0806);
  const arp = new Uint8Array(28);
  const dv = new DataView(arp.buffer);
  dv.setUint16(0, 1, false);     // Ethernet
  dv.setUint16(2, 0x0800, false);// IPv4
  arp[4] = 6;
  arp[5] = 4;
  dv.setUint16(6, 2, false);     // ARP Reply
  arp.set(parseMac(senderMac), 8);
  arp.set(parseIp(senderIp), 14);
  arp.set(parseMac(targetMac), 18);
  arp.set(parseIp(targetIp), 24);

  const pkt = new Uint8Array(eth.length + arp.length);
  pkt.set(eth, 0);
  pkt.set(arp, eth.length);
  return pkt;
}

function buildDnsPacket(srcIp, dstIp, srcPort, dstPort, queryDomain) {
  const eth = buildEthHeader('00:11:22:33:44:55', '66:77:88:99:AA:BB', 0x0800);

  // Simple DNS payload
  const dnsParts = [];
  queryDomain.split('.').forEach(part => {
    dnsParts.push(part.length);
    for (let i = 0; i < part.length; i++) dnsParts.push(part.charCodeAt(i));
  });
  dnsParts.push(0); // end of qname
  dnsParts.push(0, 1); // TYPE A
  dnsParts.push(0, 1); // CLASS IN

  const dnsPayload = new Uint8Array(12 + dnsParts.length);
  const dvDns = new DataView(dnsPayload.buffer);
  dvDns.setUint16(0, 0x1234, false); // Transaction ID
  dvDns.setUint16(2, 0x0100, false); // Flags: Standard Query
  dvDns.setUint16(4, 1, false);      // Questions: 1
  dnsPayload.set(new Uint8Array(dnsParts), 12);

  const udp = new Uint8Array(8 + dnsPayload.length);
  const dvUdp = new DataView(udp.buffer);
  dvUdp.setUint16(0, srcPort, false);
  dvUdp.setUint16(2, dstPort, false);
  dvUdp.setUint16(4, 8 + dnsPayload.length, false);
  udp.set(dnsPayload, 8);

  const ip = buildIpHeader(srcIp, dstIp, 17, udp.length);

  const pkt = new Uint8Array(eth.length + ip.length + udp.length);
  pkt.set(eth, 0);
  pkt.set(ip, eth.length);
  pkt.set(udp, eth.length + ip.length);
  return pkt;
}

const records = [createPcapHeader()];
let baseTs = 1700000000;

// 1. Port Scan: 35 distinct ports within 5s from 192.168.1.100 -> 10.0.0.1
console.log('Generating Port Scan packets...');
for (let p = 1; p <= 35; p++) {
  const pkt = buildTcpPacket('192.168.1.100', '10.0.0.1', 50000 + p, p, 0x02); // SYN
  records.push(createPcapRecord(pkt, baseTs + 1, p * 10000));
}

// 2. SYN Flood: 100 SYN packets in 1 second from 192.168.1.101 -> 10.0.0.1:80
console.log('Generating SYN Flood packets...');
for (let i = 0; i < 100; i++) {
  const pkt = buildTcpPacket('192.168.1.101', '10.0.0.1', 40000 + i, 80, 0x02);
  records.push(createPcapRecord(pkt, baseTs + 2, i * 5000));
}

// 3. ICMP Flood: 120 ICMP Echo Requests in 1s from 192.168.1.102 -> 10.0.0.1
console.log('Generating ICMP Flood packets...');
for (let i = 0; i < 120; i++) {
  const pkt = buildIcmpPacket('192.168.1.102', '10.0.0.1', 8, 0);
  records.push(createPcapRecord(pkt, baseTs + 3, i * 4000));
}

// 4. Brute Force: 25 SSH attempts (port 22) from 192.168.1.103 -> 10.0.0.1
console.log('Generating Brute Force SSH packets...');
for (let i = 0; i < 25; i++) {
  const pkt = buildTcpPacket('192.168.1.103', '10.0.0.1', 30000 + i, 22, 0x02);
  records.push(createPcapRecord(pkt, baseTs + 4, i * 20000));
}

// 5. ARP Spoofing: MAC 00:11:22:33:44:55 and AA:BB:CC:DD:EE:FF both claiming 10.0.0.1
console.log('Generating ARP Spoofing packets...');
for (let i = 0; i < 3; i++) {
  const pkt1 = buildArpReply('00:11:22:33:44:55', '10.0.0.1', '66:77:88:99:AA:BB', '192.168.1.50');
  const pkt2 = buildArpReply('AA:BB:CC:DD:EE:FF', '10.0.0.1', '66:77:88:99:AA:BB', '192.168.1.50');
  records.push(createPcapRecord(pkt1, baseTs + 5, i * 100000));
  records.push(createPcapRecord(pkt2, baseTs + 5, i * 100000 + 50000));
}

// 6. DNS Tunneling & Amplification: DNS queries to suspicious high-entropy subdomains
console.log('Generating DNS Tunneling & Amplification packets...');
const dnsDomains = [
  'a3f9e1b2c4d5e6f7a8b9c0.exfil.evil-domain.xyz',
  'b8d7e6f5c4b3a210987654.data.attacker-c2.top',
  'c9e8d7c6b5a49876543210.tunnel.malware-stego.click'
];
for (let i = 0; i < 15; i++) {
  const domain = dnsDomains[i % dnsDomains.length];
  const pkt = buildDnsPacket('192.168.1.104', '8.8.8.8', 53535 + i, 53, domain);
  records.push(createPcapRecord(pkt, baseTs + 6, i * 30000));
}

// 7. Data Exfiltration: Large TCP payload (1.2 MB data stream in TCP segments)
console.log('Generating Data Exfiltration packets...');
const largePayload = new Uint8Array(1400);
for (let b = 0; b < 1400; b++) largePayload[b] = (b % 256);

for (let seg = 0; seg < 900; seg++) { // ~1.26 MB
  const pkt = buildTcpPacket('192.168.1.105', '45.33.32.156', 49152, 443, 0x18, largePayload); // PSH, ACK
  records.push(createPcapRecord(pkt, baseTs + 7 + Math.floor(seg / 200), (seg % 200) * 5000));
}

// Combine all record buffers
const totalSize = records.reduce((sum, r) => sum + r.length, 0);
const finalBuf = new Uint8Array(totalSize);
let offset = 0;
for (const r of records) {
  finalBuf.set(r, offset);
  offset += r.length;
}

const outPath1 = path.join(process.cwd(), 'tests', 'samples', 'all_attacks_demo.pcap');
const outPath2 = path.join(process.cwd(), 'test.pcap');

fs.writeFileSync(outPath1, finalBuf);
fs.writeFileSync(outPath2, finalBuf);

console.log(`\nSuccessfully created synthetic PCAP with all 7 attack vectors!`);
console.log(`Saved to: ${outPath1} (${finalBuf.length} bytes)`);
console.log(`Saved to: ${outPath2} (${finalBuf.length} bytes)`);
