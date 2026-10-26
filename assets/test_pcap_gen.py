#!/usr/bin/env python3
"""
Sentry Console — Synthetic Test PCAP Generator
Generates a classic libpcap-format .pcap file containing:
  1. Normal HTTP + DNS traffic (baseline)
  2. Port scan attack  (src=10.0.0.99 → dst=192.168.1.1, 40 ports)
  3. SYN flood attack  (src=10.0.0.50 → dst=192.168.1.10, 200 SYNs)
  4. ARP spoofing      (2 MACs claiming 192.168.1.1)
  5. ICMP flood        (src=10.0.0.77 → dst=192.168.1.20, 80 pings)
  6. SSH brute force   (src=10.0.0.30 → dst=192.168.1.5, port 22, 25 SYNs)

Requires only Python stdlib (struct, random).
Run: python3 test_pcap_gen.py
Output: test_attack.pcap
"""

import struct
import random
import os

# ─── PCAP format helpers ──────────────────────────────────────────────────────

PCAP_MAGIC_LE   = 0xa1b2c3d4
PCAP_VERSION    = (2, 4)
LINK_ETHERNET   = 1

def pcap_global_header():
    """24-byte global header, little-endian."""
    return struct.pack('<IHHiIII',
        PCAP_MAGIC_LE,   # magic
        2, 4,            # version major/minor
        0,               # thiszone (UTC)
        0,               # sigfigs
        65535,           # snaplen
        LINK_ETHERNET,   # linktype
    )

def pcap_packet_record(ts_sec, ts_usec, data):
    """16-byte record header + data, little-endian."""
    return struct.pack('<IIII',
        ts_sec, ts_usec,
        len(data), len(data),
    ) + data

# ─── Layer builders ───────────────────────────────────────────────────────────

def mac(s):
    return bytes(int(x, 16) for x in s.split(':'))

def ip4(s):
    return bytes(int(x) for x in s.split('.'))

def eth_frame(dst_mac, src_mac, ethertype, payload):
    return mac(dst_mac) + mac(src_mac) + struct.pack('!H', ethertype) + payload

def ipv4_packet(src_ip, dst_ip, proto, payload, ttl=64):
    total_len = 20 + len(payload)
    header_no_csum = struct.pack('!BBHHHBBH4s4s',
        0x45,         # version + IHL
        0,            # DSCP/ECN
        total_len,
        random.randint(1, 65535),  # ID
        0x40 << 8,    # flags: DF, frag offset 0
        ttl,
        proto,
        0,            # checksum (0 = unchecked, fine for test)
        ip4(src_ip),
        ip4(dst_ip),
    )
    return header_no_csum + payload

def tcp_segment(src_port, dst_port, flags, seq=None, ack=0):
    """Minimal TCP header, no payload."""
    if seq is None:
        seq = random.randint(1000, 2**32 - 1)
    # flags byte: FIN=1 SYN=2 RST=4 PSH=8 ACK=16
    return struct.pack('!HHIIBBHHH',
        src_port, dst_port,
        seq, ack,
        0x50,   # data offset = 5 (20 bytes), reserved = 0
        flags,
        65535,  # window
        0,      # checksum (unchecked)
        0,      # urgent pointer
    )

def udp_datagram(src_port, dst_port, payload=b'\x00' * 12):
    length = 8 + len(payload)
    return struct.pack('!HHHH', src_port, dst_port, length, 0) + payload

def icmp_echo(seq=1):
    return struct.pack('!BBHHH', 8, 0, 0, 0x1234, seq)  # type=8 echo request

def arp_reply(sender_mac, sender_ip, target_mac, target_ip):
    return struct.pack('!HHBBH',
        1,     # HTYPE ethernet
        0x0800, # PTYPE IPv4
        6,     # HLEN
        4,     # PLEN
        2,     # OPCODE reply
    ) + mac(sender_mac) + ip4(sender_ip) + mac(target_mac) + ip4(target_ip)

# ─── Packet factory ────────────────────────────────────────────────────────────

ATTACKER_MAC  = 'aa:bb:cc:dd:ee:ff'
VICTIM_MAC    = '11:22:33:44:55:66'
SCANNER_MAC   = 'de:ad:be:ef:00:01'
BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'

FLAG_SYN     = 0x02
FLAG_SYN_ACK = 0x12
FLAG_ACK     = 0x10
FLAG_RST     = 0x04

def make_pkt(ts_sec, ts_usec, eth_data):
    return (ts_sec, ts_usec, eth_data)

def write_pcap(filename, packets):
    with open(filename, 'wb') as f:
        f.write(pcap_global_header())
        for (ts_sec, ts_usec, data) in packets:
            f.write(pcap_packet_record(ts_sec, ts_usec, data))
    print(f"[+] Wrote {len(packets)} packets to {filename}")
    print(f"    Size: {os.path.getsize(filename):,} bytes")

# ─── Build scenario ────────────────────────────────────────────────────────────

def build_packets():
    pkts = []
    t = 0.0  # seconds into capture

    def P(eth_data, ts_delta=0.01):
        nonlocal t
        ts_s = int(t)
        ts_us = int((t - ts_s) * 1_000_000)
        pkts.append(make_pkt(ts_s, ts_us, eth_data))
        t += ts_delta

    # ── 1. Normal baseline traffic (t=0..4s) ──────────────────────────────────
    print("[*] Generating normal baseline traffic…")
    for _ in range(30):
        # HTTP GET (TCP ACK with payload direction)
        P(eth_frame(VICTIM_MAC, ATTACKER_MAC, 0x0800,
            ipv4_packet('192.168.1.100', '93.184.216.34', 6,
                tcp_segment(random.randint(1024,65535), 80, FLAG_ACK))))

    for _ in range(20):
        # DNS query
        P(eth_frame(VICTIM_MAC, ATTACKER_MAC, 0x0800,
            ipv4_packet('192.168.1.100', '8.8.8.8', 17,
                udp_datagram(random.randint(1024,65535), 53, b'\x00'*20))))

    # ── 2. PORT SCAN (t=4..6s) ────────────────────────────────────────────────
    # 10.0.0.99 → 192.168.1.1, 40 distinct ports in ~2s
    print("[*] Generating port scan (40 ports, 2s window)…")
    ports = list(range(20, 60))
    for port in ports:
        P(eth_frame(VICTIM_MAC, SCANNER_MAC, 0x0800,
            ipv4_packet('10.0.0.99', '192.168.1.1', 6,
                tcp_segment(random.randint(40000,60000), port, FLAG_SYN))),
          ts_delta=0.05)

    # A few RST responses
    for port in ports[:5]:
        P(eth_frame(SCANNER_MAC, VICTIM_MAC, 0x0800,
            ipv4_packet('192.168.1.1', '10.0.0.99', 6,
                tcp_segment(port, random.randint(40000,60000), FLAG_RST))),
          ts_delta=0.02)

    # ── 3. SYN FLOOD (t=6..7s) ────────────────────────────────────────────────
    # 10.0.0.50 → 192.168.1.10, 200 SYNs, only 4 SYN-ACKs
    print("[*] Generating SYN flood (200 SYNs → 192.168.1.10)…")
    for i in range(200):
        P(eth_frame(VICTIM_MAC, ATTACKER_MAC, 0x0800,
            ipv4_packet(f'10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}',
                '192.168.1.10', 6,
                tcp_segment(random.randint(1024,65535), 80, FLAG_SYN))),
          ts_delta=0.005)

    # Only 4 SYN-ACK responses
    for _ in range(4):
        P(eth_frame(ATTACKER_MAC, VICTIM_MAC, 0x0800,
            ipv4_packet('192.168.1.10', '10.0.0.50', 6,
                tcp_segment(80, random.randint(1024,65535), FLAG_SYN_ACK))),
          ts_delta=0.01)

    # ── 4. ARP SPOOFING (t=8s) ────────────────────────────────────────────────
    # Two different MACs claim 192.168.1.1
    print("[*] Generating ARP spoofing (2 MACs → 192.168.1.1)…")
    mac_legit  = '11:22:33:44:55:01'
    mac_spoof  = 'de:ad:be:ef:13:37'

    # Legit ARP reply
    P(eth_frame(BROADCAST_MAC, mac_legit, 0x0806,
        arp_reply(mac_legit, '192.168.1.1', '00:00:00:00:00:00', '192.168.1.100')))

    # Spoofed ARP reply (different MAC, same IP)
    P(eth_frame(BROADCAST_MAC, mac_spoof, 0x0806,
        arp_reply(mac_spoof, '192.168.1.1', '00:00:00:00:00:00', '192.168.1.100')))

    # More spoofed replies to simulate ongoing poisoning
    for _ in range(8):
        P(eth_frame(BROADCAST_MAC, mac_spoof, 0x0806,
            arp_reply(mac_spoof, '192.168.1.1', '00:00:00:00:00:00', '192.168.1.100')),
          ts_delta=0.1)

    # ── 5. ICMP FLOOD (t=9..10s) ──────────────────────────────────────────────
    # 10.0.0.77 → 192.168.1.20, 80 echo requests in 1s
    print("[*] Generating ICMP flood (80 pings/s → 192.168.1.20)…")
    for i in range(80):
        P(eth_frame(VICTIM_MAC, ATTACKER_MAC, 0x0800,
            ipv4_packet('10.0.0.77', '192.168.1.20', 1,
                icmp_echo(seq=i))),
          ts_delta=0.012)

    # ── 6. SSH BRUTE FORCE (t=10..15s) ────────────────────────────────────────
    # 10.0.0.30 → 192.168.1.5:22, 25 SYN attempts
    print("[*] Generating SSH brute force (25 attempts → port 22)…")
    for i in range(25):
        P(eth_frame(VICTIM_MAC, ATTACKER_MAC, 0x0800,
            ipv4_packet('10.0.0.30', '192.168.1.5', 6,
                tcp_segment(random.randint(40000,60000), 22, FLAG_SYN))),
          ts_delta=0.2)

    print(f"[+] Total packets in scenario: {len(pkts)}")
    return pkts

# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    OUT = os.path.join(os.path.dirname(__file__), 'test_attack.pcap')
    packets = build_packets()
    write_pcap(OUT, packets)
    print()
    print("Expected Sentry Console detections:")
    print("  [HIGH/CRITICAL] Port Scan Detected       — 10.0.0.99 → 192.168.1.1")
    print("  [CRITICAL]      TCP SYN Flood             — * → 192.168.1.10")
    print("  [CRITICAL]      ARP Spoofing              — de:ad:be:ef:13:37 → 192.168.1.1")
    print("  [HIGH]          ICMP Flood                — 10.0.0.77 → 192.168.1.20")
    print("  [HIGH/MEDIUM]   Brute Force SSH           — 10.0.0.30 → 192.168.1.5:22")
    print()
    print(f"Open index.html in a browser and drop: {OUT}")
