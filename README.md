# Sentry Console — PCAP Threat Analyzer

A fully client-side network threat analysis tool. Drop a `.pcap` capture file and get automatic detection of port scans, SYN floods, brute force, ARP spoofing, DNS tunneling, data exfiltration, and ICMP floods — with interactive charts, a network flow diagram, and an exportable Markdown report.

**Everything runs in your browser. No data ever leaves your machine.**

---

## Running the App

> ⚠️ **Do NOT open `index.html` directly via `file://`.**
>
> JavaScript ES modules (`import`/`export`) and the File/DragEvent APIs behave inconsistently or are blocked under the `file://` protocol in most browsers. Always serve the app over HTTP.

### Quickstart (Python — no install required)

```bash
cd /path/to/pcap_analyzer
python3 -m http.server 8000
```

Then open **http://localhost:8000** in your browser.

### Alternative: Node / npx

```bash
npx serve .          # or: npx http-server -p 8000
```

---

## Supported File Formats

| Format | Support |
|---|---|
| Classic libpcap (`.pcap`, `.cap`) | ✅ Fully supported |
| pcapng (`.pcapng`) | ❌ Not supported — export from Wireshark as `.pcap` |

**To convert pcapng → pcap in Wireshark:**  
`File → Export Specified Packets → Save as type: Wireshark/tcpdump/... - pcap (*.pcap)`

---

## Detection Coverage

| Attack | Severity | Detection Heuristic |
|---|---|---|
| Port Scan | CRITICAL | ≥ 15 distinct dst ports from one src in any 5-second window |
| TCP SYN Flood | CRITICAL | ≥ 80 SYNs/s to one host with ≤ 30% handshake completion |
| ICMP Flood | CRITICAL/HIGH | ≥ 40 ICMP Echo Requests/s to one host |
| Brute Force | CRITICAL/HIGH | ≥ 15 SYNs from one src to a sensitive port (SSH, RDP, FTP…) |
| ARP Spoofing | CRITICAL | Same IP claimed by ≥ 2 distinct MACs in ARP replies |
| DNS Tunneling | HIGH/MEDIUM | ≥ 80 outbound DNS queries from one source |
| Data Exfiltration | HIGH/MEDIUM | Any directional flow > 512 KB |

---

## Architecture

All source files are plain ES modules — no build step required.

```
pcap_analyzer/
├── index.html          — Full landing page + dashboard shell
├── styles/
│   └── main.css        — Dark SOC theme (IBM Plex Mono + Orbitron)
└── src/
    ├── app.js           — Main controller: upload, UI, state
    ├── parser.js        — Binary PCAP parser (no deps)
    ├── detection.js     — 7 threat detectors
    ├── charts.js        — Chart.js wrappers (timeline, protocol, talkers)
    ├── network_graph.js — SVG force-directed network graph
    └── report.js        — Markdown report generator
```

---

## Privacy

- **Zero server communication.** The app makes no network requests after initial page load.
- File processing uses the browser's `FileReader` / `ArrayBuffer` APIs — all in-memory, in-browser.
- Nothing is stored, logged, or transmitted.
