# Sentry Console — Architecture & Module Documentation

Sentry Console is a modular, multi-format **Security & Threat Analysis Platform**. It combines zero-trust, privacy-preserving client-side file threat analysis with a lightweight backend for domain/network security auditing and periodic monitoring.

---

## 1. System Overview & Data Flow

```
                               ┌──────────────────────────────────────────────┐
                               │             Sentry Console UI                │
                               │  (Dual-mode Upload & Domain Input Handler)   │
                               └──────────────────────┬───────────────────────┘
                                                      │
                       ┌──────────────────────────────┴──────────────────────────────┐
                       │                                                             │
                       ▼                                                             ▼
         ┌───────────────────────────┐                                 ┌───────────────────────────┐
         │   Client-Side Analyzers   │                                 │     Backend API Service   │
         │   (100% In-Browser JS)    │                                 │     (Node.js / Express)   │
         └─────────────┬─────────────┘                                 └─────────────┬─────────────┘
                       │                                                             │
  ┌────────────────────┼────────────────────┐                               ┌────────┴────────┐
  ▼                    ▼                    ▼                               ▼                 ▼
┌───────────┐    ┌───────────┐        ┌───────────┐                   ┌───────────┐     ┌───────────┐
│ PCAP /    │    │ Document  │        │ Image /   │                   │ Domain    │     │ Scheduled │
│ PCAPNG    │    │ (PDF/DOCX)│        │ EML Mail  │                   │ Security  │     │ Monitoring│
└─────┬─────┘    └─────┬─────┘        └─────┬─────┘                   └─────┬─────┘     └─────┬─────┘
      │                │                    │                               │                 │
      └────────────────┴──────────┬─────────┘                               └────────┬────────┘
                                  │                                                  │
                                  ▼                                                  ▼
                     ┌───────────────────────────┐                      ┌───────────────────────────┐
                     │ Unified Score & Severity  │                      │   SQLite Database         │
                     │ Engine + IOC Extractor    │                      │   (Targets & History)     │
                     └─────────────┬─────────────┘                      └───────────────────────────┘
                                   │
                                   ▼
                     ┌───────────────────────────┐
                     │ PDF / Markdown Security   │
                     │ Report Export Engine      │
                     └───────────────────────────┘
```

---

## 2. Privacy & Security Boundary

| Feature Category | Execution Environment | Network Traffic | Privacy Guarantee |
|------------------|-----------------------|-----------------|-------------------|
| **PCAP / PCAPNG Analysis** | 100% In-Browser JS | Zero | File never leaves browser |
| **PDF Threat Analysis** | 100% In-Browser JS | Zero | File never leaves browser |
| **Email (.eml) Analysis** | 100% In-Browser JS | Zero | File never leaves browser |
| **Image EXIF / Stego Analysis** | 100% In-Browser JS | Zero | File never leaves browser |
| **Office Doc Analysis** | 100% In-Browser JS | Zero | File never leaves browser |
| **Generic File Hash / Magic Bytes** | 100% In-Browser JS | Zero | File never leaves browser |
| **Domain Security Audit** | Backend API Proxy | Server-side domain requests | Target domain requested by server |
| **Periodic Security Monitoring** | Backend Scheduler & SQLite | Scheduled server background jobs | Scans target domain periodically |

---

## 3. Frontend Architecture (`src/modules/`)

### 3.1 File Type Router (`src/modules/file_type_detector.js`)
Detects actual file format via binary magic bytes (not file extensions):
- `0xA1B2C3D4` / `0xD4C3B2A1` → Classic PCAP (`.pcap`, `.cap`)
- `0x0A0D0D0A` → PCAPNG (`.pcapng`)
- `%PDF-` → PDF Document (`.pdf`)
- `0xFF 0xD8 0xFF` → JPEG Image (`.jpg`, `.jpeg`)
- `0x89 0x50 0x4E 0x47` → PNG Image (`.png`)
- `GIF87a` / `GIF89a` → GIF Image (`.gif`)
- `0x50 0x4B 0x03 0x04` (`PK..`) → ZIP Container / Office Open XML (`.docx`, `.xlsx`, `.pptx`)
- RFC 822 Header Patterns → Email (`.eml`, `.msg`)
- Unknown → Generic Binary / Hash Analyzer

### 3.2 Analysis Engine Modules
- `pcap_analyzer.js`: Extracts IPv4/IPv6, TCP/UDP, ARP, ICMP frames. Detects SYN floods, port scans, brute force, ARP spoofing, DNS tunneling, exfiltration.
- `pdf_analyzer.js`: Parses cross-reference tables, stream objects, detects `/JS`, `/JavaScript`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFiles`, and stream obfuscation.
- `eml_analyzer.js`: Parses RFC 822 headers, extracts `SPF`/`DKIM`/`DMARC` verification fields, evaluates sender spoofing, extracts URLs/attachments, flags phishing heuristics.
- `image_analyzer.js`: Parses JPEG/PNG/GIF EXIF tags (GPS, camera info, software), inspects bytes after End-of-Image markers (`0xFF 0xD9`, `IEND`, `0x00 0x3B`) for hidden steganography/polyglot data.
- `office_analyzer.js`: Inspects Open XML ZIP containers for `vbaProject.bin` (macros), external target links in `.rels`, embedded OLE controls.
- `generic_analyzer.js`: Calculates MD5 / SHA-256 via Web Crypto API, inspects high-entropy blocks, extracts ASCII strings.

### 3.3 Core Shared Services
- `score_engine.js`: Calculates a unified 0-100 Security Score and standardizes findings into `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` severity buckets.
- `ioc_extractor.js`: Extracts IPs, Hostnames, URLs, Email Addresses, File Hashes across all artifact types. Evaluates typosquatting and suspicious TLD patterns. Supports optional user-provided VirusTotal API key.
- `pdf_report_generator.js`: Renders formatted SOC dark-theme downloadable PDF security reports via `jsPDF`.

---

## 4. Backend Service Architecture (`backend/`)

- **Runtime**: Node.js + Express
- **Database**: SQLite (`backend/sentry.db`)
- **Key Modules**:
  - `routes/scan.js`: Security Headers, SSL/TLS inspection, DNS records (SPF/DKIM/DMARC), Technology Fingerprinting, non-invasive vulnerability checks.
  - `routes/monitor.js`: Scheduled monitoring targets CRUD & history endpoints.
  - `services/scheduler.js`: Cron background job executor for periodic target re-scans.

---

## 5. Finding & Result Schema

Every analysis module outputs a standardized result object:

```javascript
{
  metadata: {
    targetName: "sample.pdf",
    targetType: "PDF Document",
    fileSize: 1048576,
    hashMD5: "e10adc3949ba59abbe56e057f20f883e",
    hashSHA256: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
    analysisDate: "2026-08-13T16:20:00Z",
    privacyMode: "CLIENT_SIDE_LOCAL" // or "BACKEND_NETWORK"
  },
  score: 65, // 0 to 100
  findings: [
    {
      id: "PDF-JS-01",
      title: "Embedded JavaScript Detected",
      severity: "CRITICAL", // CRITICAL, HIGH, MEDIUM, LOW, INFO
      category: "Executable Code",
      description: "PDF contains auto-executing JavaScript in /OpenAction dictionary.",
      source: "Object 14 0 R (/OpenAction)",
      recommendation: "Open PDF in isolated sandbox or strip JavaScript before viewing."
    }
  ],
  iocs: {
    ips: ["192.168.1.50"],
    domains: ["evil-domain.xyz"],
    urls: ["http://evil-domain.xyz/payload.exe"],
    emails: ["phisher@evil-domain.xyz"],
    hashes: ["8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"]
  },
  artifacts: { /* Module-specific structured data: EXIF tags, packet stats, header map */ }
}
```
