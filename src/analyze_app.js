/**
 * Sentry Console — Analyze Page Application Controller
 * Handles file drop, file type detection, running analysis engines,
 * saving result payload to sessionStorage, and routing to results.html.
 */

import { parsePcap } from './parser.js';
import { runDetections } from './detection.js';
import { detectFileType, FILE_TYPES } from './modules/file_type_detector.js';
import { analyzePdf } from './modules/pdf_analyzer.js';
import { analyzeEml } from './modules/eml_analyzer.js';
import { analyzeImage } from './modules/image_analyzer.js';
import { analyzeOfficeDoc } from './modules/office_analyzer.js';
import { analyzeGenericFile } from './modules/generic_analyzer.js';
import { calculateSecurityScore, normalizeFinding } from './modules/score_engine.js';
import { processIocs } from './modules/ioc_extractor.js';
import { saveAnalysisData, saveAnalysisPayload } from './modules/storage.js';

const $ = (id) => document.getElementById(id);
const BACKEND_URL = 'http://localhost:3001';

export function initAnalyzePage() {
  console.log('[Sentry Analyze] Wiring up Analyze Hub');
  console.warn(`[Sentry Origin] Active origin: ${window.location.origin}`);

  setupDropZone();
  setupModeSwitcher();
  setupDomainScan();
  setupUrlModeRouting();

  const errClose = $('error-close-btn');
  if (errClose) {
    errClose.addEventListener('click', () => {
      $('error-banner').style.display = 'none';
    });
  }
}

function setupUrlModeRouting() {
  const params = new URLSearchParams(window.location.search);
  const autoload = params.get('autoload');
  if (autoload) {
    showLoading(true, `Autoloading test artifact: ${autoload}...`);
    fetch(autoload)
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.arrayBuffer();
      })
      .then(buffer => {
        const fileName = autoload.split('/').pop();
        const file = new File([buffer], fileName);
        handleFile(file);
      })
      .catch(err => {
        showLoading(false);
        showError(`Failed to autoload sample artifact: ${err.message}`);
      });
    return;
  }

  const mode = params.get('mode')?.toLowerCase();
  if (!mode) return;

  const btnFile = $('btn-mode-file');
  const btnDomain = $('btn-mode-domain');

  if (mode === 'domain') {
    btnDomain?.click();
  } else if (['pcap', 'pdf', 'eml', 'img', 'doc'].includes(mode)) {
    btnFile?.click();
    const chip = document.querySelector(`.format-toggle[data-format="${mode}"]`);
    if (chip) chip.click();
  }
}

function setupModeSwitcher() {
  const btnFile = $('btn-mode-file');
  const btnDomain = $('btn-mode-domain');
  const fileDesc = $('file-mode-desc');
  const domainDesc = $('domain-mode-desc');
  const fileUploadBox = $('file-upload-box');
  const domainScanBox = $('domain-scan-box-wrap');

  btnFile?.addEventListener('click', () => {
    btnFile.classList.add('active');
    btnDomain.classList.remove('active');
    if (fileDesc) fileDesc.style.display = 'block';
    if (domainDesc) domainDesc.style.display = 'none';
    if (fileUploadBox) fileUploadBox.style.display = 'block';
    if (domainScanBox) domainScanBox.style.display = 'none';
  });

  btnDomain?.addEventListener('click', () => {
    btnDomain.classList.add('active');
    btnFile.classList.remove('active');
    if (fileDesc) fileDesc.style.display = 'none';
    if (domainDesc) domainDesc.style.display = 'block';
    if (fileUploadBox) fileUploadBox.style.display = 'none';
    if (domainScanBox) domainScanBox.style.display = 'block';
  });
}

function setupDomainScan() {
  const btnScan = $('btn-run-domain-scan');
  const domainInput = $('domain-scan-input');

  btnScan?.addEventListener('click', () => {
    const val = domainInput?.value?.trim();
    if (val) handleDomainScan(val);
  });

  domainInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const val = domainInput.value.trim();
      if (val) handleDomainScan(val);
    }
  });
}

async function handleDomainScan(url) {
  showLoading(true, `Connecting to backend server to scan domain: ${url}...`);

  try {
    const res = await fetch(`${BACKEND_URL}/api/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    if (!res.ok) {
      throw new Error(`Backend scan failed (${res.status}). Ensure backend server is running on ${BACKEND_URL}`);
    }

    const data = await res.json();
    showLoading(false);

    const findings = data.findings.map(normalizeFinding);
    const scoreInfo = calculateSecurityScore(findings);
    const iocs = processIocs(data.iocs);
    const graphData = buildGraphData([], findings, iocs);

    const resultPayload = {
      metadata: data.metadata,
      scoreInfo,
      findings,
      iocs,
      graphData,
      artifacts: data.artifacts,
      privacyMode: 'BACKEND_NETWORK'
    };

    // Save to IndexedDB (with fallbacks) and route to results.html
    console.log('[Sentry Analyze] Domain scan complete. Saving payload via Storage module...');
    try {
      await saveAnalysisPayload(resultPayload);
      console.log('[Sentry Analyze] Payload saved successfully. Navigating to results.html...');
      window.location.href = 'results.html';
    } catch (storageErr) {
      console.error('[Sentry Analyze] Storage write failed:', storageErr);
      showLoading(false);
      showError(`Storage error: ${storageErr.message}`);
    }


  } catch (err) {
    showLoading(false);
    showError(err.message || 'Failed to complete domain scan. Make sure backend server is running (node backend/server.js)');
  }
}

function setupDropZone() {
  const zone = $('drop-zone');
  const input = $('file-input');
  const browseBtn = $('browse-btn');

  if (!zone) return;

  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(evtName => {
    zone.addEventListener(evtName, (e) => {
      e.preventDefault();
      e.stopPropagation();
    });
  });

  zone.addEventListener('dragenter', () => zone.classList.add('drag-over'));
  zone.addEventListener('dragover', () => zone.classList.add('drag-over'));
  zone.addEventListener('dragleave', (e) => {
    if (!zone.contains(e.relatedTarget)) zone.classList.remove('drag-over');
  });

  zone.addEventListener('drop', (e) => {
    zone.classList.remove('drag-over');
    const file = e.dataTransfer?.files[0];
    if (file) {
      showFileChosen(file);
      handleFile(file);
    }
  });

  browseBtn?.addEventListener('click', (e) => {
    e.stopPropagation();
    input.click();
  });

  zone.addEventListener('click', (e) => {
    if (e.target !== browseBtn) input.click();
  });

  input?.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      showFileChosen(file);
      handleFile(file);
    }
  });
}

function showFileChosen(file) {
  const idle = $('drop-zone-idle');
  const chosen = $('drop-zone-chosen');
  const fname = $('chosen-filename');
  const fsize = $('chosen-size');

  if (idle) idle.style.display = 'none';
  if (chosen) chosen.style.display = 'flex';
  if (fname) fname.textContent = file.name;
  if (fsize) fsize.textContent = formatFileSize(file.size);
}

async function handleFile(file) {
  showLoading(true, 'Inspecting file header & magic bytes…');

  try {
    const buffer = await file.arrayBuffer();
    const detected = detectFileType(buffer, file.name);

    console.log('[Sentry Analyze] Detected file type:', detected);
    console.log('[Sentry Analyze] First 16 magic bytes (hex):', Array.from(new Uint8Array(buffer, 0, Math.min(buffer.byteLength, 16))).map(b => b.toString(16).padStart(2, '0')).join(' '));

    let rawResult = null;
    let targetTypeLabel = 'File Artifact';

    try {
      switch (detected.type) {
        case FILE_TYPES.PCAP:
        case FILE_TYPES.PCAPNG: {
          targetTypeLabel = detected.type === FILE_TYPES.PCAPNG ? 'Network Capture (.pcapng)' : 'Network Capture (.pcap)';
          showLoading(true, 'Parsing packet records…');
          const parsed = parsePcap(buffer);
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

          rawResult = {
            metadata: { fileName: file.name, fileSize: file.size, targetType: targetTypeLabel, privacyMode: '🔒 100% LOCAL' },
            findings: normalized,
            iocs: pcapIocs,
            _rawPackets: parsed.packets,  // kept in-memory only; NOT stored in sessionStorage
            stats: parsed.stats,
            artifacts: { packetsCount: parsed.packets.length, duration: parsed.stats.duration }
          };
          break;
        }

        case FILE_TYPES.PDF: {
          targetTypeLabel = 'PDF Document';
          showLoading(true, 'Analyzing PDF object tree & streams…');
          rawResult = analyzePdf(buffer, file.name);
          break;
        }

        case FILE_TYPES.EMAIL_EML: {
          targetTypeLabel = 'Email Message (.eml)';
          showLoading(true, 'Parsing MIME headers & DKIM/SPF authentication…');
          rawResult = analyzeEml(buffer, file.name);
          break;
        }

        case FILE_TYPES.IMAGE_JPEG:
        case FILE_TYPES.IMAGE_PNG:
        case FILE_TYPES.IMAGE_GIF: {
          targetTypeLabel = `Image Artifact (${detected.type.replace('image_', '').toUpperCase()})`;
          showLoading(true, 'Parsing EXIF tags & checking steganography payload markers…');
          rawResult = analyzeImage(buffer, file.name);
          break;
        }

        case FILE_TYPES.OFFICE_DOCX:
        case FILE_TYPES.OFFICE_OLE: {
          targetTypeLabel = 'Office Document';
          showLoading(true, 'Inspecting OpenXML archive & VBA macro streams…');
          rawResult = analyzeOfficeDoc(buffer, file.name);
          break;
        }

        default: {
          targetTypeLabel = 'Generic Binary';
          showLoading(true, 'Calculating SHA-256 hash & extracting binary strings…');
          rawResult = await analyzeGenericFile(buffer, file.name);
          break;
        }
      }
    } catch (analysisErr) {
      console.warn('[Analyze Hub] Primary analyzer encountered error, falling back to static analyzer:', analysisErr);
      try {
        const savedLabel = targetTypeLabel;
        rawResult = await analyzeGenericFile(buffer, file.name);
        rawResult.metadata.targetType = savedLabel;
        rawResult.findings.unshift({
          id: 'ANALYZER-PARTIAL-FALLBACK',
          title: `Primary ${savedLabel} Parser Warning`,
          severity: 'INFO',
          category: 'Parser Warning',
          description: `Primary parser warning: ${analysisErr.message || 'Partial parsing error'}. Static binary analysis completed successfully.`,
          source: file.name,
          recommendation: 'Review extracted static binary indicators.'
        });
      } catch (fallbackErr) {
        console.error('[Analyze Hub] Fallback generic analyzer error:', fallbackErr);
        rawResult = {
          metadata: { fileName: file.name, fileSize: file.size, targetType: targetTypeLabel, privacyMode: '🔒 100% LOCAL' },
          findings: [{
            id: 'ANALYSIS-PARSER-ERROR',
            title: 'File Analysis Warning',
            severity: 'INFO',
            category: 'System',
            description: `File analysis completed with warnings: ${fallbackErr.message || analysisErr.message}`,
            source: file.name,
            recommendation: 'Verify file integrity.'
          }],
          iocs: { ips: [], domains: [], urls: [], emails: [], hashes: [] },
          artifacts: {}
        };
      }
    }

    const processedIocs = processIocs(rawResult.iocs);
    const combinedFindings = [...rawResult.findings, ...processedIocs.findings].map(normalizeFinding);
    const scoreInfo = calculateSecurityScore(combinedFindings);

    // Pre-aggregate network graph data from raw packets (nodes + edges only).
    // This keeps the storage payload small: we never persist the full packet array.
    const graphData = buildGraphData(rawResult._rawPackets || [], combinedFindings, processedIocs.iocs || processedIocs);

    // Build a clean, aggregated stats object for storage.
    // Exclude flowBytes (which can contain thousands of entries in large files and is only needed during detection).
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

    const resultPayload = {
      metadata: rawResult.metadata,
      scoreInfo,
      findings: combinedFindings,
      iocs: processedIocs.iocs || processedIocs,
      // NOTE: packets are NOT stored. cleanStats provides authoritative counts & distributions.
      stats: cleanStats,
      graphData,                          // pre-aggregated nodes + edges for network diagram
      artifacts: rawResult.artifacts,
      privacyMode: 'CLIENT_SIDE_LOCAL'
    };

    showLoading(false);

    const packetCount = resultPayload.stats?.totalPackets ?? resultPayload.artifacts?.packetsCount ?? 0;
    console.log('[Sentry Analyze] Analysis complete. Result payload summary:', {
      fileName: resultPayload.metadata?.fileName,
      packetCount,
      findingsCount: resultPayload.findings?.length || 0,
      graphNodes: graphData.nodes?.length || 0,
      graphEdges: graphData.edges?.length || 0,
      scoreInfo: resultPayload.scoreInfo,
      hasStats: !!resultPayload.stats
    });

    // Diagnostic size logging for storage payload
    console.log('[Sentry Storage Diagnostic] resultPayload top-level keys:', Object.keys(resultPayload));
    Object.keys(resultPayload).forEach(k => {
      const fieldStr = JSON.stringify(resultPayload[k]);
      const len = fieldStr ? fieldStr.length : 0;
      console.log(`[Sentry Storage Diagnostic] Key "${k}": ${len.toLocaleString()} chars (~${(len/1024).toFixed(1)} KB)`);
    });

    // Save to IndexedDB via shared storage module and redirect ONLY after promise resolves
    let stored = false;
    try {
      await saveAnalysisData(resultPayload);
      stored = true;
      console.log('[Sentry Analyze] saveAnalysisData() promise resolved. Navigating to results.html...');
    } catch (storageErr) {
      console.warn('[Sentry Analyze] Primary storage failed, trying minimal payload:', storageErr);
      try {
        const minimalPayload = {
          metadata: resultPayload.metadata,
          scoreInfo: resultPayload.scoreInfo,
          findings: resultPayload.findings,
          iocs: resultPayload.iocs,
          stats: resultPayload.stats,
          artifacts: resultPayload.artifacts,
          privacyMode: resultPayload.privacyMode
        };
        await saveAnalysisData(minimalPayload);
        stored = true;
        console.warn('[Sentry Analyze] Minimal fallback payload saved.');
      } catch (minimalErr) {
        console.error('[Sentry Analyze] Storage failed:', minimalErr);
        showLoading(false);
        showError("Your browser doesn't support storing large analysis results — try a smaller capture or a different browser");
      }
    }

    if (stored) {
      window.location.href = 'results.html';
    }

  } catch (err) {
    console.error('[Sentry Analyze] Pipeline error:', err);
    showLoading(false);
    showError(`Analysis failed: ${err.message}`);
  }
}

/**
 * Pre-aggregate network graph node and edge data from raw packets.
 * Returns a small, serializable { nodes[], edges[] } object suitable for
 * sessionStorage — NOT the full packet array.
 * Mirrors the aggregation logic in NetworkGraph.build() so the Results page
 * can render the diagram directly from this data without needing packets.
 *
 * @param {Array} packets  - parsed packet objects (in-memory only, not stored)
 * @param {Array} findings - normalized findings (for flagged IP detection)
 * @returns {{ nodes: Array, edges: Array }}
 */
function buildGraphData(packets, findings, iocs) {
  const flaggedIPs = new Set();
  for (const f of (findings || [])) {
    if (f.src && !f.src.includes(' ')) flaggedIPs.add(f.src);
    if (f.dst && !f.dst.includes(' ')) flaggedIPs.add(f.dst);
  }

  const nodeMap = {};  // ip -> { ip, packets, bytes, flagged }
  const edgeMap = {};  // "src->dst" -> { src, dst, packets, bytes, flagged }

  if (packets && packets.length > 0) {
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
  } else {
    // Non-PCAP artifact fallback: construct nodes from findings & extracted IOC IPs
    const iocsIps = iocs?.ips || (Array.isArray(iocs) ? iocs : []);
    const ips = new Set([...flaggedIPs, ...iocsIps]);
    let prevIp = null;
    for (const ip of ips) {
      if (!ip || typeof ip !== 'string' || ip.includes(' ')) continue;
      nodeMap[ip] = { ip, packets: 10, bytes: 1000, flagged: flaggedIPs.has(ip) };
      if (prevIp && prevIp !== ip) {
        const eKey = `${prevIp}->${ip}`;
        edgeMap[eKey] = {
          src: prevIp, dst: ip,
          packets: 5, bytes: 500,
          flagged: flaggedIPs.has(prevIp) || flaggedIPs.has(ip)
        };
      }
      prevIp = ip;
    }
  }

  let nodes = Object.values(nodeMap);
  let edges = Object.values(edgeMap);

  // Limit to top 60 nodes by packet count (mirrors NetworkGraph.build limit)
  if (nodes.length > 60) {
    nodes.sort((a, b) => b.packets - a.packets);
    const kept = new Set(nodes.slice(0, 60).map(n => n.ip));
    for (const ip of flaggedIPs) kept.add(ip);
    nodes = nodes.filter(n => kept.has(n.ip));
    edges = edges.filter(e => kept.has(e.src) && kept.has(e.dst));
  }

  return { nodes, edges };
}

function showLoading(show, message = '') {
  const overlay = $('loading-overlay');
  const msgEl = $('loading-message');
  if (msgEl && message) msgEl.textContent = message;
  if (overlay) overlay.style.display = show ? 'flex' : 'none';
}

function showError(msg) {
  const banner = $('error-banner');
  const text = $('error-text');
  if (text) text.textContent = msg;
  if (banner) banner.style.display = 'flex';
}

function formatFileSize(bytes) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}
