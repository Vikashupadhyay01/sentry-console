/**
 * Sentry Console — Main Application Controller (Platform Edition)
 * Wires together client-side multi-format threat analyzers (PCAP, PDF, EML, Images, Office Docs, Generic),
 * backend domain security scans, universal Security Score engine, IOC extraction, PDF reporting, and scheduled monitoring.
 */

import { parsePcap } from './parser.js';
import { runDetections } from './detection.js';
import { renderTimeline, renderProtocolChart, renderTopTalkersChart, destroyAllCharts } from './charts.js';
import { NetworkGraph } from './network_graph.js';
import { detectFileType, FILE_TYPES } from './modules/file_type_detector.js';
import { analyzePdf } from './modules/pdf_analyzer.js';
import { analyzeEml } from './modules/eml_analyzer.js';
import { analyzeImage } from './modules/image_analyzer.js';
import { analyzeOfficeDoc } from './modules/office_analyzer.js';
import { analyzeGenericFile } from './modules/generic_analyzer.js';
import { calculateSecurityScore, normalizeFinding } from './modules/score_engine.js';
import { processIocs } from './modules/ioc_extractor.js';
import { exportPdfReport } from './modules/pdf_report_generator.js';

// ─── Application State ────────────────────────────────────────────────────────

let state = {
  filename: null,
  fileTypeInfo: null,
  analysisResult: null,
  packets:  [],
  stats:    null,
  findings: [],
  scoreInfo: null,
  iocs: null,
  networkGraph: null,
  suspiciousIPs: new Set(),
  privacyMode: 'CLIENT_SIDE_LOCAL'
};

const $ = (id) => document.getElementById(id);
const BACKEND_URL = (['localhost','127.0.0.1'].includes(location.hostname) && location.port !== '3001') ? 'http://localhost:3001' : '';

// ─── Init ─────────────────────────────────────────────────────────────────────

export function init() {
  console.log('[Sentry Platform] init() called — wiring up UI and modules');

  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop',     (e) => e.preventDefault());

  setupDropZone();
  setupTabs();
  setupHexTicker();
  setupModeSwitcher();
  setupDomainScan();
  setupMonitoring();

  $('btn-export-report')?.addEventListener('click', handleExportReport);
  $('btn-reset')?.addEventListener('click', handleReset);

  const heroCta = $('hero-upload-btn');
  if (heroCta) {
    heroCta.addEventListener('click', () => {
      $('upload-section')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      setTimeout(() => $('file-input').click(), 400);
    });
  }

  const errClose = $('error-close-btn');
  if (errClose) {
    errClose.addEventListener('click', () => {
      $('error-banner').style.display = 'none';
    });
  }

  console.log('[Sentry Platform] init() complete — ready');
}

// ─── Mode Switcher (File Upload vs Website Scan) ──────────────────────────────

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

// ─── Domain Security Scan ─────────────────────────────────────────────────────

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
      let msg = `Scan failed (${res.status}).`;
      try { const j = await res.json(); if (j.error) msg = j.error; } catch {}
      throw new Error(msg);
    }

    const data = await res.json();
    showLoading(false);

    // Format analysis result
    state.privacyMode = 'BACKEND_NETWORK';
    state.filename = data.metadata.targetName;
    state.findings = data.findings.map(normalizeFinding);
    state.scoreInfo = calculateSecurityScore(state.findings);
    state.iocs = processIocs(data.iocs);
    state.analysisResult = {
      metadata: data.metadata,
      scoreInfo: state.scoreInfo,
      findings: state.findings,
      iocs: state.iocs.iocs,
      artifacts: data.artifacts
    };

    updatePrivacyBadge('network');
    showDashboard();
    populateDashboardGeneric(data.metadata.targetName, 'Website & Domain Assessment');

  } catch (err) {
    showLoading(false);
    showError(err.message || 'Failed to complete domain scan. Make sure backend server is running (node backend/server.js)');
  }
}

// ─── File Drop Zone & Handling ────────────────────────────────────────────────

function setupDropZone() {
  const zone      = $('drop-zone');
  const input     = $('file-input');
  const browseBtn = $('browse-btn');

  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(evtName => {
    zone.addEventListener(evtName, (e) => {
      e.preventDefault();
      e.stopPropagation();
    });
  });

  zone.addEventListener('dragenter', () => zone.classList.add('drag-over'));
  zone.addEventListener('dragover',  () => zone.classList.add('drag-over'));
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

  input.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      showFileChosen(file);
      handleFile(file);
    }
  });
}

function showFileChosen(file) {
  const idle   = $('drop-zone-idle');
  const chosen = $('drop-zone-chosen');
  const fname  = $('chosen-filename');
  const fsize  = $('chosen-size');

  if (idle)   idle.style.display   = 'none';
  if (chosen) chosen.style.display = 'flex';
  if (fname)  fname.textContent  = file.name;
  if (fsize)  fsize.textContent  = formatFileSize(file.size);
}

// ─── Core File Router ─────────────────────────────────────────────────────────

async function handleFile(file) {
  state.filename = file.name;
  state.privacyMode = 'CLIENT_SIDE_LOCAL';
  updatePrivacyBadge('local');

  showLoading(true, 'Inspecting file header & magic bytes…');

  try {
    const buffer = await file.arrayBuffer();
    const detected = detectFileType(buffer, file.name);
    state.fileTypeInfo = detected;

    console.log('[Sentry Platform] Detected file type:', detected);
    console.log('[Sentry Platform] First 16 magic bytes (hex):', Array.from(new Uint8Array(buffer, 0, Math.min(buffer.byteLength, 16))).map(b => b.toString(16).padStart(2, '0')).join(' '));

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

          // Map PCAP findings to standard taxonomy
          const normalized = pcapFindings.map(f => ({
            id: `PCAP-${f.id.toUpperCase()}`,
            title: f.name,
            severity: f.severity.toUpperCase(),
            category: 'Network Attack',
            description: f.description,
            source: `${f.srcIP || 'Network'} → ${f.dstIP || 'Target'}`,
            recommendation: f.mitigation || 'Inspect network flow logs.'
          }));

          // Extract PCAP IOCs
          const pcapIocs = {
            ips: Array.from(new Set(parsed.packets.flatMap(p => [p.ipSrc, p.ipDst]).filter(Boolean))),
            domains: [],
            urls: [],
            emails: [],
            hashes: []
          };

          state.packets = parsed.packets;
          state.stats = parsed.stats;

          rawResult = {
            metadata: { fileName: file.name, fileSize: file.size, targetType: targetTypeLabel, privacyMode: '🔒 100% LOCAL' },
            findings: normalized,
            iocs: pcapIocs,
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
      console.warn('[Sentry Platform] Primary analyzer encountered error, falling back to static analyzer:', analysisErr);
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
        console.error('[Sentry Platform] Fallback generic analyzer error:', fallbackErr);
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

    // Standardize Findings, Compute Score & Process IOCs
    const processedIocs = processIocs(rawResult.iocs);
    const combinedFindings = [...rawResult.findings, ...processedIocs.findings].map(normalizeFinding);
    const scoreInfo = calculateSecurityScore(combinedFindings);

    state.findings = combinedFindings;
    state.scoreInfo = scoreInfo;
    state.iocs = processedIocs;
    state.analysisResult = {
      metadata: rawResult.metadata,
      scoreInfo,
      findings: combinedFindings,
      iocs: processedIocs.iocs,
      artifacts: rawResult.artifacts
    };

    showLoading(false);
    showDashboard();
    populateDashboardGeneric(file.name, targetTypeLabel);

  } catch (err) {
    console.error('[Sentry Platform] Pipeline error:', err);
    showLoading(false);
    showError(`Analysis failed: ${err.message}`);
  }
}

// ─── Dashboard Population ─────────────────────────────────────────────────────

function populateDashboardGeneric(targetName, targetTypeLabel) {
  $('stat-filename').textContent = targetName;
  $('stat-target-type').textContent = targetTypeLabel;
  $('stat-total-findings').textContent = state.findings.length;
  $('stat-total-iocs').textContent = (state.iocs?.summary?.totalIps || 0) + (state.iocs?.summary?.totalUrls || 0) + (state.iocs?.summary?.totalDomains || 0);
  $('stat-critical').textContent = state.scoreInfo.counts.CRITICAL || 0;
  $('stat-high').textContent = state.scoreInfo.counts.HIGH || 0;

  // Update Score Gauge
  const scoreNum = $('score-num');
  const scoreDial = $('score-dial');
  const riskTitle = $('score-risk-title');

  if (scoreNum) scoreNum.textContent = state.scoreInfo.score;
  if (riskTitle) {
    riskTitle.textContent = state.scoreInfo.riskLevel;
    riskTitle.style.color = state.scoreInfo.color;
  }
  if (scoreDial) {
    scoreDial.className = 'score-dial';
    if (state.scoreInfo.score < 40) scoreDial.classList.add('crit');
    else if (state.scoreInfo.score < 70) scoreDial.classList.add('high');
    else if (state.scoreInfo.score < 90) scoreDial.classList.add('med');
  }

  populateFindingsTab();
  populateIocsTab();

  // Render PCAP charts if packets exist
  if (state.packets && state.packets.length > 0) {
    renderTimeline(state.stats.timelineBuckets);
    renderProtocolChart(state.stats.protocolCounts);
    renderTopTalkersChart(state.stats.topSrcIPs);
    if (!state.networkGraph) {
      state.networkGraph = new NetworkGraph('network-svg');
    }
    state.networkGraph.update(state.packets, state.suspiciousIPs);
  }
}

function populateFindingsTab() {
  const container = $('findings-list');
  if (!container) return;

  if (state.findings.length === 0) {
    container.innerHTML = `
      <div class="section-card" style="text-align:center; padding:32px">
        <div style="font-size:32px; margin-bottom:8px">🟢</div>
        <h3 style="color:var(--green)">No Security Threats Detected</h3>
        <p style="color:var(--text-secondary)">Static analysis completed clean with zero security anomaly flags.</p>
      </div>
    `;
    return;
  }

  const html = state.findings.map(f => {
    const sevClass = f.severity.toLowerCase();
    return `
      <div class="section-card finding-card" style="border-left: 4px solid var(--${sevClass === 'critical' ? 'red' : sevClass === 'high' ? 'amber' : 'green'})">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px">
          <span class="sev-badge sev-${sevClass}">${f.severity}</span>
          <span style="color:var(--text-muted); font-size:11px">${f.category}</span>
        </div>
        <h3 style="font-size:15px; margin-bottom:6px" class="finding-name">${f.title}</h3>
        <p style="color:var(--text-secondary); margin-bottom:10px">${f.description}</p>
        <div style="font-size:11px; color:var(--text-muted)">
          <strong>Source:</strong> <code>${f.source}</code>
        </div>
        <div style="font-size:11px; color:var(--green); margin-top:4px">
          💡 <strong>Mitigation:</strong> ${f.recommendation}
        </div>
      </div>
    `;
  }).join('');

  container.innerHTML = html;
}

function populateIocsTab() {
  const ipContainer = $('ioc-ips-list');
  const urlContainer = $('ioc-urls-list');
  const hashContainer = $('ioc-hashes-list');

  const iocs = state.iocs?.iocs || { ips: [], domains: [], urls: [], hashes: [] };

  if (ipContainer) {
    ipContainer.innerHTML = iocs.ips.concat(iocs.domains).map(item => `
      <span class="ioc-badge">${item}</span>
    `).join('') || '<span style="color:var(--text-muted)">None extracted</span>';
  }

  if (urlContainer) {
    urlContainer.innerHTML = iocs.urls.map(url => `
      <div style="margin-bottom:4px"><code class="ioc-badge">${url}</code></div>
    `).join('') || '<span style="color:var(--text-muted)">None extracted</span>';
  }

  if (hashContainer) {
    hashContainer.innerHTML = iocs.hashes.map(h => `
      <div><span class="ioc-badge">${h}</span></div>
    `).join('') || '<span style="color:var(--text-muted)">None computed</span>';
  }
}

// ─── Monitoring Tab Management ───────────────────────────────────────────────

function setupMonitoring() {
  const btnAdd = $('btn-add-monitor-target');
  const input = $('monitor-target-input');

  btnAdd?.addEventListener('click', () => {
    const domain = input?.value?.trim();
    if (domain) addMonitorTarget(domain);
  });

  // Fetch targets when monitoring tab is clicked
  const tabMon = $('tab-monitoring');
  tabMon?.addEventListener('click', fetchMonitorTargets);
}

async function fetchMonitorTargets() {
  const tbody = $('table-monitor-targets');
  if (!tbody) return;

  try {
    const res = await fetch(`${BACKEND_URL}/api/monitor/targets`);
    if (!res.ok) throw new Error();
    const targets = await res.json();

    if (targets.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-row">No active monitoring targets. Add a domain above.</td></tr>';
      return;
    }

    tbody.innerHTML = targets.map(t => `
      <tr>
        <td><strong>${t.domain}</strong></td>
        <td><span class="sev-badge sev-info">${t.status}</span></td>
        <td>Every ${t.frequency_hours}h</td>
        <td><strong style="color:var(--green)">${t.last_score || 'N/A'}</strong></td>
        <td>${t.last_scanned_at ? new Date(t.last_scanned_at).toLocaleString() : 'Pending'}</td>
        <td>
          <button class="btn btn-ghost" onclick="window.removeMonitorTarget(${t.id})" style="padding:2px 8px; font-size:11px">Delete</button>
        </td>
      </tr>
    `).join('');
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-row" style="color:var(--amber)">Backend scheduler offline. Run "node backend/server.js" to enable.</td></tr>';
  }
}

async function addMonitorTarget(domain) {
  try {
    const res = await fetch(`${BACKEND_URL}/api/monitor/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });
    if (res.ok) {
      $('monitor-target-input').value = '';
      fetchMonitorTargets();
    } else {
      showMonitorError(`Backend returned an error (HTTP ${res.status}). Check that the backend server is running.`);
    }
  } catch (e) {
    showMonitorError('Backend service unavailable. Scheduled monitoring requires the backend server — run: node backend/server.js');
  }
}

function showMonitorError(msg) {
  const tbody = $('table-monitor-targets');
  if (tbody) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-row" style="color:var(--amber); padding:16px">
      <span style="font-size:16px; margin-right:8px">⚠️</span>${msg}
    </td></tr>`;
  }
}

window.removeMonitorTarget = async function(id) {
  try {
    await fetch(`${BACKEND_URL}/api/monitor/targets/${id}`, { method: 'DELETE' });
    fetchMonitorTargets();
  } catch (e) {}
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function updatePrivacyBadge(mode) {
  const headerBadge = $('header-privacy-badge');
  const dashBadge = $('dashboard-privacy-indicator');

  if (mode === 'local') {
    if (headerBadge) { headerBadge.className = 'privacy-badge local'; headerBadge.textContent = '🔒 100% LOCAL CLIENT-SIDE ANALYSIS'; }
    if (dashBadge) { dashBadge.className = 'privacy-badge local'; dashBadge.textContent = '🔒 PROCESSED LOCALLY'; }
  } else {
    if (headerBadge) { headerBadge.className = 'privacy-badge network'; headerBadge.textContent = '🌐 BACKEND NETWORK LOOKUP'; }
    if (dashBadge) { dashBadge.className = 'privacy-badge network'; dashBadge.textContent = '🌐 BACKEND NETWORK LOOKUP'; }
  }
}

function setupHexTicker() {
  const ticker = $('hex-ticker-inner');
  if (!ticker) return;
  const chars  = '0123456789abcdef';
  const rand   = () => chars[Math.floor(Math.random() * 16)];
  let hex = '';
  for (let i = 0; i < 400; i++) {
    hex += rand() + rand();
    if (i % 2 === 1) hex += ' ';
  }
  ticker.textContent = hex + '    ' + hex;
}

function setupTabs() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      const targetTab = e.currentTarget.getAttribute('data-tab');
      e.currentTarget.classList.add('active');
      const panel = $('panel-' + targetTab.replace('tab-', ''));
      if (panel) panel.classList.add('active');
    });
  });
}

function handleExportReport() {
  if (state.analysisResult) {
    exportPdfReport(state.analysisResult);
  }
}

function handleReset() {
  state.packets = [];
  state.findings = [];
  state.analysisResult = null;
  destroyAllCharts();
  $('landing-page').style.display = 'block';
  $('dashboard').style.display = 'none';
  resetDropZoneUI();
}

function resetDropZoneUI() {
  const idle   = $('drop-zone-idle');
  const chosen = $('drop-zone-chosen');
  if (chosen) chosen.style.display = 'none';
  if (idle)   idle.style.display   = 'flex';
}

function showLoading(show, message = '') {
  const overlay = $('loading-overlay');
  const msgEl   = $('loading-message');
  if (msgEl && message) msgEl.textContent = message;
  if (overlay) overlay.style.display = show ? 'flex' : 'none';
}

function showError(msg) {
  const banner = $('error-banner');
  const text   = $('error-text');
  if (text) text.textContent = msg;
  if (banner) banner.style.display = 'flex';
}

function showDashboard() {
  $('landing-page').style.display = 'none';
  $('dashboard').style.display = 'block';
}

function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}
