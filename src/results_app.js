/**
 * Sentry Console — Results Page Application Controller
 * Loads analysis payload from sessionStorage, renders score gauge,
 * findings list, extracted IOCs, traffic analytics, and PDF reports.
 */

import { calculateSecurityScore } from './modules/score_engine.js';
import { renderTimeline, renderProtocolChart, renderTopTalkersChart } from './charts.js?v=1.0.1';
import { NetworkGraph } from './network_graph.js?v=1.0.1';
import { exportPdfReport } from './modules/pdf_report_generator.js?v=1.0.1';
import { loadAnalysisData, clearAnalysisData } from './modules/storage.js?v=1.0.1';

const $ = (id) => document.getElementById(id);
const BACKEND_URL = 'http://localhost:3001';

let analysisData = null;

export async function initResultsPage() {
  console.log('[Sentry Results] Initializing Dashboard Page via Storage module (IndexedDB)');
  console.warn(`[Sentry Origin] Active origin: ${window.location.origin}`);

  try {
    const data = await loadAnalysisData();
    if (!data) {
      console.warn('[Sentry Results] No data returned from Storage module — showing empty state.');
      showEmptyState();
      return;
    }

    analysisData = data;
    console.log('[Sentry Results] Successfully loaded analysis data payload:', {
      fileName: analysisData.metadata?.fileName,
      totalPackets: analysisData.stats?.totalPackets || analysisData.artifacts?.packetsCount || 0,
      findingsCount: analysisData.findings?.length || 0,
      scoreInfo: analysisData.scoreInfo,
      hasStats: !!analysisData.stats
    });
    renderDashboard(analysisData);
  } catch (err) {
    console.error('[Sentry Results] Failed to load analysis storage payload:', err);
    showEmptyState();
  }

  setupTabs();
  setupActionButtons();
  setupMonitoring();
}

function showEmptyState() {
  const emptyBox = $('empty-results-box');
  const dashBox = $('dashboard');
  if (emptyBox) emptyBox.style.display = 'block';
  if (dashBox) dashBox.style.display = 'none';
}

function renderDashboard(data) {
  const emptyBox = $('empty-results-box');
  const dashBox = $('dashboard');
  if (emptyBox) emptyBox.style.display = 'none';
  if (dashBox) dashBox.style.display = 'block';

  const { metadata = {}, scoreInfo: storedScoreInfo = {}, findings = [], iocs = {}, packets = [], stats = null, privacyMode = 'CLIENT_SIDE_LOCAL' } = data;

  // Always recompute from findings so old/stale saved scores never show (0 vs 5 bug).
  const scoreInfo = findings.length ? calculateSecurityScore(findings) : storedScoreInfo;

  // Header & Privacy Badge
  const filenameEl = $('stat-filename');
  const typeBadgeEl = $('stat-target-type-badge');
  const privacyHeadEl = $('header-privacy-badge');
  const privacyDashEl = $('dashboard-privacy-indicator');

  if (filenameEl) filenameEl.textContent = metadata.fileName || metadata.targetName || 'Artifact';
  if (typeBadgeEl) typeBadgeEl.textContent = `(${metadata.targetType || 'File Artifact'})`;

  if (privacyMode === 'BACKEND_NETWORK') {
    if (privacyHeadEl) { privacyHeadEl.className = 'privacy-badge network'; privacyHeadEl.textContent = '🌐 BACKEND NETWORK LOOKUP'; }
    if (privacyDashEl) { privacyDashEl.className = 'privacy-badge network'; privacyDashEl.textContent = '🌐 BACKEND NETWORK LOOKUP'; }
  } else {
    if (privacyHeadEl) { privacyHeadEl.className = 'privacy-badge local'; privacyHeadEl.textContent = '🔒 100% LOCAL CLIENT-SIDE ANALYSIS'; }
    if (privacyDashEl) { privacyDashEl.className = 'privacy-badge local'; privacyDashEl.textContent = '🔒 PROCESSED LOCALLY'; }
  }

  // Score Dial
  const scoreNum = $('score-num');
  const scoreDial = $('score-dial');
  const riskTitle = $('score-risk-title');

  const calculatedScore = (scoreInfo.score !== undefined && scoreInfo.score !== null) ? scoreInfo.score : 100;
  const critTotal = scoreInfo.counts?.CRITICAL ?? 0;
  const dialLabel = scoreDial ? scoreDial.querySelector('.score-label') : null;

  // Dial shows the CRITICAL count (matches the Critical card); otherwise the 0-100 score.
  if (critTotal > 0) {
    if (scoreNum) scoreNum.textContent = critTotal;
    if (dialLabel) dialLabel.textContent = 'CRITICAL';
  } else {
    if (scoreNum) scoreNum.textContent = calculatedScore;
    if (dialLabel) dialLabel.textContent = 'SCORE';
  }
  const riskSub = $('score-risk-sub');
  if (riskSub && scoreInfo.counts) {
    const c = scoreInfo.counts;
    riskSub.textContent = `Security score ${calculatedScore}/100 · ${c.CRITICAL} critical, ${c.HIGH} high, ${c.MEDIUM} medium, ${c.LOW} low findings.`;
  }
  if (riskTitle) {
    riskTitle.textContent = scoreInfo.riskLevel || 'LOW RISK';
    riskTitle.style.color = scoreInfo.color || 'var(--accent)';
  }
  if (scoreDial) {
    scoreDial.className = 'score-dial';
    if (critTotal > 0 || calculatedScore < 40) scoreDial.classList.add('crit');
    else if (calculatedScore < 70) scoreDial.classList.add('high');
    else if (calculatedScore < 90) scoreDial.classList.add('med');
  }

  // Stat Cards
  // stats.totalPackets is the authoritative count (set by parsePcap from the full file).
  // artifacts.packetsCount is the fallback. We never use packets.length since the raw
  // packets array is no longer stored in sessionStorage.
  const parsedPacketCount = stats?.totalPackets ?? data.artifacts?.packetsCount ?? 0;
  if ($('stat-total-packets')) $('stat-total-packets').textContent = typeof parsedPacketCount === 'number' ? parsedPacketCount.toLocaleString() : (parsedPacketCount || 'N/A');
  if ($('stat-target-type')) $('stat-target-type').textContent = metadata.targetType || 'File';
  if ($('stat-total-findings')) $('stat-total-findings').textContent = findings.length;

  const totalIocsCount = (iocs?.summary?.totalIps || iocs?.ips?.length || 0) +
    (iocs?.summary?.totalUrls || iocs?.urls?.length || 0) +
    (iocs?.summary?.totalDomains || iocs?.domains?.length || 0);

  if ($('stat-total-iocs')) $('stat-total-iocs').textContent = totalIocsCount;

  const critCount = scoreInfo.counts?.CRITICAL ?? findings.filter(f => (f.severity || '').toUpperCase() === 'CRITICAL').length;
  const highCount = scoreInfo.counts?.HIGH ?? findings.filter(f => (f.severity || '').toUpperCase() === 'HIGH').length;
  const medCount = scoreInfo.counts?.MEDIUM ?? findings.filter(f => (f.severity || '').toUpperCase() === 'MEDIUM').length;
  const lowCount = scoreInfo.counts?.LOW ?? findings.filter(f => (f.severity || '').toUpperCase() === 'LOW').length;

  if ($('stat-critical')) $('stat-critical').textContent = critCount;
  if ($('stat-high')) $('stat-high').textContent = highCount;
  if ($('stat-medium')) $('stat-medium').textContent = medCount;
  if ($('stat-low')) $('stat-low').textContent = lowCount;

  renderFindings(findings);
  renderIocs(iocs);

  // Render Charts & Network Graph if packet stats exist.
  // Each visualization is isolated in its own try-catch block so an issue with one
  // (e.g. Chart.js CDN unavailable) never prevents the others or the NetworkGraph from rendering.
  if (stats && stats.timelineBuckets) {
    const suspiciousIPs = new Set(findings.flatMap(f => [f.src, f.dst]).filter(Boolean));

    try {
      renderTimeline('chart-timeline', stats, findings);
    } catch (chartErr) {
      console.error('[Sentry Results] Timeline chart rendering error:', chartErr);
    }

    try {
      renderProtocolChart('chart-protocol', stats);
    } catch (chartErr) {
      console.error('[Sentry Results] Protocol chart rendering error:', chartErr);
    }

    try {
      renderTopTalkersChart('chart-talkers', stats, suspiciousIPs);
    } catch (chartErr) {
      console.error('[Sentry Results] Top Talkers chart rendering error:', chartErr);
    }
  }

  // Render Network Flow Diagram independently if graphData exists
  try {
    const svgEl = $('network-svg');
    const graphData = data.graphData;
    console.log('[Sentry Results] graphData for network diagram:', graphData);
    console.log('[Sentry Results] graphData nodes count:', graphData?.nodes?.length, 'edges count:', graphData?.edges?.length);
    if (svgEl && graphData && graphData.nodes?.length > 0) {
      console.log('[Sentry NetworkGraph] Methods available:', Object.getOwnPropertyNames(NetworkGraph.prototype));
      const netGraph = new NetworkGraph(svgEl);
      netGraph.loadGraphData(graphData);
    } else {
      console.warn('[Sentry Results] Network graph skipped: svgEl missing or graphData has 0 nodes.');
    }
  } catch (graphErr) {
    console.error('[Sentry Results] Network graph SVG rendering error:', graphErr);
  }
}


function renderFindings(findings) {
  const container = $('findings-list');
  if (!container) return;

  if (findings.length === 0) {
    container.innerHTML = `
      <div class="section-card" style="text-align:center; padding:32px">
        <div style="font-size:32px; margin-bottom:8px">🟢</div>
        <h3 style="color:var(--accent)">No Security Threats Detected</h3>
        <p style="color:var(--text-secondary)">Analysis completed clean with zero security anomaly flags.</p>
      </div>
    `;
    return;
  }

  const html = findings.map(f => {
    const sevClass = (f.severity || 'LOW').toLowerCase();
    const borderColor = sevClass === 'critical' ? 'var(--red)' : sevClass === 'high' ? 'var(--amber)' : sevClass === 'medium' ? '#eab308' : 'var(--accent)';

    // SRC → DST flow badge
    const srcDst = (f.src || f.dst)
      ? `<div style="margin-bottom:10px; font-size:12px; font-family:var(--mono)">
           ${f.src ? `<span style="background:rgba(0,255,65,0.1); border:1px solid var(--border); color:var(--green); padding:2px 8px; border-radius:3px; margin-right:4px">${f.src}</span>` : ''}
           ${f.src && f.dst ? `<span style="color:var(--text-muted); margin-right:4px">→</span>` : ''}
           ${f.dst ? `<span style="background:rgba(255,68,68,0.1); border:1px solid rgba(255,68,68,0.3); color:var(--red); padding:2px 8px; border-radius:3px">${f.dst}</span>` : ''}
         </div>`
      : '';

    // Technical indicators list
    const indicators = Array.isArray(f.indicators) && f.indicators.length > 0
      ? `<div style="margin-top:12px">
           <div style="font-size:10px; text-transform:uppercase; letter-spacing:0.08em; color:var(--text-muted); margin-bottom:6px; font-weight:600">Technical Indicators</div>
           <ul style="margin:0; padding-left:16px; color:var(--text-secondary); font-size:12px; line-height:1.7">
             ${f.indicators.map(ind => `<li>${ind}</li>`).join('')}
           </ul>
         </div>`
      : '';

    // Mitigation block
    const mitigation = f.recommendation
      ? `<div style="margin-top:12px; padding:10px 12px; background:rgba(0,255,65,0.05); border-left:2px solid var(--green); font-size:12px; color:var(--text-secondary)">
           <div style="font-size:10px; text-transform:uppercase; letter-spacing:0.08em; color:var(--green); margin-bottom:4px; font-weight:600">Mitigation</div>
           ${f.recommendation}
         </div>`
      : '';

    return `
      <div class="section-card finding-card" style="border-left: 4px solid ${borderColor}; margin-bottom:12px">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px">
          <div style="display:flex; align-items:center; gap:10px">
            <span class="sev-badge sev-${sevClass}">${f.severity}</span>
            <h3 style="font-size:16px; margin:0; color:var(--text-primary); font-family:var(--mono)">${f.title}</h3>
          </div>
          <span style="color:var(--text-muted); font-size:11px">${f.category || 'Security Anomaly'}</span>
        </div>
        ${srcDst}
        <p style="color:var(--text-secondary); margin-bottom:0; font-size:13px; line-height:1.6">${f.description}</p>
        ${indicators}
        ${mitigation}
      </div>
    `;
  }).join('');

  container.innerHTML = html;
}


function renderIocs(iocsObj) {
  const ipContainer = $('ioc-ips-list');
  const urlContainer = $('ioc-urls-list');
  const hashContainer = $('ioc-hashes-list');

  const iocs = iocsObj.iocs || iocsObj || { ips: [], domains: [], urls: [], hashes: [] };

  if (ipContainer) {
    ipContainer.innerHTML = (iocs.ips || []).concat(iocs.domains || []).map(item => `
      <span class="ioc-badge">${item}</span>
    `).join('') || '<span style="color:var(--text-muted)">None extracted</span>';
  }

  if (urlContainer) {
    urlContainer.innerHTML = (iocs.urls || []).map(url => `
      <div style="margin-bottom:4px"><code class="ioc-badge">${url}</code></div>
    `).join('') || '<span style="color:var(--text-muted)">None extracted</span>';
  }

  if (hashContainer) {
    hashContainer.innerHTML = (iocs.hashes || []).map(h => `
      <div><span class="ioc-badge">${h}</span></div>
    `).join('') || '<span style="color:var(--text-muted)">None computed</span>';
  }
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

      if (analysisData) {
        if (targetTab === 'tab-traffic') {
          try {
            const svgEl = $('network-svg');
            const graphData = analysisData.graphData;
            console.log('[Sentry Results] Tab traffic graphData:', graphData);
            console.log('[Sentry Results] Tab traffic nodes count:', graphData?.nodes?.length, 'edges count:', graphData?.edges?.length);
            if (svgEl && graphData && graphData.nodes?.length > 0) {
              console.log('[Sentry NetworkGraph] Tab traffic methods available:', Object.getOwnPropertyNames(NetworkGraph.prototype));
              const netGraph = new NetworkGraph(svgEl);
              netGraph.loadGraphData(graphData);
            } else {
              console.warn('[Sentry Results] Tab traffic graph skipped: svgEl missing or graphData has 0 nodes.');
            }
          } catch (tabGraphErr) {
            console.error('[Sentry Results] Tab network graph rendering error:', tabGraphErr);
          }
        } else if (targetTab === 'tab-overview' && analysisData.stats && analysisData.stats.timelineBuckets) {
          const suspiciousIPs = new Set((analysisData.findings || []).flatMap(f => [f.src, f.dst]).filter(Boolean));
          try { renderTimeline('chart-timeline', analysisData.stats, analysisData.findings || []); } catch (e) { console.error('[Sentry Results] Tab timeline error:', e); }
          try { renderProtocolChart('chart-protocol', analysisData.stats); } catch (e) { console.error('[Sentry Results] Tab protocol chart error:', e); }
          try { renderTopTalkersChart('chart-talkers', analysisData.stats, suspiciousIPs); } catch (e) { console.error('[Sentry Results] Tab top talkers chart error:', e); }
        }
      }
    });
  });
}

function setupActionButtons() {
  const btnNew = $('btn-new-analysis');
  const btnExport = $('btn-export-report');
  const btnExportTab = $('btn-export-report-tab');

  btnNew?.addEventListener('click', async () => {
    await clearAnalysisData();
    window.location.href = 'analyze.html';
  });

  const triggerPdfExport = () => {
    if (analysisData) {
      exportPdfReport(analysisData);
    }
  };

  btnExport?.addEventListener('click', triggerPdfExport);
  btnExportTab?.addEventListener('click', triggerPdfExport);
}

function setupMonitoring() {
  const btnAdd = $('btn-add-monitor-target');
  const input = $('monitor-target-input');

  btnAdd?.addEventListener('click', () => {
    const domain = input?.value?.trim();
    if (domain) addMonitorTarget(domain);
  });

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
    showMonitorError('Backend service unavailable. Scheduled monitoring requires the backend server to be running — run: node backend/server.js');
  }
}

/**
 * Shows an inline, styled error message in the monitoring panel.
 * Replaces the old native alert() popup with an in-app message.
 */
function showMonitorError(msg) {
  const tbody = $('table-monitor-targets');
  if (tbody) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-row" style="color:var(--amber); padding:16px">
      <span style="font-size:16px; margin-right:8px">⚠️</span>${msg}
    </td></tr>`;
  }
}

window.removeMonitorTarget = async function (id) {
  try {
    await fetch(`${BACKEND_URL}/api/monitor/targets/${id}`, { method: 'DELETE' });
    fetchMonitorTargets();
  } catch (e) { }
};