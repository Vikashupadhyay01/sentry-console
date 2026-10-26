/**
 * Sentry Console — Chart.js Wrappers
 * Timeline, protocol donut, top-talkers bar chart.
 */

let timelineChart = null;
let protocolChart  = null;
let talkersChart   = null;

const COLORS = {
  green:  '#00ff41',
  amber:  '#ffb347',
  red:    '#ff4444',
  blue:   '#4fc3f7',
  purple: '#b39ddb',
  teal:   '#26c6da',
  pink:   '#f48fb1',
  grid:   'rgba(0,255,65,0.08)',
  text:   '#a0adb8',
};

const PROTO_COLORS = [COLORS.green, COLORS.blue, COLORS.amber, COLORS.purple, COLORS.teal];

// Guard against Chart.js CDN load failure — allow module to load even if Chart is unavailable
if (typeof Chart !== 'undefined') {
  Chart.defaults.color = COLORS.text;
  Chart.defaults.font.family = "'IBM Plex Mono', monospace";
  Chart.defaults.font.size = 11;
} else {
  console.warn('[Sentry Charts] Chart.js is not loaded (CDN may be unavailable). Charts will be disabled.');
}

// ─── Timeline ─────────────────────────────────────────────────────────────────

export function renderTimeline(canvasId, stats, findings) {
  if (typeof Chart === 'undefined') {
    console.warn('[Sentry Charts] Cannot render timeline chart: Chart.js is undefined (CDN unavailable).');
    return;
  }
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  if (timelineChart) { timelineChart.destroy(); timelineChart = null; }

  const labels = (stats.timelineBuckets || []).map((_, i) => `${i}s`);
  const data   = stats.timelineBuckets || [];
  const maxVal = Math.max(...data, 10);

  const datasets = [
    {
      label: 'Packets/sec',
      type: 'line',
      data,
      borderColor: COLORS.green,
      backgroundColor: 'rgba(0,255,65,0.06)',
      borderWidth: 1.5,
      pointRadius: 0,
      fill: true,
      tension: 0.3,
      order: 1,
    }
  ];

  // Build attack window highlight overlays as bar datasets (pure Chart.js, zero plugins)
  let aIdx = 0;
  for (const f of (findings || [])) {
    if (!f.attackWindow) continue;
    const startSec = Number(f.attackWindow.startSec);
    const endSec   = Number(f.attackWindow.endSec);

    if (isNaN(startSec) || isNaN(endSec) || startSec < 0 || startSec > endSec) continue;

    const startIdx = Math.min(Math.floor(startSec), labels.length > 0 ? labels.length - 1 : 0);
    const endIdx   = Math.min(Math.ceil(endSec), labels.length > 0 ? labels.length - 1 : 0);

    const overlayData = new Array(labels.length).fill(null);
    for (let i = startIdx; i <= endIdx; i++) {
      overlayData[i] = maxVal;
    }

    datasets.push({
      label: `_attack_${aIdx++}`,
      type: 'bar',
      data: overlayData,
      backgroundColor: (f.severity || '').toLowerCase() === 'critical'
        ? 'rgba(255,68,68,0.15)'
        : 'rgba(255,179,71,0.12)',
      borderWidth: 0,
      barPercentage: 1.0,
      categoryPercentage: 1.0,
      order: 2,
    });
  }

  try {
    timelineChart = new Chart(ctx, {
      type: 'line',
      data: { labels, datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 600 },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#0d1117',
            borderColor: COLORS.green,
            borderWidth: 1,
            filter: (item) => !item.dataset.label.startsWith('_'),
            callbacks: {
              label: (ctx) => ` ${ctx.parsed.y} pkts`,
            },
          },
        },
        scales: {
          x: {
            ticks: { maxTicksLimit: 15, color: COLORS.text },
            grid: { color: COLORS.grid },
          },
          y: {
            ticks: { color: COLORS.text },
            grid: { color: COLORS.grid },
            beginAtZero: true,
          },
        },
      },
    });
  } catch (err) {
    console.error('[Sentry Charts] Timeline chart render error:', err);
  }
}

// ─── Protocol Donut ───────────────────────────────────────────────────────────

export function renderProtocolChart(canvasId, stats) {
  if (typeof Chart === 'undefined') {
    console.warn('[Sentry Charts] Cannot render protocol chart: Chart.js is undefined (CDN unavailable).');
    return;
  }
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  if (protocolChart) { protocolChart.destroy(); protocolChart = null; }

  const entries = Object.entries(stats.protocolCounts).filter(([, v]) => v > 0);
  const labels  = entries.map(([k]) => k);
  const values  = entries.map(([, v]) => v);

  protocolChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: PROTO_COLORS.slice(0, labels.length),
        borderColor: '#0a0c0f',
        borderWidth: 3,
        hoverOffset: 6,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '70%',
      animation: { duration: 700 },
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: COLORS.text,
            usePointStyle: true,
            pointStyleWidth: 10,
            padding: 14,
          },
        },
        tooltip: {
          backgroundColor: '#0d1117',
          borderColor: COLORS.green,
          borderWidth: 1,
          callbacks: {
            label: (ctx) => {
              const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
              const pct   = ((ctx.parsed / total) * 100).toFixed(1);
              return ` ${ctx.label}: ${ctx.parsed.toLocaleString()} pkts (${pct}%)`;
            },
          },
        },
      },
    },
  });
}

// ─── Top Talkers Bar ──────────────────────────────────────────────────────────

export function renderTopTalkersChart(canvasId, stats, suspiciousIPs) {
  if (typeof Chart === 'undefined') {
    console.warn('[Sentry Charts] Cannot render top talkers chart: Chart.js is undefined (CDN unavailable).');
    return;
  }
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  if (talkersChart) { talkersChart.destroy(); talkersChart = null; }

  const topN  = stats.topSrcIPs.slice(0, 12);
  const labels = topN.map(e => e.ip);
  const values = topN.map(e => e.count);
  const bgColors = labels.map(ip =>
    suspiciousIPs.has(ip) ? 'rgba(255,68,68,0.75)' : 'rgba(0,255,65,0.65)'
  );
  const borderColors = labels.map(ip =>
    suspiciousIPs.has(ip) ? COLORS.red : COLORS.green
  );

  talkersChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Packets Sent',
        data: values,
        backgroundColor: bgColors,
        borderColor: borderColors,
        borderWidth: 1,
        borderRadius: 3,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 500 },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0d1117',
          borderColor: COLORS.green,
          borderWidth: 1,
          callbacks: {
            label: (ctx) => ` ${ctx.parsed.x.toLocaleString()} packets`,
          },
        },
      },
      scales: {
        x: {
          grid: { color: COLORS.grid },
          ticks: { color: COLORS.text },
          beginAtZero: true,
        },
        y: {
          grid: { color: COLORS.grid },
          ticks: { color: COLORS.text, font: { family: "'IBM Plex Mono'" } },
        },
      },
    },
  });
}

export function destroyAllCharts() {
  if (timelineChart) { timelineChart.destroy(); timelineChart = null; }
  if (protocolChart)  { protocolChart.destroy();  protocolChart  = null; }
  if (talkersChart)   { talkersChart.destroy();   talkersChart   = null; }
}
