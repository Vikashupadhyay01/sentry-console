/**
 * Sentry Console — Markdown Report Generator
 * Compiles all analysis data into a downloadable .md report.
 */

const SEV_EMOJI = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' };

/**
 * Generate a Markdown report string.
 * @param {string} filename — original pcap filename
 * @param {Object} stats    — from parsePcap()
 * @param {Array}  findings — from runDetections()
 * @returns {string} markdown
 */
export function generateReport(filename, stats, findings) {
  const now = new Date().toISOString().replace('T', ' ').split('.')[0] + ' UTC';
  const dur = formatDuration(stats.duration);
  const critCount = findings.filter(f => f.severity === 'critical').length;
  const highCount  = findings.filter(f => f.severity === 'high').length;
  const medCount   = findings.filter(f => f.severity === 'medium').length;
  const lowCount   = findings.filter(f => f.severity === 'low').length;

  const lines = [];

  // ── Cover ─────────────────────────────────────────────────────────────────
  lines.push(`# Sentry Console — Security Analysis Report`);
  lines.push(``);
  lines.push(`**File:** \`${filename}\``);
  lines.push(`**Generated:** ${now}`);
  lines.push(`**Analyst Tool:** Sentry Console v1.0 (client-side analysis)`);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // ── Executive Summary ─────────────────────────────────────────────────────
  lines.push(`## Executive Summary`);
  lines.push(``);
  lines.push(`This report presents automated threat analysis of the PCAP capture \`${filename}\`.`);
  lines.push(`The capture contains **${stats.totalPackets.toLocaleString()} packets** spanning **${dur}** across **${stats.uniqueHosts} unique hosts**.`);
  lines.push(``);

  if (findings.length === 0) {
    lines.push(`> ✅ **No threats detected.** The capture does not exhibit patterns matching known attack heuristics.`);
  } else {
    lines.push(`The detection engine identified **${findings.length} finding(s)**:`);
    lines.push(``);
    lines.push(`| Severity | Count |`);
    lines.push(`|---|---|`);
    if (critCount) lines.push(`| 🔴 Critical | ${critCount} |`);
    if (highCount)  lines.push(`| 🟠 High     | ${highCount}  |`);
    if (medCount)   lines.push(`| 🟡 Medium   | ${medCount}  |`);
    if (lowCount)   lines.push(`| 🔵 Low      | ${lowCount}   |`);
    lines.push(``);

    if (critCount > 0) {
      lines.push(`> ⚠️ **CRITICAL threats detected.** Immediate investigation and remediation is recommended.`);
    } else if (highCount > 0) {
      lines.push(`> ⚠️ **High-severity threats detected.** Prompt investigation is recommended.`);
    } else {
      lines.push(`> ℹ️ Medium/low severity findings detected. Review at next available opportunity.`);
    }
  }
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // ── Findings ─────────────────────────────────────────────────────────────
  if (findings.length > 0) {
    lines.push(`## Detected Threats`);
    lines.push(``);

    for (const f of findings) {
      const emoji = SEV_EMOJI[f.severity] || '⚪';
      lines.push(`### ${emoji} [${f.severity.toUpperCase()}] ${f.name}`);
      lines.push(``);
      lines.push(`**Source:** \`${f.src || 'N/A'}\`  `);
      lines.push(`**Destination:** \`${f.dst || 'N/A'}\``);
      lines.push(``);
      lines.push(`**Summary:**`);
      lines.push(``);
      lines.push(f.summary);
      lines.push(``);
      lines.push(`**Technical Indicators:**`);
      lines.push(``);
      for (const ind of f.indicators) {
        lines.push(`- ${ind}`);
      }
      lines.push(``);
      lines.push(`**Mitigation:**`);
      lines.push(``);
      lines.push(`> ${f.mitigation}`);
      lines.push(``);
      lines.push(`---`);
      lines.push(``);
    }
  }

  // ── Traffic Statistics ────────────────────────────────────────────────────
  lines.push(`## Traffic Statistics`);
  lines.push(``);

  lines.push(`### Capture Metadata`);
  lines.push(``);
  lines.push(`| Field | Value |`);
  lines.push(`|---|---|`);
  lines.push(`| Total Packets | ${stats.totalPackets.toLocaleString()} |`);
  lines.push(`| Capture Duration | ${dur} |`);
  lines.push(`| Unique Hosts | ${stats.uniqueHosts} |`);
  lines.push(`| Snaplen | ${stats.snaplen} bytes |`);
  lines.push(`| Link Type | ${stats.linktype} (${stats.linktype === 1 ? 'Ethernet' : 'Other'}) |`);
  lines.push(``);

  lines.push(`### Protocol Distribution`);
  lines.push(``);
  lines.push(`| Protocol | Packets | Share |`);
  lines.push(`|---|---|---|`);
  const total = stats.totalPackets || 1;
  for (const [proto, count] of Object.entries(stats.protocolCounts)) {
    if (count === 0) continue;
    lines.push(`| ${proto} | ${count.toLocaleString()} | ${((count / total) * 100).toFixed(1)}% |`);
  }
  lines.push(``);

  lines.push(`### Top Source IPs`);
  lines.push(``);
  lines.push(`| Rank | IP Address | Packets |`);
  lines.push(`|---|---|---|`);
  stats.topSrcIPs.slice(0, 10).forEach((e, i) => {
    lines.push(`| ${i + 1} | \`${e.ip}\` | ${e.count.toLocaleString()} |`);
  });
  lines.push(``);

  lines.push(`### Top Destination Ports`);
  lines.push(``);
  lines.push(`| Port | Packets | Service |`);
  lines.push(`|---|---|---|`);
  const portNames = { 80:'HTTP', 443:'HTTPS', 53:'DNS', 22:'SSH', 21:'FTP', 25:'SMTP', 3389:'RDP', 3306:'MySQL' };
  stats.topDstPorts.slice(0, 10).forEach((e) => {
    lines.push(`| ${e.port} | ${e.count.toLocaleString()} | ${portNames[e.port] || 'Unknown'} |`);
  });
  lines.push(``);
  lines.push(`---`);
  lines.push(``);

  // ── Recommendations ───────────────────────────────────────────────────────
  lines.push(`## Recommendations`);
  lines.push(``);

  if (findings.length === 0) {
    lines.push(`1. Continue routine traffic monitoring.`);
    lines.push(`2. Ensure IDS/IPS signatures are up to date.`);
    lines.push(`3. Periodically review firewall rules.`);
  } else {
    const uniqueMitigations = [...new Set(findings.map(f => f.mitigation))];
    uniqueMitigations.forEach((m, i) => {
      lines.push(`${i + 1}. ${m}`);
    });
  }
  lines.push(``);
  lines.push(`---`);
  lines.push(``);
  lines.push(`*Report generated by Sentry Console — 100% client-side analysis. No packet data was transmitted to any server.*`);

  return lines.join('\n');
}

/**
 * Trigger a browser download of a text/markdown file.
 *
 * @param {string} content  — the Markdown string to download
 * @param {string} filename — the filename shown in the browser download bar
 *
 * IMPORTANT: follows the exact safe-download pattern:
 *   1. a.download must be a non-empty string set BEFORE click()
 *   2. anchor must be in the DOM when click() fires
 *   3. revokeObjectURL must be deferred (not synchronous) so the
 *      browser has time to initiate the file save before the URL disappears
 */
export function downloadReport(content, filename = 'sentry_security_report.md') {
  // Guard: confirm content is non-empty before touching the DOM
  console.log('[Sentry] downloadReport — content length:', content ? content.length : 0, 'chars | filename:', filename);
  if (!content || content.length === 0) {
    console.error('[Sentry] Report content is empty — aborting download');
    return;
  }

  const blob = new Blob([content], { type: 'text/markdown' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');

  a.href     = url;
  a.download = filename;          // MUST be a real string, set before appendChild/click

  document.body.appendChild(a);  // required for click() to register in all browsers
  a.click();
  document.body.removeChild(a);

  // Delay revocation — revoking immediately races with the download starting
  setTimeout(() => URL.revokeObjectURL(url), 1000);

  console.log('[Sentry] Download triggered → filename:', a.download);
}


function formatDuration(seconds) {
  if (seconds < 1)    return `${(seconds * 1000).toFixed(0)} ms`;
  if (seconds < 60)   return `${seconds.toFixed(2)} seconds`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}
