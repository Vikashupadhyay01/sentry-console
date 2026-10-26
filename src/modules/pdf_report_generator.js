/**
 * Sentry Console — PDF & Markdown Security Report Generator
 * Generates styled SOC dark-theme downloadable reports for any artifact analysis type.
 * Uses jsPDF library (loaded via CDN) or formatted HTML export window.
 * 100% Client-Side. Privacy Preserved.
 */

/**
 * Generate and trigger download of a formatted PDF Security Report.
 * @param {object} analysisResult Analysis result containing metadata, score, findings, iocs.
 */
export function exportPdfReport(analysisResult) {
  const { metadata = {}, scoreInfo = {}, findings = [], iocs = {} } = analysisResult;

  if (window.jspdf && window.jspdf.jsPDF) {
    generateJsPdfReport(metadata, scoreInfo, findings, iocs);
  } else {
    // Fallback: Trigger browser print window with styled SOC HTML print template
    generateHtmlPrintReport(metadata, scoreInfo, findings, iocs);
  }
}

/** Generate PDF using jsPDF library */
function generateJsPdfReport(metadata, scoreInfo, findings, iocs) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit: 'mm', format: 'a4' });

  // Dark SOC Background Header Bar
  doc.setFillColor(15, 23, 42); // #0f172a
  doc.rect(0, 0, 210, 35, 'F');

  // Title Text
  doc.setTextColor(56, 189, 248); // #38bdf8
  doc.setFont('Helvetica', 'bold');
  doc.setFontSize(20);
  doc.text('SENTRY CONSOLE', 14, 16);

  doc.setFontSize(10);
  doc.setTextColor(148, 163, 184);
  doc.text('SECURITY & THREAT ANALYSIS REPORT', 14, 23);
  doc.text(`Generated: ${new Date().toUTCString()}`, 14, 29);

  // Score Box
  doc.setFillColor(30, 41, 59);
  doc.roundedRect(140, 6, 56, 23, 3, 3, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(9);
  doc.text('SECURITY SCORE', 145, 12);

  doc.setFontSize(18);
  if (scoreInfo.score < 40) doc.setTextColor(239, 68, 68);
  else if (scoreInfo.score < 70) doc.setTextColor(245, 158, 11);
  else doc.setTextColor(34, 197, 94);
  doc.text(`${scoreInfo.score} / 100`, 145, 22);

  // Target Metadata Section
  let y = 45;
  doc.setTextColor(15, 23, 42);
  doc.setFontSize(12);
  doc.setFont('Helvetica', 'bold');
  doc.text('1. Target & Execution Profile', 14, y);

  y += 6;
  doc.setFontSize(9);
  doc.setFont('Helvetica', 'normal');
  doc.text(`Target Name: ${metadata.fileName || metadata.targetName || 'Artifact'}`, 14, y);
  y += 5;
  doc.text(`Analysis Mode: ${metadata.targetType || 'File Threat Scan'}`, 14, y);
  y += 5;
  doc.text(`Execution Privacy: ${metadata.privacyMode || '100% Client-Side Local'}`, 14, y);
  y += 5;
  if (metadata.sha256) {
    doc.text(`SHA-256: ${metadata.sha256}`, 14, y);
    y += 5;
  }

  // Findings Summary
  y += 5;
  doc.setFontSize(12);
  doc.setFont('Helvetica', 'bold');
  doc.text(`2. Detected Findings & Threats (${findings.length})`, 14, y);
  y += 8;

  if (findings.length === 0) {
    doc.setFontSize(9);
    doc.setFont('Helvetica', 'normal');
    doc.setTextColor(34, 197, 94);
    doc.text('No threat anomalies or malicious signatures were detected.', 14, y);
    y += 10;
  } else {
    findings.slice(0, 10).forEach((f, idx) => {
      if (y > 260) {
        doc.addPage();
        y = 20;
      }

      doc.setFontSize(9);
      doc.setFont('Helvetica', 'bold');

      if (f.severity === 'CRITICAL') doc.setTextColor(239, 68, 68);
      else if (f.severity === 'HIGH') doc.setTextColor(245, 158, 11);
      else doc.setTextColor(234, 179, 8);

      doc.text(`[${f.severity}] ${idx + 1}. ${f.title}`, 14, y);
      y += 5;

      doc.setFont('Helvetica', 'normal');
      doc.setTextColor(51, 65, 85);
      const splitDesc = doc.splitTextToSize(f.description || '', 180);
      doc.text(splitDesc, 14, y);
      y += (splitDesc.length * 4) + 2;

      doc.setTextColor(71, 85, 105);
      doc.text(`Source: ${f.source || 'N/A'} | Category: ${f.category || 'General'}`, 14, y);
      y += 6;
    });
  }

  // IOC Section
  if (y > 240) { doc.addPage(); y = 20; }
  doc.setFontSize(12);
  doc.setFont('Helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('3. Extracted Indicators of Compromise (IOCs)', 14, y);
  y += 6;

  doc.setFontSize(9);
  doc.setFont('Helvetica', 'normal');
  const ips = iocs.ips || [];
  const urls = iocs.urls || [];
  const domains = iocs.domains || [];

  doc.text(`IP Addresses (${ips.length}): ${ips.slice(0, 5).join(', ') || 'None'}`, 14, y); y += 5;
  doc.text(`Domains (${domains.length}): ${domains.slice(0, 5).join(', ') || 'None'}`, 14, y); y += 5;
  doc.text(`URLs (${urls.length}): ${urls.slice(0, 3).join(', ') || 'None'}`, 14, y); y += 8;

  // Footer / Sign-off
  doc.setFontSize(8);
  doc.setTextColor(148, 163, 184);
  doc.text('Sentry Console — Threat Intelligence Platform · Confidential Security Audit', 14, 285);

  const cleanName = (metadata.fileName || 'security_report').replace(/[^a-zA-Z0-9_-]/g, '_');
  doc.save(`Sentry_Report_${cleanName}.pdf`);
}

/** Fallback HTML print generator */
function generateHtmlPrintReport(metadata, scoreInfo, findings, iocs) {
  const win = window.open('', '_blank');
  if (!win) return;

  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Sentry Console Security Report</title>
      <style>
        body { font-family: monospace, sans-serif; background: #0f172a; color: #f8fafc; padding: 24px; }
        h1 { color: #38bdf8; margin-bottom: 4px; }
        .score-box { background: #1e293b; padding: 16px; border-radius: 8px; border: 1px solid #334155; margin-bottom: 20px; }
        .score { font-size: 28px; font-weight: bold; color: ${scoreInfo.color || '#38bdf8'}; }
        .finding { background: #1e293b; padding: 12px; margin-bottom: 12px; border-left: 4px solid #ef4444; border-radius: 4px; }
        .finding.HIGH { border-color: #f59e0b; }
        .finding.MEDIUM { border-color: #eab308; }
        .finding.LOW { border-color: #3b82f6; }
      </style>
    </head>
    <body>
      <h1>SENTRY CONSOLE SECURITY REPORT</h1>
      <div>Generated: ${new Date().toUTCString()}</div>
      <hr style="border-color:#334155; margin: 16px 0;" />

      <div class="score-box">
        <div>SECURITY SCORE</div>
        <div class="score">${scoreInfo.score ?? 100} / 100 — ${scoreInfo.riskLevel || 'CLEAN'}</div>
        <div>Target: ${metadata.fileName || 'Artifact'}</div>
      </div>

      <h2>Detected Findings (${findings.length})</h2>
      ${findings.map(f => `
        <div class="finding ${f.severity}">
          <strong>[${f.severity}] ${f.title}</strong>
          <p>${f.description}</p>
          <small>Source: ${f.source} | Recommendation: ${f.recommendation}</small>
        </div>
      `).join('') || '<p>No findings detected.</p>'}

      <script>window.print();</script>
    </body>
    </html>
  `;

  win.document.write(html);
  win.document.close();
}
