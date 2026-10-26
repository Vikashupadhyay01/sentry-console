/**
 * Sentry Console — PDF Static Threat Analyzer
 * Inspects PDF objects, streams, embedded JavaScript, auto-launchers, and structural anomalies.
 * 100% Client-Side. Privacy Preserved.
 */

/**
 * Analyze a PDF ArrayBuffer for security threats.
 * @param {ArrayBuffer} buffer
 * @param {string} fileName
 * @returns {object} Analysis result containing metadata, findings, and extracted IOCs.
 */
export function analyzePdf(buffer, fileName) {
  console.log('[PDF Analyzer] Analyzing PDF:', fileName, 'Size:', buffer.byteLength, 'bytes');

  const textDecoder = new TextDecoder('latin1'); // Use latin1 to safely parse binary streams as string
  const pdfString = textDecoder.decode(buffer);

  const findings = [];
  const iocs = { ips: [], domains: [], urls: [], emails: [], hashes: [] };
  const metadata = {
    fileName,
    fileSize: buffer.byteLength,
    pdfVersion: 'Unknown',
    objectCount: 0,
    streamCount: 0,
    isEncrypted: false,
    hasEmbeddedFiles: false,
    hasJavaScript: false,
  };

  // 1. PDF Version Check
  const versionMatch = pdfString.match(/%PDF-(\d+\.\d+)/);
  if (versionMatch) {
    metadata.pdfVersion = versionMatch[1];
  } else {
    findings.push({
      id: 'PDF-ANOMALY-HEADER',
      title: 'Malformed PDF Header',
      severity: 'MEDIUM',
      category: 'Structural Anomaly',
      description: 'The file lacks a standard %PDF-x.x header declaration at the start.',
      source: 'PDF Header',
      recommendation: 'Verify file source; malformed headers can bypass security scanners.'
    });
  }

  // 2. Count Objects & Streams
  const objects = pdfString.match(/\d+\s+\d+\s+obj/g) || [];
  metadata.objectCount = objects.length;

  const streams = pdfString.match(/stream[\r\n]/g) || [];
  metadata.streamCount = streams.length;

  // 3. Embedded JavaScript Detection (/JS or /JavaScript)
  const jsMatches = pdfString.match(/\/JavaScript|\/JS\b/gi);
  if (jsMatches) {
    metadata.hasJavaScript = true;
    findings.push({
      id: 'PDF-CRIT-JS',
      title: 'Embedded JavaScript Code Detected',
      severity: 'CRITICAL',
      category: 'Executable Code',
      description: `PDF contains ${jsMatches.length} embedded JavaScript directive(s) (/JavaScript or /JS). Embedded scripts in PDFs are a primary vector for client-side exploitation.`,
      source: `PDF Document Stream (${jsMatches.length} occurrence(s))`,
      recommendation: 'Open this document only in an isolated sandbox or disable JavaScript in your PDF reader.'
    });
  }

  // 4. Auto-Execution Triggers (/OpenAction, /AA, /Launch)
  if (/\/OpenAction\b/i.test(pdfString)) {
    findings.push({
      id: 'PDF-CRIT-OPENACTION',
      title: 'Auto-Execute OpenAction Directive',
      severity: 'CRITICAL',
      category: 'Auto-Execution',
      description: 'PDF contains an /OpenAction dictionary key which executes code or script immediately upon opening the document without user interaction.',
      source: 'PDF Catalog Dictionary (/OpenAction)',
      recommendation: 'Do not view with auto-executing PDF viewers. Audit the action target.'
    });
  }

  if (/\/AA\b/i.test(pdfString)) {
    findings.push({
      id: 'PDF-HIGH-AA',
      title: 'Additional Actions (AA) Trigger Present',
      severity: 'HIGH',
      category: 'Auto-Execution',
      description: 'PDF contains /AA (Additional Actions) triggers that execute commands when pages are turned, buttons clicked, or fields focused.',
      source: 'PDF Page / Field Dictionary (/AA)',
      recommendation: 'Inspect event triggers for hidden payload execution.'
    });
  }

  if (/\/Launch\b/i.test(pdfString)) {
    findings.push({
      id: 'PDF-CRIT-LAUNCH',
      title: 'External Application / Shell Launch Action',
      severity: 'CRITICAL',
      category: 'Code Execution',
      description: 'PDF contains a /Launch action dictionary, designed to launch an external executable file or local system command.',
      source: 'Action Dictionary (/Launch)',
      recommendation: 'Block document execution. High risk of local command invocation.'
    });
  }

  // 5. Embedded Files & Attachments (/EmbeddedFiles, /EF, /FileSpec)
  if (/\/EmbeddedFiles|\/EF\b|\/FileSpec\b/i.test(pdfString)) {
    metadata.hasEmbeddedFiles = true;
    findings.push({
      id: 'PDF-HIGH-EMBEDDED',
      title: 'Embedded Attachment / Payload File',
      severity: 'HIGH',
      category: 'Embedded Content',
      description: 'PDF contains embedded binary attachments (/EmbeddedFiles or /EF). Attackers conceal executables, macros, or scripts inside PDF containers.',
      source: 'Name Dictionary (/EmbeddedFiles)',
      recommendation: 'Extract attachments in an isolated environment before opening.'
    });
  }

  // 6. Suspicious External Links & Form Submissions (/URI, /SubmitForm)
  const uriMatches = [...pdfString.matchAll(/\/URI\s*\(([^)]+)\)/gi)];
  uriMatches.forEach(m => {
    const url = m[1];
    if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
      iocs.urls.push(url);
      try {
        const parsedUrl = new URL(url);
        iocs.domains.push(parsedUrl.hostname);
      } catch (e) { /* ignore invalid URL parse */ }
    }
  });

  if (uriMatches.length > 0) {
    findings.push({
      id: 'PDF-MED-URI',
      title: 'External Web Links / URIs Extracted',
      severity: 'MEDIUM',
      category: 'External Referral',
      description: `PDF contains ${uriMatches.length} external URL reference(s) (/URI). Attackers place links to credential harvest or download external drop files.`,
      source: `PDF Annotations (${uriMatches.length} link(s))`,
      recommendation: 'Verify link destinations prior to clicking.'
    });
  }

  if (/\/SubmitForm\b/i.test(pdfString)) {
    findings.push({
      id: 'PDF-HIGH-SUBMITFORM',
      title: 'Form Data Exfiltration (/SubmitForm)',
      severity: 'HIGH',
      category: 'Data Exfiltration',
      description: 'PDF contains a /SubmitForm action designed to silently transmit form input or document data to an external remote web server.',
      source: 'Action Dictionary (/SubmitForm)',
      recommendation: 'Inspect remote endpoint destination for potential data harvesting.'
    });
  }

  // 7. Obfuscation Techniques (Multiple /Filter streams, /ASCIIHexDecode)
  if (/\/Filter\s*\[\s*\/\w+\s+\/\w+/i.test(pdfString)) {
    findings.push({
      id: 'PDF-MED-OBFUSCATION',
      title: 'Multi-Layer Stream Obfuscation Filter',
      severity: 'MEDIUM',
      category: 'Obfuscation',
      description: 'PDF stream uses multiple nested compression filters (e.g. FlateDecode + ASCIIHexDecode) to evade static text scanners.',
      source: 'PDF Stream Filter Array',
      recommendation: 'Decompress streams using deep analysis tools to inspect raw stream payloads.'
    });
  }

  // 8. End of File (EOF) Marker Anomaly Check
  const eofMatches = pdfString.match(/%%EOF/g);
  if (!eofMatches) {
    findings.push({
      id: 'PDF-LOW-EOF',
      title: 'Missing End-Of-File (%%EOF) Marker',
      severity: 'LOW',
      category: 'Structural Anomaly',
      description: 'Document is missing the mandatory %%EOF trailer signature, indicating possible stream truncation or appended hidden trailing bytes.',
      source: 'PDF File Structure',
      recommendation: 'Inspect trailing bytes for hidden data appended after the file body.'
    });
  } else if (eofMatches.length > 1) {
    findings.push({
      id: 'PDF-MED-INCREMENTAL',
      title: 'Multiple Incremental Update Sections',
      severity: 'MEDIUM',
      category: 'Structural Anomaly',
      description: `File contains ${eofMatches.length} %%EOF markers indicating incremental updates. Incremental updates are sometimes used to append malicious revisions to benign documents.`,
      source: `PDF Revision History (${eofMatches.length} sections)`,
      recommendation: 'Review PDF revision history to inspect modified objects.'
    });
  }

  // De-duplicate IOC arrays
  iocs.urls = [...new Set(iocs.urls)];
  iocs.domains = [...new Set(iocs.domains)];

  return {
    metadata,
    findings,
    iocs,
    artifacts: {
      objectsCount: metadata.objectCount,
      streamsCount: metadata.streamCount,
      jsDetected: metadata.hasJavaScript,
      embeddedFiles: metadata.hasEmbeddedFiles,
      extractedLinks: iocs.urls
    }
  };
}
