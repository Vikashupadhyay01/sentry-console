/**
 * Sentry Console — Office Document Threat Analyzer
 * Inspects DOCX/XLSX/PPTX (ZIP containers) and legacy OLE documents for VBA macros (vbaProject.bin),
 * remote template injection (.rels), embedded OLE objects, and ActiveX controls.
 * 100% Client-Side. Privacy Preserved.
 */

/**
 * Analyze an Office document for security threats.
 * @param {ArrayBuffer} buffer
 * @param {string} fileName
 * @returns {object} Analysis result containing metadata, findings, and extracted IOCs.
 */
export function analyzeOfficeDoc(buffer, fileName) {
  console.log('[Office Analyzer] Analyzing Office document:', fileName, 'Size:', buffer.byteLength, 'bytes');

  const textDecoder = new TextDecoder('latin1');
  const binaryText = textDecoder.decode(buffer);

  const findings = [];
  const iocs = { ips: [], domains: [], urls: [], emails: [], hashes: [] };

  const metadata = {
    fileName,
    fileSize: buffer.byteLength,
    isMacroPresent: false,
    hasExternalTemplate: false,
    hasEmbeddedOle: false,
    hasActiveX: false,
    format: fileName.endsWith('.doc') || fileName.endsWith('.xls') ? 'OLE2 Legacy Office' : 'Office Open XML (ZIP)'
  };

  // 1. VBA Macro Detection (vbaProject.bin)
  if (binaryText.includes('vbaProject.bin') || binaryText.includes('VBA/dir') || binaryText.includes('PROJECTwm')) {
    metadata.isMacroPresent = true;

    // Check for Auto-Exec macro procedures inside VBA stream
    const hasAutoOpen = /AutoOpen|Document_Open|AutoExec|Workbook_Open|Auto_Open/i.test(binaryText);

    findings.push({
      id: 'OFFICE-CRIT-VBA-MACRO',
      title: hasAutoOpen ? 'Auto-Executing VBA Macro Detected (AutoOpen)' : 'VBA Macro Binary Present (vbaProject.bin)',
      severity: 'CRITICAL',
      category: 'Macro Code',
      description: hasAutoOpen
        ? 'Office document contains an auto-executing VBA macro (AutoOpen / Document_Open) that runs automatically upon opening document.'
        : 'Office document contains embedded VBA macro code (vbaProject.bin). Macros can run arbitrary PowerShell, cmd commands, or download payloads.',
      source: 'word/vbaProject.bin Container',
      recommendation: 'Do not enable macros or edit mode in Microsoft Office.'
    });
  }

  // 2. Remote Template Injection (.rels files containing TargetMode="External")
  const externalRelMatches = [...binaryText.matchAll(/TargetMode=["']External["']\s+Target=["'](https?:\/\/[^"']+)["']/gi)];
  externalRelMatches.forEach(m => {
    const targetUrl = m[1];
    iocs.urls.push(targetUrl);
    metadata.hasExternalTemplate = true;

    try {
      iocs.domains.push(new URL(targetUrl).hostname);
    } catch (e) { /* ignore */ }

    findings.push({
      id: 'OFFICE-CRIT-TEMPLATE-INJECTION',
      title: 'Remote Template Injection Attack',
      severity: 'CRITICAL',
      category: 'Remote Injection',
      description: `Document relationship connects to an external remote target template '${targetUrl}'. Attackers use remote template injection to fetch malicious DOTM templates containing macros while bypassing initial email scanners.`,
      source: 'word/_rels/settings.xml.rels',
      recommendation: 'Block remote template fetches at the perimeter firewall.'
    });
  });

  // 3. Embedded OLE Objects & ActiveX Controls
  if (binaryText.includes('oleObject') || binaryText.includes('embeddings/')) {
    metadata.hasEmbeddedOle = true;
    findings.push({
      id: 'OFFICE-HIGH-OLE-OBJECT',
      title: 'Embedded OLE Object / Binary Package',
      severity: 'HIGH',
      category: 'Embedded Content',
      description: 'Document contains embedded OLE objects or binary packages. OLE objects can drop executables or exploit MS Office memory corruption vulnerabilities (e.g. CVE-2017-11882 EQNEDT32).',
      source: 'word/embeddings/ Directory',
      recommendation: 'Audit embedded objects using forensic extraction tools.'
    });
  }

  if (binaryText.includes('activeX') || binaryText.includes('activeXControls')) {
    metadata.hasActiveX = true;
    findings.push({
      id: 'OFFICE-HIGH-ACTIVEX',
      title: 'ActiveX Control Present',
      severity: 'HIGH',
      category: 'Embedded Control',
      description: 'Document contains ActiveX controls. ActiveX controls increase attack surface for browser and Office vulnerabilities.',
      source: 'word/activeX/ Directory',
      recommendation: 'Disable ActiveX control execution in Office Trust Center.'
    });
  }

  // 4. Extract URLs embedded in document text
  const urlRegex = /https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"'\r\n)]*/gi;
  const rawUrls = binaryText.match(urlRegex) || [];
  rawUrls.forEach(u => {
    if (!u.includes('schemas.openxmlformats.org') && !u.includes('schemas.microsoft.com') && !u.includes('w3.org')) {
      iocs.urls.push(u);
      try { iocs.domains.push(new URL(u).hostname); } catch (e) {}
    }
  });

  // Clean IOC sets
  iocs.urls = [...new Set(iocs.urls)];
  iocs.domains = [...new Set(iocs.domains)];

  return {
    metadata,
    findings,
    iocs,
    artifacts: {
      format: metadata.format,
      macroDetected: metadata.isMacroPresent,
      templateInjection: metadata.hasExternalTemplate,
      oleObjectsCount: metadata.hasEmbeddedOle ? 1 : 0,
      extractedUrls: iocs.urls
    }
  };
}
