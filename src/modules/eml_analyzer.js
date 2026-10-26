/**
 * Sentry Console — Email (.eml) Static Threat Analyzer
 * Parses RFC 822 MIME headers, SPF/DKIM/DMARC authentication results,
 * detects sender spoofing, anchor text mismatches, phishing triggers, and risky attachments.
 * 100% Client-Side. Privacy Preserved.
 */

/**
 * Analyze an EML / MSG email file for phishing and email spoofing threats.
 * @param {ArrayBuffer} buffer
 * @param {string} fileName
 * @returns {object} Analysis result containing metadata, findings, and extracted IOCs.
 */
export function analyzeEml(buffer, fileName) {
  console.log('[EML Analyzer] Analyzing EML file:', fileName, 'Size:', buffer.byteLength, 'bytes');

  const textDecoder = new TextDecoder('utf-8', { fatal: false });
  const rawEmail = textDecoder.decode(buffer);

  const findings = [];
  const iocs = { ips: [], domains: [], urls: [], emails: [], hashes: [] };

  // Split headers and body
  const headerBodySplit = rawEmail.split(/\r?\n\r?\n/);
  const rawHeaders = headerBodySplit[0] || '';
  const rawBody = headerBodySplit.slice(1).join('\n\n') || '';

  // Parse Headers
  const headers = parseHeaders(rawHeaders);

  const metadata = {
    fileName,
    fileSize: buffer.byteLength,
    from: headers['from'] || 'Unknown',
    to: headers['to'] || 'Unknown',
    subject: headers['subject'] || '(No Subject)',
    date: headers['date'] || 'Unknown',
    returnPath: headers['return-path'] || 'N/A',
    replyTo: headers['reply-to'] || 'N/A',
    mailer: headers['x-mailer'] || headers['user-agent'] || 'Unknown',
    spfStatus: 'Not Evaluated',
    dkimStatus: 'Not Evaluated',
    dmarcStatus: 'Not Evaluated',
    attachmentCount: 0
  };

  // 1. Extract Email Addresses into IOCs
  if (headers['from']) extractEmails(headers['from'], iocs.emails);
  if (headers['to']) extractEmails(headers['to'], iocs.emails);
  if (headers['reply-to']) extractEmails(headers['reply-to'], iocs.emails);
  if (headers['return-path']) extractEmails(headers['return-path'], iocs.emails);

  // 2. Sender Spoofing Analysis (From vs Return-Path / Reply-To)
  const fromDomain = extractDomainFromEmail(headers['from']);
  const returnPathDomain = extractDomainFromEmail(headers['return-path']);
  const replyToDomain = extractDomainFromEmail(headers['reply-to']);

  if (fromDomain) iocs.domains.push(fromDomain);
  if (returnPathDomain) iocs.domains.push(returnPathDomain);
  if (replyToDomain) iocs.domains.push(replyToDomain);

  if (fromDomain && returnPathDomain && fromDomain.toLowerCase() !== returnPathDomain.toLowerCase()) {
    findings.push({
      id: 'EML-CRIT-SPOOF-RETURNPATH',
      title: 'Sender Address Domain Mismatch (Return-Path Spoofing)',
      severity: 'CRITICAL',
      category: 'Sender Spoofing',
      description: `The claimed From header domain ('${fromDomain}') does not match the actual Return-Path address domain ('${returnPathDomain}'). This is a strong indicator of email spoofing.`,
      source: `From: ${headers['from']} | Return-Path: ${headers['return-path']}`,
      recommendation: 'Treat email sender with extreme suspicion; do not click embedded links or download attachments.'
    });
  }

  if (fromDomain && replyToDomain && fromDomain.toLowerCase() !== replyToDomain.toLowerCase()) {
    findings.push({
      id: 'EML-HIGH-SPOOF-REPLYTO',
      title: 'Reply-To Address Mismatch',
      severity: 'HIGH',
      category: 'Sender Spoofing',
      description: `Replies will be routed to '${headers['reply-to']}', which differs from the From address ('${headers['from']}'). Attackers use Reply-To redirection to hijack victim responses.`,
      source: `From: ${headers['from']} | Reply-To: ${headers['reply-to']}`,
      recommendation: 'Verify the recipient identity before responding.'
    });
  }

  // 3. SPF / DKIM / DMARC Authentication Header Analysis
  const receivedSpf = headers['received-spf'] || '';
  const authResults = headers['authentication-results'] || '';

  if (/pass/i.test(receivedSpf) || /spf=pass/i.test(authResults)) {
    metadata.spfStatus = 'PASS';
  } else if (/fail|softfail/i.test(receivedSpf) || /spf=fail|spf=softfail/i.test(authResults)) {
    metadata.spfStatus = 'FAIL';
    findings.push({
      id: 'EML-HIGH-SPF-FAIL',
      title: 'SPF Authentication Failed',
      severity: 'HIGH',
      category: 'Authentication',
      description: 'Received-SPF header reports SPF verification failed or soft-failed for the originating sending server IP.',
      source: `Received-SPF: ${receivedSpf || authResults}`,
      recommendation: 'Reject or quarantine message due to failed SPF sender verification.'
    });
  }

  if (/dkim=pass/i.test(authResults)) {
    metadata.dkimStatus = 'PASS';
  } else if (/dkim=fail/i.test(authResults)) {
    metadata.dkimStatus = 'FAIL';
    findings.push({
      id: 'EML-HIGH-DKIM-FAIL',
      title: 'DKIM Signature Authentication Failed',
      severity: 'HIGH',
      category: 'Authentication',
      description: 'DKIM cryptographic signature verification failed, indicating the message body or headers were modified in transit.',
      source: `Authentication-Results: ${authResults}`,
      recommendation: 'Do not trust email contents due to broken cryptographic signature integrity.'
    });
  }

  if (/dmarc=pass/i.test(authResults)) {
    metadata.dmarcStatus = 'PASS';
  } else if (/dmarc=fail/i.test(authResults)) {
    metadata.dmarcStatus = 'FAIL';
    findings.push({
      id: 'EML-CRIT-DMARC-FAIL',
      title: 'DMARC Verification Failed',
      severity: 'CRITICAL',
      category: 'Authentication',
      description: 'DMARC alignment check failed for the sending domain, confirming spoofed email origin.',
      source: `Authentication-Results: ${authResults}`,
      recommendation: 'Drop message immediately according to domain DMARC policy.'
    });
  }

  // 4. Body Link & Anchor Discrepancy Extraction
  const links = extractUrlsFromBody(rawBody);
  links.forEach(l => {
    iocs.urls.push(l.url);
    if (l.domain) iocs.domains.push(l.domain);

    if (l.isMismatchedAnchor) {
      findings.push({
        id: 'EML-CRIT-ANCHOR-MISMATCH',
        title: 'Phishing Anchor Link Text Mismatch',
        severity: 'CRITICAL',
        category: 'Phishing',
        description: `Visible link text displays '${l.anchorText}' but actual hyperlink destination points to '${l.url}'. This deceptive technique is used to deceive users into visiting fraudulent websites.`,
        source: `Body Link: <a href="${l.url}">${l.anchorText}</a>`,
        recommendation: 'Do not visit the destination link; report phishing attempt to SOC.'
      });
    }
  });

  // 5. Phishing Keywords & High Urgency Heuristics
  const phishingTriggerRegex = /(account\s+suspended|verify\s+your\s+identity|unauthorized\s+login|action\s+required|wire\s+transfer|urgent\s+payment|password\s+expir|click\s+here\s+immediately|security\s+alert)/gi;
  const triggerMatches = [...rawBody.matchAll(phishingTriggerRegex)];

  if (triggerMatches.length >= 2) {
    findings.push({
      id: 'EML-HIGH-PHISHING-TRIGGER',
      title: 'High-Urgency Phishing Language Detected',
      severity: 'HIGH',
      category: 'Phishing Heuristic',
      description: `Email body contains ${triggerMatches.length} high-urgency phishing phrase(s): ${triggerMatches.map(m => `"${m[0]}"`).slice(0, 3).join(', ')}. Social engineering attacks use artificial urgency to trick targets.`,
      source: `Email Body Text`,
      recommendation: 'Out-of-band verify request with sender before taking action.'
    });
  }

  // 6. Attachment Scanning & Risky Extensions
  const attachmentRegex = /Content-Disposition:\s*attachment;?\s*filename=["']?([^"'\r\n;]+)["']?/gi;
  const attachmentMatches = [...rawEmail.matchAll(attachmentRegex)];
  metadata.attachmentCount = attachmentMatches.length;

  const riskyExtensions = ['.exe', '.scr', '.vbs', '.js', '.bat', '.cmd', '.ps1', '.zip', '.iso', '.docm', '.xlsm', '.jar', '.hta'];

  attachmentMatches.forEach(m => {
    const attName = m[1];
    const attExt = '.' + (attName.split('.').pop()?.toLowerCase() || '');

    if (riskyExtensions.includes(attExt)) {
      findings.push({
        id: 'EML-CRIT-RISKY-ATTACHMENT',
        title: `High-Risk Executable/Macro Attachment (${attName})`,
        severity: 'CRITICAL',
        category: 'Malicious Attachment',
        description: `Email includes attachment '${attName}' with executable or scriptable extension '${attExt}'. Opening this attachment can cause arbitrary remote code execution.`,
        source: `Attachment: ${attName}`,
        recommendation: 'Block and purge attachment. Never open executable email attachments.'
      });
    }
  });

  // Clean IOC sets
  iocs.urls = [...new Set(iocs.urls)];
  iocs.domains = [...new Set(iocs.domains)];
  iocs.emails = [...new Set(iocs.emails)];

  return {
    metadata,
    findings,
    iocs,
    artifacts: {
      headers,
      attachmentCount: metadata.attachmentCount,
      spf: metadata.spfStatus,
      dkim: metadata.dkimStatus,
      dmarc: metadata.dmarcStatus,
      extractedLinks: iocs.urls
    }
  };
}

/** Helper: Parse RFC 822 raw headers into key-value map */
function parseHeaders(rawHeaders) {
  const headers = {};
  const lines = rawHeaders.split(/\r?\n/);
  let currentKey = null;

  lines.forEach(line => {
    if (/^\s+/.test(line) && currentKey) {
      headers[currentKey] += ' ' + line.trim();
    } else {
      const colonIdx = line.indexOf(':');
      if (colonIdx > 0) {
        currentKey = line.substring(0, colonIdx).toLowerCase().trim();
        headers[currentKey] = line.substring(colonIdx + 1).trim();
      }
    }
  });

  return headers;
}

/** Helper: Extract email address domain */
function extractDomainFromEmail(emailStr) {
  if (!emailStr) return null;
  const match = emailStr.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  return match ? match[1].toLowerCase() : null;
}

/** Helper: Extract email addresses into array */
function extractEmails(str, emailArray) {
  const matches = str.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
  matches.forEach(e => emailArray.push(e.toLowerCase()));
}

/** Helper: Extract URLs and anchor mismatches from HTML / Body */
function extractUrlsFromBody(bodyText) {
  const links = [];
  const urlRegex = /https?:\/\/[^\s<>"'\r\n)]+/gi;
  const rawUrls = bodyText.match(urlRegex) || [];

  rawUrls.forEach(url => {
    try {
      const parsed = new URL(url);
      links.push({ url, domain: parsed.hostname, isMismatchedAnchor: false, anchorText: url });
    } catch (e) { /* ignore */ }
  });

  // Extract HTML anchor links <a href="URL">TEXT</a>
  const anchorRegex = /<a\s+[^>]*href=["'](https?:\/\/[^"']+)["'][^>]*>(.*?)<\/a>/gi;
  const anchorMatches = [...bodyText.matchAll(anchorRegex)];

  anchorMatches.forEach(m => {
    const hrefUrl = m[1];
    const anchorText = m[2].replace(/<[^>]+>/g, '').trim();

    try {
      const hrefDomain = new URL(hrefUrl).hostname.toLowerCase();

      // Check if anchor text looks like a domain/URL e.g. "www.paypal.com"
      const textAsDomainMatch = anchorText.match(/(?:https?:\/\/)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
      if (textAsDomainMatch) {
        const textDomain = textAsDomainMatch[1].toLowerCase();
        if (textDomain !== hrefDomain && !textDomain.includes(hrefDomain) && !hrefDomain.includes(textDomain)) {
          links.push({
            url: hrefUrl,
            domain: hrefDomain,
            isMismatchedAnchor: true,
            anchorText: anchorText
          });
        }
      }
    } catch (e) { /* ignore */ }
  });

  return links;
}
