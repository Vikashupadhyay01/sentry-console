/**
 * Sentry Console Backend — Website & Domain Security Scan API
 * Evaluates Security Headers, SSL/TLS Certificates, DNS Records (SPF/DKIM/DMARC),
 * Tech Fingerprinting, and Basic Vulnerability Checks.
 */

import express from 'express';
import https from 'https';
import tls from 'tls';
import dns from 'dns/promises';
import { URL } from 'url';

export const router = express.Router();

/**
 * POST /api/scan/url
 * Body: { url: "https://example.com" }
 */
router.post('/url', async (req, res) => {
  let { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL parameter is required.' });

  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (err) {
    return res.status(400).json({ error: 'Invalid URL format.' });
  }

  const hostname = parsedUrl.hostname;
  console.log('[Backend Scan] Starting domain scan for:', hostname);

  try {
    // Run checks concurrently
    const [headersResult, tlsResult, dnsResult] = await Promise.allSettled([
      fetchHeadersAndTech(url),
      inspectTls(hostname),
      inspectDns(hostname)
    ]);

    const headersData = headersResult.status === 'fulfilled' ? headersResult.value : { findings: [], headers: {}, tech: [] };
    const tlsData     = tlsResult.status === 'fulfilled'     ? tlsResult.value     : { findings: [], cert: {} };
    const dnsData     = dnsResult.status === 'fulfilled'     ? dnsResult.value     : { findings: [], records: {} };

    const allFindings = [
      ...headersData.findings,
      ...tlsData.findings,
      ...dnsData.findings
    ];

    // Deduce Security Score
    let deduction = 0;
    allFindings.forEach(f => {
      if (f.severity === 'CRITICAL') deduction += 25;
      else if (f.severity === 'HIGH') deduction += 15;
      else if (f.severity === 'MEDIUM') deduction += 8;
      else if (f.severity === 'LOW') deduction += 3;
    });

    const score = Math.max(0, 100 - deduction);

    res.json({
      metadata: {
        targetName: hostname,
        targetUrl: url,
        targetType: 'Website & Domain Assessment',
        privacyMode: '🌐 BACKEND NETWORK LOOKUP',
        scanDate: new Date().toISOString()
      },
      score,
      riskLevel: score < 40 ? 'CRITICAL RISK' : score < 70 ? 'HIGH RISK' : score < 90 ? 'MODERATE RISK' : 'LOW RISK',
      findings: allFindings,
      iocs: {
        domains: [hostname],
        urls: [url],
        ips: dnsData.records?.aRecords || [],
        emails: [],
        hashes: []
      },
      artifacts: {
        headers: headersData.headers,
        techStack: headersData.tech,
        tlsCertificate: tlsData.cert,
        dnsRecords: dnsData.records
      }
    });

  } catch (err) {
    console.error('[Backend Scan] Error during scan:', err);
    res.status(500).json({ error: `Scan failed: ${err.message}` });
  }
});

/** Fetch HTTP Response Headers & Technology Fingerprints */
function fetchHeadersAndTech(targetUrl) {
  return new Promise((resolve) => {
    const findings = [];
    const headers = {};
    const tech = [];

    const req = https.get(targetUrl, { timeout: 8000, rejectUnauthorized: false }, (res) => {
      Object.assign(headers, res.headers);

      // Evaluate Security Headers
      if (!headers['strict-transport-security']) {
        findings.push({
          id: 'HDR-HIGH-NO-HSTS',
          title: 'Missing HTTP Strict Transport Security (HSTS)',
          severity: 'HIGH',
          category: 'Security Headers',
          description: 'Domain does not serve the Strict-Transport-Security header. Users are vulnerable to SSL stripping and man-in-the-middle downgrade attacks.',
          source: 'HTTP Response Headers',
          recommendation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" header.'
        });
      }

      if (!headers['content-security-policy']) {
        findings.push({
          id: 'HDR-HIGH-NO-CSP',
          title: 'Missing Content Security Policy (CSP)',
          severity: 'HIGH',
          category: 'Security Headers',
          description: 'No Content-Security-Policy header defined. Lacking CSP increases vulnerability to Cross-Site Scripting (XSS) and data injection.',
          source: 'HTTP Response Headers',
          recommendation: 'Implement a strict CSP header restricting script and connect directives.'
        });
      }

      if (!headers['x-frame-options']) {
        findings.push({
          id: 'HDR-MED-NO-XFO',
          title: 'Missing X-Frame-Options (Clickjacking Vulnerability)',
          severity: 'MEDIUM',
          category: 'Security Headers',
          description: 'Missing X-Frame-Options header allows the website to be framed inside third-party iframes, exposing users to clickjacking.',
          source: 'HTTP Response Headers',
          recommendation: 'Set "X-Frame-Options: DENY" or "SAMEORIGIN".'
        });
      }

      if (!headers['x-content-type-options']) {
        findings.push({
          id: 'HDR-LOW-NO-XCTO',
          title: 'Missing X-Content-Type-Options Header',
          severity: 'LOW',
          category: 'Security Headers',
          description: 'Missing X-Content-Type-Options: nosniff allows browsers to MIME-sniff response bodies away from declared content types.',
          source: 'HTTP Response Headers',
          recommendation: 'Set "X-Content-Type-Options: nosniff".'
        });
      }

      // Tech Fingerprinting
      if (headers['server']) {
        tech.push(`Server: ${headers['server']}`);
        if (/apache|nginx\/1\.[0-8]/i.test(headers['server'])) {
          findings.push({
            id: 'TECH-MED-OUTDATED-SERVER',
            title: `Server Technology Signature Disclosed (${headers['server']})`,
            severity: 'LOW',
            category: 'Information Disclosure',
            description: `Server banner discloses exact software version (${headers['server']}).`,
            source: 'Server Response Header',
            recommendation: 'Obfuscate or strip Server version banner.'
          });
        }
      }

      if (headers['x-powered-by']) {
        tech.push(`Powered-By: ${headers['x-powered-by']}`);
      }

      resolve({ findings, headers, tech });
    });

    req.on('error', (err) => {
      resolve({ findings, headers: {}, tech: [] });
    });

    req.setTimeout(8000, () => {
      req.destroy();
      resolve({ findings, headers: {}, tech: [] });
    });
  });
}

/** Inspect SSL/TLS Certificate & Cipher Suite */
function inspectTls(hostname) {
  return new Promise((resolve) => {
    const findings = [];
    let cert = {};

    const socket = tls.connect(443, hostname, { servername: hostname, timeout: 5000 }, () => {
      const peerCert = socket.getPeerCertificate();
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();

      cert = {
        subject: peerCert.subject?.CN || hostname,
        issuer: peerCert.issuer?.O || peerCert.issuer?.CN || 'Unknown Issuer',
        validFrom: peerCert.valid_from,
        validTo: peerCert.valid_to,
        protocol,
        cipherName: cipher?.name
      };

      // Check Expiry Date
      const validToDate = new Date(peerCert.valid_to);
      const daysRemaining = Math.floor((validToDate - new Date()) / (1000 * 60 * 60 * 24));

      if (daysRemaining < 0) {
        findings.push({
          id: 'TLS-CRIT-EXPIRED-CERT',
          title: 'SSL/TLS Certificate Expired',
          severity: 'CRITICAL',
          category: 'TLS Security',
          description: `SSL certificate expired ${Math.abs(daysRemaining)} days ago on ${peerCert.valid_to}. Browsers will block connections.`,
          source: 'TLS Certificate Inspection',
          recommendation: 'Renew SSL certificate immediately.'
        });
      } else if (daysRemaining < 15) {
        findings.push({
          id: 'TLS-HIGH-EXPIRING-SOON',
          title: `SSL Certificate Expiring Soon (${daysRemaining} days remaining)`,
          severity: 'HIGH',
          category: 'TLS Security',
          description: `SSL certificate will expire in ${daysRemaining} days.`,
          source: 'TLS Certificate Inspection',
          recommendation: 'Schedule certificate renewal before expiration.'
        });
      }

      // Check TLS Protocol Version
      if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
        findings.push({
          id: 'TLS-CRIT-DEPRECATED-PROTOCOL',
          title: `Deprecated TLS Protocol Supported (${protocol})`,
          severity: 'CRITICAL',
          category: 'TLS Security',
          description: `${protocol} is deprecated, insecure, and vulnerable to BEAST / POODLE attacks.`,
          source: 'TLS Handshake',
          recommendation: 'Disable TLS 1.0/1.1; enforce TLS 1.2 and TLS 1.3.'
        });
      }

      socket.end();
      resolve({ findings, cert });
    });

    socket.on('error', () => {
      resolve({ findings, cert: {} });
    });

    socket.setTimeout(5000, () => {
      socket.destroy();
      resolve({ findings, cert: {} });
    });
  });
}

/** Inspect DNS Records (SPF, DKIM, DMARC) */
async function inspectDns(hostname) {
  const findings = [];
  const records = { txtRecords: [], aRecords: [], spf: null, dmarc: null };

  try {
    const a = await dns.resolve4(hostname).catch(() => []);
    records.aRecords = a;

    const txt = await dns.resolveTxt(hostname).catch(() => []);
    records.txtRecords = txt.flat();

    // Check SPF record
    const spfRecord = records.txtRecords.find(r => r.startsWith('v=spf1'));
    if (spfRecord) {
      records.spf = spfRecord;
    } else {
      findings.push({
        id: 'DNS-HIGH-NO-SPF',
        title: 'Missing DNS SPF Record',
        severity: 'HIGH',
        category: 'DNS Email Security',
        description: 'Domain lacks an SPF (Sender Policy Framework) TXT record. Anyone can send spoofed emails claiming to originate from this domain.',
        source: `DNS TXT Query (${hostname})`,
        recommendation: 'Publish a valid v=spf1 TXT record defining authorized mail senders.'
      });
    }

    // Check DMARC record
    const dmarcTxt = await dns.resolveTxt(`_dmarc.${hostname}`).catch(() => []);
    const dmarcRecord = dmarcTxt.flat().find(r => r.startsWith('v=DMARC1'));
    if (dmarcRecord) {
      records.dmarc = dmarcRecord;
      if (dmarcRecord.includes('p=none')) {
        findings.push({
          id: 'DNS-MED-DMARC-NONE',
          title: 'DMARC Enforcement Policy Set to None (p=none)',
          severity: 'MEDIUM',
          category: 'DNS Email Security',
          description: 'DMARC record exists but uses policy p=none (monitoring mode only). Spoofed messages will still be delivered.',
          source: `DNS TXT Query (_dmarc.${hostname})`,
          recommendation: 'Upgrade DMARC policy from p=none to p=quarantine or p=reject.'
        });
      }
    } else {
      findings.push({
        id: 'DNS-HIGH-NO-DMARC',
        title: 'Missing DMARC Record (_dmarc)',
        severity: 'HIGH',
        category: 'DNS Email Security',
        description: 'Domain does not have a DMARC policy published at _dmarc record.',
        source: `DNS TXT Query (_dmarc.${hostname})`,
        recommendation: 'Publish a DMARC policy TXT record to block email spoofing.'
      });
    }

  } catch (err) {
    console.warn('[Backend Scan] DNS resolution error:', err);
  }

  return { findings, records };
}
