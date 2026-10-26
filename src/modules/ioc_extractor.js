/**
 * Sentry Console — Cross-Cutting IOC Extractor & Threat Intelligence Layer
 * Normalizes IOCs (IPs, Domains, URLs, Emails, Hashes) across all artifact types,
 * flags suspicious patterns (typosquatting, unusual TLDs, IP URLs),
 * and provides optional user-supplied VirusTotal API lookups.
 */

const HIGH_RISK_TLDS = new Set([
  'xyz', 'top', 'zip', 'ru', 'country', 'click', 'link', 'work',
  'gq', 'cf', 'tk', 'ml', 'ga', 'buzz', 'fit', 'monster', 'rest'
]);

const TYPOSQUAT_PATTERNS = [
  /paypa[1l]/i, /g[0o]{2}gle/i, /m[1i]cr[0o]s[0o]ft/i, /am[a4]z[0o]n/i,
  /b[a4]nk/i, /secure[0-9]/i, /verify[0-9]/i, /support[0-9]/i
];

/**
 * Process and enrich an IOC collection object.
 * @param {object} rawIocs { ips: [], domains: [], urls: [], emails: [], hashes: [] }
 * @returns {object} Processed IOCs with flag indicators and findings.
 */
export function processIocs(rawIocs = {}) {
  const iocs = {
    ips: [...new Set(rawIocs.ips || [])],
    domains: [...new Set(rawIocs.domains || [])],
    urls: [...new Set(rawIocs.urls || [])],
    emails: [...new Set(rawIocs.emails || [])],
    hashes: [...new Set(rawIocs.hashes || [])]
  };

  const flaggedItems = [];
  const findings = [];

  // 1. Domain Heuristics (High-risk TLDs & Typosquatting)
  iocs.domains.forEach(domain => {
    const tld = domain.split('.').pop()?.toLowerCase();

    if (HIGH_RISK_TLDS.has(tld)) {
      flaggedItems.push({ type: 'domain', value: domain, reason: `High-risk TLD (.${tld})` });
      findings.push({
        id: `IOC-DOMAIN-TLD-${domain}`,
        title: `High-Risk Top Level Domain Detected (${domain})`,
        severity: 'HIGH',
        category: 'Threat Intelligence',
        description: `Extracted domain '${domain}' uses a high-risk TLD (.${tld}) heavily abused in malware distribution campaigns.`,
        source: `Extracted Domain: ${domain}`,
        recommendation: 'Block DNS resolution for high-risk TLD destination.'
      });
    }

    TYPOSQUAT_PATTERNS.forEach(pat => {
      if (pat.test(domain) && !domain.endsWith('.paypal.com') && !domain.endsWith('.google.com') && !domain.endsWith('.microsoft.com') && !domain.endsWith('.amazon.com')) {
        flaggedItems.push({ type: 'domain', value: domain, reason: 'Suspected Typosquatted Domain' });
        findings.push({
          id: `IOC-DOMAIN-TYPO-${domain}`,
          title: `Suspected Typosquatted Domain (${domain})`,
          severity: 'CRITICAL',
          category: 'Phishing Intelligence',
          description: `Extracted domain '${domain}' matches known typosquatting patterns designed to impersonate legitimate brand domains.`,
          source: `Extracted Domain: ${domain}`,
          recommendation: 'Blacklist typosquatted domain in perimeter DNS.'
        });
      }
    });
  });

  // 2. URL Heuristics (Raw IP URLs)
  iocs.urls.forEach(url => {
    if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
      flaggedItems.push({ type: 'url', value: url, reason: 'Direct IP Host URL' });
      findings.push({
        id: `IOC-URL-IP-${url}`,
        title: `Direct IP Address Web URL (${url})`,
        severity: 'HIGH',
        category: 'Threat Intelligence',
        description: `Extracted URL '${url}' uses a raw numeric IP address instead of a registered domain name. Legitimate web services rarely host production endpoints directly on raw IPs.`,
        source: `Extracted URL: ${url}`,
        recommendation: 'Restrict direct IP outbound web access.'
      });
    }
  });

  return {
    iocs,
    flaggedItems,
    findings,
    summary: {
      totalIps: iocs.ips.length,
      totalDomains: iocs.domains.length,
      totalUrls: iocs.urls.length,
      totalEmails: iocs.emails.length,
      totalHashes: iocs.hashes.length,
      flaggedCount: flaggedItems.length
    }
  };
}

/**
 * Perform optional VirusTotal API lookup for a file hash if user provided API Key.
 * @param {string} hash SHA-256 or MD5 hash string
 * @returns {Promise<object|null>}
 */
export async function lookupVirusTotal(hash) {
  const apiKey = localStorage.getItem('sentry_vt_api_key');
  if (!apiKey) return null;

  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { 'x-apikey': apiKey }
    });

    if (!res.ok) return null;
    const data = await res.json();
    const stats = data?.data?.attributes?.last_analysis_stats;

    if (stats) {
      return {
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        harmless: stats.harmless || 0,
        undetected: stats.undetected || 0,
        total: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0),
        permalink: `https://www.virustotal.com/gui/file/${hash}`
      };
    }
  } catch (err) {
    console.warn('[VirusTotal] Lookup error:', err);
  }
  return null;
}
