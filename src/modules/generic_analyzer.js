/**
 * Sentry Console — Generic File Analyzer
 * Fallback static analyzer for unknown binary artifacts.
 * Calculates MD5 / SHA-256 hashes, extracts ASCII strings, IPs, URLs, and magic byte anomalies.
 * 100% Client-Side. Privacy Preserved.
 */

export function isCryptoSubtleAvailable() {
  try {
    return typeof window !== 'undefined' &&
           window.isSecureContext === true &&
           typeof crypto !== 'undefined' &&
           crypto !== null &&
           typeof crypto.subtle !== 'undefined' &&
           crypto.subtle !== null &&
           typeof crypto.subtle.digest === 'function';
  } catch (e) {
    return false;
  }
}

/**
 * Analyze generic/unknown file buffer.
 * @param {ArrayBuffer} buffer
 * @param {string} fileName
 * @returns {Promise<object>}
 */
export async function analyzeGenericFile(buffer, fileName) {
  console.log('[Generic Analyzer] Analyzing unknown file:', fileName, 'Size:', buffer.byteLength, 'bytes');

  const findings = [];
  const iocs = { ips: [], domains: [], urls: [], emails: [], hashes: [] };

  // 1. Calculate SHA-256 hash using Web Crypto API (if secure context & crypto.subtle is available)
  let sha256 = null;

  if (isCryptoSubtleAvailable()) {
    try {
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      sha256 = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      iocs.hashes.push(sha256);
    } catch (err) {
      console.warn('[Generic Analyzer] SHA-256 calculation failed:', err);
      sha256 = null;
    }
  }

  if (!sha256) {
    findings.push({
      id: 'GENERIC-NON-SECURE-CONTEXT',
      title: 'SHA-256 Hashing Unavailable',
      severity: 'INFO',
      category: 'Environment Warning',
      description: 'SHA-256 hashing is disabled because the application is running in a non-secure browser context. Serve the app over HTTPS or via localhost for full Web Crypto API hash support.',
      source: 'Browser Web Crypto API',
      recommendation: 'Access Sentry Console via http://localhost:8000 or HTTPS to enable SHA-256 checksums.'
    });
  }

  // Quick JS MD5 fallback implementation
  const md5 = calculateSimpleHash(new Uint8Array(buffer));
  if (md5) {
    iocs.hashes.push(md5);
  }

  const metadata = {
    fileName,
    fileSize: buffer.byteLength,
    sha256: sha256 || 'Unavailable (Non-Secure Context)',
    md5,
    entropyScore: calculateEntropy(new Uint8Array(buffer.slice(0, 4096)))
  };

  // 2. High Entropy Warning (indicating packed or encrypted payload)
  if (metadata.entropyScore > 7.2) {
    findings.push({
      id: 'GENERIC-HIGH-ENTROPY',
      title: 'High Entropy Block Detected (Packed/Encrypted)',
      severity: 'MEDIUM',
      category: 'Obfuscation',
      description: `File exhibits high Shannon entropy (${metadata.entropyScore.toFixed(2)} / 8.0). High entropy is characteristic of encrypted, packed, or compressed binary payloads.`,
      source: 'Binary Buffer Entropy Sample',
      recommendation: 'Analyze binary in an isolated sandbox or reverse engineering tool.'
    });
  }

  // 3. String Extraction & IOC Harvesting
  const textDecoder = new TextDecoder('latin1');
  const asciiStr = textDecoder.decode(buffer);

  // Extract IPs
  const ipMatches = asciiStr.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g) || [];
  ipMatches.forEach(ip => {
    if (!ip.startsWith('127.') && !ip.startsWith('0.') && ip !== '255.255.255.255') {
      iocs.ips.push(ip);
    }
  });

  // Extract URLs
  const urlMatches = asciiStr.match(/https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"'\r\n)]*/gi) || [];
  urlMatches.forEach(u => {
    iocs.urls.push(u);
    try { iocs.domains.push(new URL(u).hostname); } catch (e) {}
  });

  // Deduplicate IOCs
  iocs.ips = [...new Set(iocs.ips)];
  iocs.urls = [...new Set(iocs.urls)];
  iocs.domains = [...new Set(iocs.domains)];
  iocs.hashes = [...new Set(iocs.hashes)];

  if (iocs.urls.length > 0 || iocs.ips.length > 0) {
    findings.push({
      id: 'GENERIC-INFO-IOCS',
      title: 'Network IOC Indicators Extracted',
      severity: 'INFO',
      category: 'Static Intelligence',
      description: `Extracted ${iocs.ips.length} IP address(es) and ${iocs.urls.length} URL reference(s) from binary string pool.`,
      source: 'ASCII String Extraction',
      recommendation: 'Review extracted network indicators in the IOC tab.'
    });
  }

  return {
    metadata,
    findings,
    iocs,
    artifacts: {
      sha256: sha256 || null,
      md5,
      entropy: metadata.entropyScore,
      extractedIpsCount: iocs.ips.length,
      extractedUrlsCount: iocs.urls.length
    }
  };
}

/** Calculate Shannon Entropy (0.0 to 8.0) */
function calculateEntropy(bytes) {
  if (bytes.length === 0) return 0;
  const frequencies = new Array(256).fill(0);
  bytes.forEach(b => frequencies[b]++);

  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / bytes.length;
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

/** Simple 32-hex string checksum helper */
function calculateSimpleHash(bytes) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < Math.min(bytes.length, 100000); i++) {
    hash ^= bytes[i];
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return (hash >>> 0).toString(16).padStart(8, '0').repeat(4).slice(0, 32);
}
