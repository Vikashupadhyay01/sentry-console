/**
 * Sentry Console — Universal Security Score & Risk Severity Engine
 * Computes a standardized 0-100 Security Score across all analysis types
 * (PCAP, PDF, Email, Image, Office, Generic, Website Scans).
 */

export const SEVERITY_LEVELS = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO'
};

const SEVERITY_WEIGHTS = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 8,
  LOW: 3,
  INFO: 0
};

/**
 * Calculate universal Security Score (0-100) and severity counts.
 * @param {Array<object>} findings
 * @returns {{ score: number, riskLevel: string, color: string, badgeClass: string, counts: object }}
 */
export function calculateSecurityScore(findings = []) {
  let deduction = 0;
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };

  findings.forEach(f => {
    const sev = (f.severity || 'LOW').toUpperCase();
    if (counts[sev] !== undefined) {
      counts[sev]++;
    }
    deduction += SEVERITY_WEIGHTS[sev] || 0;
  });

  // Diminishing-returns curve: score smoothly girta hai, direct 0 par nahi atakta
  let score = Math.round(100 * (50 / (50 + deduction)));
  score = Math.max(1, Math.min(100, score));
  if (deduction === 0) score = 100;

  let riskLevel = 'LOW RISK';
  let color = 'var(--green)';
  let badgeClass = 'sev-info';

  if (score < 40 || counts.CRITICAL > 0) {
    riskLevel = 'CRITICAL RISK';
    color = 'var(--red)';
    badgeClass = 'sev-critical';
  } else if (score < 70 || counts.HIGH > 0) {
    riskLevel = 'HIGH RISK';
    color = 'var(--amber)';
    badgeClass = 'sev-high';
  } else if (score < 90 || counts.MEDIUM > 0) {
    riskLevel = 'MODERATE RISK';
    color = '#f1c40f';
    badgeClass = 'sev-medium';
  }

  return {
    score,
    riskLevel,
    color,
    badgeClass,
    counts
  };
}

/**
 * Standardizes a finding object to match Sentry taxonomy.
 * @param {object} finding
 * @returns {object}
 */
export function normalizeFinding(finding) {
  const nameStr = String(finding.name || finding.title || 'Security Anomaly');
  return {
    // Spread all original fields first so nothing is accidentally dropped
    ...finding,
    // Then enforce required normalized fields
    id: finding.id || `FINDING-${Math.random().toString(36).substr(2, 6).toUpperCase()}`,
    name: nameStr,
    title: nameStr,
    severity: (finding.severity || 'LOW').toUpperCase(),
    category: finding.category || 'General Security',
    description: finding.description || 'No description provided.',
    source: finding.source || 'Analysis Engine',
    recommendation: finding.recommendation || 'Investigate anomaly and apply security controls.',
    // Explicitly preserve PCAP-specific fields needed by results_app.js
    src: finding.src || '',
    dst: finding.dst || '',
    attackWindow: finding.attackWindow || null,
    indicators: finding.indicators || []
  };
}
