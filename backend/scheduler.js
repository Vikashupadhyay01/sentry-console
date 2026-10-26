/**
 * Sentry Console Backend — Background Job Scheduler
 * Periodically re-scans active monitoring targets and records score trends in SQLite.
 */

import { allQuery, runQuery } from './db.js';

export function startScheduler() {
  console.log('[Scheduler] Background periodic security monitoring scheduler active.');

  // Run initial check after 10 seconds, then repeat every 1 hour
  setTimeout(checkAndRunScans, 10000);
  setInterval(checkAndRunScans, 60 * 60 * 1000);
}

async function checkAndRunScans() {
  console.log('[Scheduler] Checking for pending target re-scans...');

  try {
    const activeTargets = await allQuery("SELECT * FROM targets WHERE status = 'ACTIVE'");

    for (const target of activeTargets) {
      const lastScan = target.last_scanned_at ? new Date(target.last_scanned_at) : 0;
      const hoursSinceLast = (Date.now() - lastScan) / (1000 * 60 * 60);

      if (hoursSinceLast >= (target.frequency_hours || 24) || !target.last_scanned_at) {
        console.log(`[Scheduler] Executing scheduled scan for domain: ${target.domain}`);
        await executeTargetScan(target);
      }
    }
  } catch (err) {
    console.error('[Scheduler] Error checking targets:', err);
  }
}

async function executeTargetScan(target) {
  try {
    const res = await fetch('http://localhost:3001/api/scan/url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: `https://${target.domain}` })
    });

    if (!res.ok) return;
    const scanData = await res.json();

    const score = scanData.score || 100;
    const riskLevel = scanData.riskLevel || 'LOW RISK';
    const findingsCount = (scanData.findings || []).length;
    const now = new Date().toISOString();

    // Record in history table
    await runQuery(
      'INSERT INTO scan_history (target_id, score, risk_level, findings_count, result_json, scanned_at) VALUES (?, ?, ?, ?, ?, ?)',
      [target.id, score, riskLevel, findingsCount, JSON.stringify(scanData), now]
    );

    // Update target status
    await runQuery(
      'UPDATE targets SET last_scanned_at = ?, last_score = ? WHERE id = ?',
      [now, score, target.id]
    );

    console.log(`[Scheduler] Scan complete for ${target.domain}: Score ${score}/100`);
  } catch (err) {
    console.error(`[Scheduler] Target scan error for ${target.domain}:`, err.message);
  }
}
