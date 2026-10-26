/**
 * Sentry Console Backend — Scheduled Security Monitoring Router
 * Manages monitored target domains, triggers re-scans, and returns target history.
 */

import express from 'express';
import { runQuery, allQuery, getQuery } from '../db.js';

export const router = express.Router();

/** GET /api/monitor/targets — List all monitored target domains */
router.get('/targets', async (req, res) => {
  try {
    const targets = await allQuery('SELECT * FROM targets ORDER BY created_at DESC');
    res.json(targets);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** POST /api/monitor/targets — Add a domain to scheduled monitoring */
router.post('/targets', async (req, res) => {
  const { domain, name, frequencyHours = 24 } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain name is required.' });

  const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();

  try {
    const result = await runQuery(
      'INSERT INTO targets (domain, name, frequency_hours, status) VALUES (?, ?, ?, ?)',
      [cleanDomain, name || cleanDomain, frequencyHours, 'ACTIVE']
    );

    res.json({ id: result.id, domain: cleanDomain, name: name || cleanDomain, status: 'ACTIVE' });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed')) {
      return res.status(409).json({ error: 'Target domain is already monitored.' });
    }
    res.status(500).json({ error: err.message });
  }
});

/** DELETE /api/monitor/targets/:id — Delete a monitored target */
router.delete('/targets/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await runQuery('DELETE FROM targets WHERE id = ?', [id]);
    res.json({ success: true, message: 'Target removed from monitoring.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** GET /api/monitor/scans/:targetId — Get scan history for a target */
router.get('/scans/:targetId', async (req, res) => {
  const { targetId } = req.params;
  try {
    const history = await allQuery(
      'SELECT id, target_id, score, risk_level, findings_count, scanned_at FROM scan_history WHERE target_id = ? ORDER BY scanned_at DESC LIMIT 50',
      [targetId]
    );
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
