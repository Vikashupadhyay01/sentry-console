/**
 * Sentry Console Backend — Lightweight Pure JS Database Manager
 * Uses persistent JSON storage (backend/sentry_db.json) with async query interfaces.
 * Zero native binary compilation required.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbFile = path.join(__dirname, 'sentry_db.json');

let dbData = {
  targets: [],
  scan_history: []
};

// Initialize DB file
if (fs.existsSync(dbFile)) {
  try {
    const raw = fs.readFileSync(dbFile, 'utf8');
    dbData = JSON.parse(raw);
  } catch (err) {
    console.warn('[DB] Resetting DB file due to parse error:', err);
  }
} else {
  saveDb();
}

function saveDb() {
  fs.writeFileSync(dbFile, JSON.stringify(dbData, null, 2), 'utf8');
}

export function runQuery(sql, params = []) {
  return new Promise((resolve, reject) => {
    try {
      sql = sql.trim().toUpperCase();

      if (sql.startsWith('INSERT INTO TARGETS')) {
        const id = dbData.targets.length > 0 ? Math.max(...dbData.targets.map(t => t.id)) + 1 : 1;
        const [domain, name, frequency_hours, status] = params;

        if (dbData.targets.some(t => t.domain === domain)) {
          return reject(new Error('UNIQUE constraint failed: targets.domain'));
        }

        const newTarget = {
          id,
          domain,
          name: name || domain,
          frequency_hours: frequency_hours || 24,
          status: status || 'ACTIVE',
          last_scanned_at: null,
          last_score: null,
          created_at: new Date().toISOString()
        };

        dbData.targets.push(newTarget);
        saveDb();
        return resolve({ id, changes: 1 });
      }

      if (sql.startsWith('UPDATE TARGETS')) {
        const [last_scanned_at, last_score, id] = params;
        const target = dbData.targets.find(t => t.id === Number(id));
        if (target) {
          target.last_scanned_at = last_scanned_at;
          target.last_score = last_score;
          saveDb();
        }
        return resolve({ changes: target ? 1 : 0 });
      }

      if (sql.startsWith('DELETE FROM TARGETS')) {
        const [id] = params;
        const initialCount = dbData.targets.length;
        dbData.targets = dbData.targets.filter(t => t.id !== Number(id));
        dbData.scan_history = dbData.scan_history.filter(s => s.target_id !== Number(id));
        saveDb();
        return resolve({ changes: initialCount - dbData.targets.length });
      }

      if (sql.startsWith('INSERT INTO SCAN_HISTORY')) {
        const id = dbData.scan_history.length > 0 ? Math.max(...dbData.scan_history.map(s => s.id)) + 1 : 1;
        const [target_id, score, risk_level, findings_count, result_json, scanned_at] = params;

        dbData.scan_history.push({
          id,
          target_id: Number(target_id),
          score: Number(score),
          risk_level,
          findings_count: Number(findings_count),
          result_json,
          scanned_at: scanned_at || new Date().toISOString()
        });

        saveDb();
        return resolve({ id, changes: 1 });
      }

      resolve({ id: 0, changes: 0 });
    } catch (err) {
      reject(err);
    }
  });
}

export function allQuery(sql, params = []) {
  return new Promise((resolve) => {
    sql = sql.trim().toUpperCase();

    if (sql.includes('FROM TARGETS')) {
      return resolve(dbData.targets);
    }

    if (sql.includes('FROM SCAN_HISTORY')) {
      const targetId = Number(params[0]);
      const history = dbData.scan_history
        .filter(s => s.target_id === targetId)
        .sort((a, b) => new Date(b.scanned_at) - new Date(a.scanned_at));
      return resolve(history);
    }

    resolve([]);
  });
}

export function getQuery(sql, params = []) {
  return allQuery(sql, params).then(rows => rows[0] || null);
}
