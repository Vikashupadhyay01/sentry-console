/**
 * Sentry Console — Shared Storage Module (IndexedDB)
 *
 * Uses IndexedDB for storing analysis results directly without manual JSON stringify.
 * Includes automatic database recovery for stale/corrupt object stores,
 * request timeout safeguards, and fallback storage mechanisms.
 */

const DB_NAME = 'sentry_console_db';
const STORE_NAME = 'analysis_results';
const KEY = 'sentry_analysis_data';

function openDB(isRetry = false) {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      return reject(new Error("Your browser doesn't support storing large analysis results — try a smaller capture or a different browser"));
    }

    let timer = setTimeout(() => {
      reject(new Error('[Sentry Storage] IndexedDB open operation timed out (3s limit reached).'));
    }, 3000);

    const req = indexedDB.open(DB_NAME, 1);

    req.onblocked = () => {
      console.warn('[Sentry Storage] IndexedDB open blocked — close other Sentry Console tabs and retry.');
    };

    req.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };

    req.onsuccess = async (event) => {
      clearTimeout(timer);
      const db = event.target.result;

      // Detect stale/corrupt DB (e.g. database exists but object store missing)
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        console.warn('[Sentry Storage] Detected corrupt/stale DB — recreating...');
        db.close();
        if (!isRetry) {
          try {
            await new Promise((res, rej) => {
              const delReq = indexedDB.deleteDatabase(DB_NAME);
              delReq.onsuccess = () => res();
              delReq.onerror = () => rej(delReq.error);
              delReq.onblocked = () => res();
            });
          } catch (delErr) {
            console.warn('[Sentry Storage] Failed to delete corrupt DB:', delErr);
          }
          try {
            const freshDb = await openDB(true);
            return resolve(freshDb);
          } catch (retryErr) {
            return reject(retryErr);
          }
        } else {
          return reject(new Error('[Sentry Storage] Unable to create object store on IndexedDB'));
        }
      }

      resolve(db);
    };

    req.onerror = (event) => {
      clearTimeout(timer);
      reject(req.error || new Error('Failed to open IndexedDB'));
    };
  });
}

/**
 * Save analysis data object directly to IndexedDB.
 * Falls back to sessionStorage / localStorage if IndexedDB is blocked or fails.
 * @param {object} data
 * @returns {Promise<void>}
 */
export async function saveAnalysisData(data) {
  try {
    const db = await openDB();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      tx.objectStore(STORE_NAME).put(data, KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error || new Error('IndexedDB transaction write error'));
    });
    console.log('[Sentry Storage] Saved via IndexedDB');
    return;
  } catch (idbErr) {
    console.warn('[Sentry Storage] IndexedDB write failed, attempting fallback:', idbErr);
    // Fallback 1: sessionStorage
    try {
      sessionStorage.removeItem(KEY);
      sessionStorage.setItem(KEY, JSON.stringify(data));
      console.log('[Sentry Storage] Saved via sessionStorage');
      return;
    } catch (sErr) {
      // Fallback 2: localStorage
      try {
        localStorage.removeItem(KEY);
        localStorage.setItem(KEY, JSON.stringify(data));
        console.log('[Sentry Storage] Saved via localStorage');
        return;
      } catch (lErr) {
        throw new Error("Your browser doesn't support storing large analysis results — try a smaller capture or a different browser");
      }
    }
  }
}

/**
 * Load analysis data object asynchronously from IndexedDB.
 * Tries IndexedDB first, then sessionStorage / localStorage fallbacks.
 * @returns {Promise<object|null>}
 */
export async function loadAnalysisData() {
  // 1. Try IndexedDB
  try {
    const db = await openDB();
    const result = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const req = tx.objectStore(STORE_NAME).get(KEY);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    if (result) {
      console.log('[Sentry Storage] Loaded via IndexedDB');
      return result;
    }
  } catch (err) {
    console.warn('[Sentry Storage] IndexedDB read error, trying fallback:', err);
  }

  // 2. Fallback to sessionStorage
  try {
    const sessionVal = sessionStorage.getItem(KEY);
    if (sessionVal) {
      console.log('[Sentry Storage] Loaded via sessionStorage');
      return JSON.parse(sessionVal);
    }
  } catch (e) {}

  // 3. Fallback to localStorage
  try {
    const localVal = localStorage.getItem(KEY);
    if (localVal) {
      console.log('[Sentry Storage] Loaded via localStorage');
      return JSON.parse(localVal);
    }
  } catch (e) {}

  return null;
}

/**
 * Clear stored analysis data from all storage mechanisms.
 * @returns {Promise<void>}
 */
export async function clearAnalysisData() {
  try {
    const db = await openDB();
    await new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const req = tx.objectStore(STORE_NAME).delete(KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });
  } catch (e) {}

  try { sessionStorage.removeItem(KEY); } catch (e) {}
  try { localStorage.removeItem(KEY); } catch (e) {}
}

// Aliases for compatibility
export const saveAnalysisPayload = saveAnalysisData;
export const loadAnalysisPayload = loadAnalysisData;
export const clearAnalysisPayload = clearAnalysisData;
