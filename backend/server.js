/**
 * Sentry Console Backend API & Static Web Server
 * Provides HTTP endpoints for Domain Security Scans, Scheduled Security Monitoring,
 * and static file serving for Sentry Console frontend.
 */

import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { router as scanRouter } from './routes/scan.js';
import { router as monitorRouter } from './routes/monitor.js';
import { startScheduler } from './scheduler.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.join(__dirname, '..');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

// Routes
app.use('/api/scan', scanRouter);
app.use('/api/monitor', monitorRouter);

// Healthcheck
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'Sentry Console Security API', timestamp: new Date().toISOString() });
});

// Alias style.css to styles/main.css
app.get(['/style.css', '/styles/style.css'], (req, res) => {
  res.sendFile(path.join(rootDir, 'styles', 'main.css'));
});

// Serve static frontend files (HTML, CSS, JS, Assets)
app.use(express.static(rootDir));

app.listen(PORT, () => {
  console.log(`[Backend] Sentry Console Platform listening on http://localhost:${PORT}`);
  startScheduler();
});

