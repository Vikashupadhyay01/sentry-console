import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { parsePcap } from '../src/parser.js';
import { runDetections } from '../src/detection.js';
import { calculateSecurityScore, normalizeFinding } from '../src/modules/score_engine.js';
import { processIocs } from '../src/modules/ioc_extractor.js';
import { NetworkGraph } from '../src/network_graph.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function testAllAttacksDemo() {
  console.log('=== TESTING all_attacks_demo.pcap ===');
  const pcapPath = path.join(__dirname, '..', 'all_attacks_demo.pcap');
  const buffer = fs.readFileSync(pcapPath);
  console.log(`Loaded all_attacks_demo.pcap buffer size: ${buffer.byteLength} bytes`);

  const pcapResult = parsePcap(buffer.buffer);
  console.log(`Parsed packet count: ${pcapResult.totalPackets}`);

  const rawFindings = runDetections(pcapResult.packets, pcapResult.stats);
  console.log(`Raw findings detected: ${rawFindings.length}`);

  const processedIocs = processIocs(pcapResult.stats);
  const combinedFindings = [...rawFindings, ...(processedIocs.findings || [])].map(normalizeFinding);
  console.log(`Normalized combined findings: ${combinedFindings.length}`);

  // Verify finding fields
  for (const f of combinedFindings) {
    if (typeof f.name !== 'string' || typeof f.title !== 'string') {
      throw new Error(`Finding ${f.id} has invalid name or title: name=${f.name}, title=${f.title}`);
    }
  }
  console.log('[PASS] All findings have valid string name and title properties!');

  // Verify NetworkGraph prototype methods
  const methods = Object.getOwnPropertyNames(NetworkGraph.prototype);
  console.log('[NetworkGraph] Available prototype methods:', methods);
  if (!methods.includes('loadGraphData')) {
    throw new Error('loadGraphData is missing from NetworkGraph prototype!');
  }
  console.log('[PASS] NetworkGraph.prototype.loadGraphData is verified present!');

  console.log('=== ALL TESTS PASSED FOR all_attacks_demo.pcap ===');
}

testAllAttacksDemo().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
