import fs from 'fs';
import path from 'path';

import { detectFileType } from '../src/modules/file_type_detector.js';
import { analyzePdf } from '../src/modules/pdf_analyzer.js';
import { analyzeEml } from '../src/modules/eml_analyzer.js';
import { analyzeImage } from '../src/modules/image_analyzer.js';
import { analyzeOfficeDoc } from '../src/modules/office_analyzer.js';
import { calculateSecurityScore } from '../src/modules/score_engine.js';
import { processIocs } from '../src/modules/ioc_extractor.js';

function toArrayBuffer(buffer) {
  return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
}

console.log('=====================================================');
console.log('   SENTRY CONSOLE AUTOMATED MODULE TEST SUITE       ');
console.log('=====================================================\n');

let passedTests = 0;
let totalTests = 0;

function assert(condition, message) {
  totalTests++;
  if (condition) {
    console.log(`  [PASS] ${message}`);
    passedTests++;
  } else {
    console.error(`  [FAIL] ${message}`);
  }
}

// 1. PDF Analyzer Verification
console.log('1. Testing PDF Threat Analyzer (sample_js.pdf)...');
const pdfBuf = toArrayBuffer(fs.readFileSync('tests/samples/sample_js.pdf'));
const pdfDetected = detectFileType(pdfBuf, 'sample_js.pdf');
assert(pdfDetected.type === 'pdf', 'Magic byte detected file as PDF');

const pdfResult = analyzePdf(pdfBuf, 'sample_js.pdf');
const hasPdfJs = pdfResult.findings.some(f => f.id === 'PDF-CRIT-JS');
const hasOpenAction = pdfResult.findings.some(f => f.id === 'PDF-CRIT-OPENACTION');

assert(hasPdfJs, 'Detected embedded JavaScript (/JS) directive');
assert(hasOpenAction, 'Detected auto-executing /OpenAction directive');

// 2. Email EML Analyzer Verification
console.log('\n2. Testing Email Threat Analyzer (sample_spoofed.eml)...');
const emlBuf = toArrayBuffer(fs.readFileSync('tests/samples/sample_spoofed.eml'));
const emlDetected = detectFileType(emlBuf, 'sample_spoofed.eml');
assert(emlDetected.type === 'email_eml', 'Detected file as EML message');

const emlResult = analyzeEml(emlBuf, 'sample_spoofed.eml');
const hasSpoof = emlResult.findings.some(f => f.id === 'EML-CRIT-SPOOF-RETURNPATH');
const hasAnchorMismatch = emlResult.findings.some(f => f.id === 'EML-CRIT-ANCHOR-MISMATCH');

assert(hasSpoof, 'Detected Sender Return-Path Spoofing mismatch');
assert(hasAnchorMismatch, 'Detected Phishing Anchor Link Text Mismatch');

// 3. Image Steganography Analyzer Verification
console.log('\n3. Testing Image Threat Analyzer (sample_stego.jpg)...');
const imgBuf = toArrayBuffer(fs.readFileSync('tests/samples/sample_stego.jpg'));
const imgDetected = detectFileType(imgBuf, 'sample_stego.jpg');
assert(imgDetected.type === 'image_jpeg', 'Magic byte detected file as JPEG');

const imgResult = analyzeImage(imgBuf, 'sample_stego.jpg');
const hasStegoPayload = imgResult.findings.some(f => f.id === 'IMG-CRIT-STEGO-PAYLOAD');
assert(hasStegoPayload, 'Detected Steganography trailing payload after EOI marker');

// 4. Office Document Analyzer Verification
console.log('\n4. Testing Office Document Analyzer (sample_macro.docx)...');
const docBuf = toArrayBuffer(fs.readFileSync('tests/samples/sample_macro.docx'));
const docDetected = detectFileType(docBuf, 'sample_macro.docx');
assert(docDetected.type === 'office_docx', 'Magic byte detected file as Office OpenXML container');

const docResult = analyzeOfficeDoc(docBuf, 'sample_macro.docx');
const hasMacro = docResult.findings.some(f => f.id === 'OFFICE-CRIT-VBA-MACRO');
const hasTemplateInj = docResult.findings.some(f => f.id === 'OFFICE-CRIT-TEMPLATE-INJECTION');
assert(hasMacro, 'Detected Auto-Executing VBA Macro (vbaProject.bin)');
assert(hasTemplateInj, 'Detected Remote Template Injection (.rels)');

// 5. Universal Security Score Engine Verification
console.log('\n5. Testing Universal Security Score Calculation...');
const sampleScore = calculateSecurityScore(pdfResult.findings);
assert(sampleScore.score < 60, `Calculated Security Score correctly penalized threat findings: ${sampleScore.score}/100`);
assert(sampleScore.riskLevel === 'CRITICAL RISK', `Assigned correct risk level taxonomy: ${sampleScore.riskLevel}`);

// Summary
console.log('\n=====================================================');
console.log(` TEST SUMMARY: ${passedTests} / ${totalTests} PASSED`);
console.log('=====================================================');

if (passedTests !== totalTests) {
  process.exit(1);
}
