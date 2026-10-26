import fs from 'fs';
import path from 'path';

// Valid minimal JPEG bytes: SOI (FF D8) + APP1 (FF E1) EXIF + DQT/SOF/SOS + EOI (FF D9) + Trailing Payload
const jpegHeader = Buffer.from([
  0xFF, 0xD8, // SOI
  0xFF, 0xE1, 0x00, 0x1A, 0x45, 0x78, 0x69, 0x66, 0x00, 0x00, // APP1 Exif header
  0x49, 0x49, 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EXIF TIFF
  0xFF, 0xD9  // EOI
]);

const trailingPayload = Buffer.from('---STEGANOGRAPHY_SECRET_PAYLOAD_BYTES_PK\x03\x04---');

const fullImage = Buffer.concat([jpegHeader, trailingPayload]);
fs.writeFileSync('tests/samples/sample_stego.jpg', fullImage);
console.log('Created sample_stego.jpg successfully:', fullImage.length, 'bytes');
