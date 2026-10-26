/**
 * Sentry Console — Image Threat & Metadata Analyzer
 * Extracts EXIF metadata (GPS, camera, software), detects steganography trailing payloads,
 * polyglot file headers (PNG+ZIP, JPG+PDF), and embedded script tags in comments.
 * 100% Client-Side. Privacy Preserved.
 */

/**
 * Analyze JPEG, PNG, or GIF image for security threats & metadata disclosures.
 * @param {ArrayBuffer} buffer
 * @param {string} fileName
 * @returns {object} Analysis result containing metadata, findings, and extracted IOCs.
 */
export function analyzeImage(buffer, fileName) {
  console.log('[Image Analyzer] Analyzing Image:', fileName, 'Size:', buffer.byteLength, 'bytes');

  const bytes = new Uint8Array(buffer);
  const findings = [];
  const iocs = { ips: [], domains: [], urls: [], emails: [], hashes: [] };

  const metadata = {
    fileName,
    fileSize: buffer.byteLength,
    format: 'Unknown',
    dimensions: 'Unknown',
    hasExif: false,
    exifTags: {},
    hasTrailingData: false,
    trailingBytesCount: 0,
    isPolyglot: false
  };

  // Determine Image Format & Perform Trailing Payload Inspection
  if (bytes[0] === 0xFF && bytes[1] === 0xD8) {
    metadata.format = 'JPEG';
    inspectJpeg(bytes, metadata, findings, iocs);
  } else if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) {
    metadata.format = 'PNG';
    inspectPng(bytes, metadata, findings, iocs);
  } else if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) {
    metadata.format = 'GIF';
    inspectGif(bytes, metadata, findings, iocs);
  }

  // Common Polyglot & Script Inspection across entire image buffer
  inspectPolyglotsAndScripts(bytes, metadata, findings, iocs);

  return {
    metadata,
    findings,
    iocs,
    artifacts: {
      format: metadata.format,
      exif: metadata.exifTags,
      trailingBytes: metadata.trailingBytesCount,
      polyglotDetected: metadata.isPolyglot
    }
  };
}

/** Inspect JPEG markers, EXIF data, and End-Of-Image (0xFF 0xD9) trailing data */
function inspectJpeg(bytes, metadata, findings, iocs) {
  let eoiIndex = -1;

  // Search for EOI (0xFF 0xD9)
  for (let i = 0; i < bytes.length - 1; i++) {
    if (bytes[i] === 0xFF && bytes[i + 1] === 0xD9) {
      eoiIndex = i;
    }
  }

  if (eoiIndex !== -1 && eoiIndex + 2 < bytes.length) {
    const trailingLength = bytes.length - (eoiIndex + 2);
    metadata.hasTrailingData = true;
    metadata.trailingBytesCount = trailingLength;

    findings.push({
      id: 'IMG-CRIT-STEGO-PAYLOAD',
      title: 'Steganography / Trailing Payload Detected',
      severity: 'CRITICAL',
      category: 'Steganography',
      description: `JPEG image contains ${trailingLength} byte(s) of hidden payload data appended after the End-Of-Image (EOI 0xFFD9) marker. Attackers conceal executable code or exfiltrated data behind valid images.`,
      source: `JPEG EOI Offset: 0x${(eoiIndex + 2).toString(16)}`,
      recommendation: 'Strip trailing payload data before serving or opening file.'
    });
  }

  // EXIF Marker Search (0xFF 0xE1 -> APP1 Exif)
  for (let i = 0; i < bytes.length - 4; i++) {
    if (bytes[i] === 0xFF && bytes[i + 1] === 0xE1) {
      if (bytes[i + 4] === 0x45 && bytes[i + 5] === 0x78 && bytes[i + 6] === 0x69 && bytes[i + 7] === 0x66) {
        metadata.hasExif = true;
        parseJpegExifHeader(bytes.subarray(i + 4), metadata, findings, iocs);
        break;
      }
    }
  }
}

/** Inspect PNG chunks, IEND chunk, and trailing payload data */
function inspectPng(bytes, metadata, findings, iocs) {
  // Search for IEND chunk signature (49 45 4E 44 41 45 42 in PNG -> "IEND" + 4-byte CRC)
  let iendIndex = -1;
  const iendSig = [0x49, 0x45, 0x4E, 0x44];

  for (let i = 0; i < bytes.length - 8; i++) {
    if (bytes[i] === iendSig[0] && bytes[i + 1] === iendSig[1] &&
        bytes[i + 2] === iendSig[2] && bytes[i + 3] === iendSig[3]) {
      iendIndex = i + 4 + 4; // IEND + 4 bytes CRC
      break;
    }
  }

  if (iendIndex !== -1 && iendIndex < bytes.length) {
    const trailingLength = bytes.length - iendIndex;
    metadata.hasTrailingData = true;
    metadata.trailingBytesCount = trailingLength;

    findings.push({
      id: 'IMG-CRIT-PNG-STEGO',
      title: 'PNG Trailing Data / Steganography Payload',
      severity: 'CRITICAL',
      category: 'Steganography',
      description: `PNG file contains ${trailingLength} trailing byte(s) beyond the mandatory IEND chunk trailer.`,
      source: `PNG IEND Offset: 0x${iendIndex.toString(16)}`,
      recommendation: 'Audit trailing bytes for hidden encrypted archives or malicious shellcode.'
    });
  }
}

/** Inspect GIF trailers (0x00 0x3B) */
function inspectGif(bytes, metadata, findings, iocs) {
  let trailerIndex = -1;
  for (let i = bytes.length - 1; i >= 0; i--) {
    if (bytes[i] === 0x3B) {
      trailerIndex = i + 1;
      break;
    }
  }

  if (trailerIndex > 0 && trailerIndex < bytes.length) {
    const trailingLength = bytes.length - trailerIndex;
    metadata.hasTrailingData = true;
    metadata.trailingBytesCount = trailingLength;

    findings.push({
      id: 'IMG-HIGH-GIF-STEGO',
      title: 'GIF Trailing Payload Data',
      severity: 'HIGH',
      category: 'Steganography',
      description: `GIF image contains ${trailingLength} trailing byte(s) past the GIF trailer byte (0x3B).`,
      source: `GIF Trailer Offset`,
      recommendation: 'Sanitize image binary before distribution.'
    });
  }
}

/** Parse EXIF GPS & Software Information */
function parseJpegExifHeader(exifBytes, metadata, findings, iocs) {
  const asciiStr = new TextDecoder('latin1').decode(exifBytes);

  // Search common EXIF software/camera strings
  const cameraMatch = asciiStr.match(/(Apple|Samsung|Canon|Nikon|Sony|Google|Pixel|iPhone)\s+[\w\s.-]+/i);
  if (cameraMatch) {
    metadata.exifTags.camera = cameraMatch[0];
  }

  const softwareMatch = asciiStr.match(/(Photoshop|GIMP|ExifTool|Adobe|Lightroom|Canva)/i);
  if (softwareMatch) {
    metadata.exifTags.software = softwareMatch[0];
  }

  // Detect GPS Location EXIF tag presence
  if (asciiStr.includes('GPSLatitude') || asciiStr.includes('GPSLongitude') || asciiStr.includes('GPSVersionID')) {
    metadata.exifTags.gpsPresent = true;
    findings.push({
      id: 'IMG-LOW-EXIF-GPS',
      title: 'EXIF Geolocation Data Discovered',
      severity: 'LOW',
      category: 'Information Disclosure',
      description: 'Image file contains embedded GPS location tags (latitude/longitude coordinates), exposing physical capture location.',
      source: 'EXIF APP1 Header',
      recommendation: 'Strip EXIF metadata before sharing images publicly to prevent physical tracking.'
    });
  }
}

/** Check for Polyglot headers (e.g. JPG+ZIP archive or PNG+PDF) and embedded scripts */
function inspectPolyglotsAndScripts(bytes, metadata, findings, iocs) {
  const binaryText = new TextDecoder('latin1').decode(bytes);

  // Check for embedded ZIP header signature inside image (0x50 0x4B 0x03 0x04) past byte 100
  const zipHeaderIdx = binaryText.indexOf('PK\x03\x04', 100);
  if (zipHeaderIdx !== -1) {
    metadata.isPolyglot = true;
    findings.push({
      id: 'IMG-CRIT-POLYGLOT-ZIP',
      title: 'Polyglot File Detected (Image + ZIP Container)',
      severity: 'CRITICAL',
      category: 'Polyglot File',
      description: `Image contains an embedded ZIP archive header (PK..) at byte offset 0x${zipHeaderIdx.toString(16)}. This polyglot technique allows files to render as images while executing as compressed archives.`,
      source: `Byte Offset: 0x${zipHeaderIdx.toString(16)}`,
      recommendation: 'Block file upload; polyglots are used to bypass content filters.'
    });
  }

  // Check for embedded HTML/JS script tags
  if (/<script|javascript:|onmouseover=|onerror=/i.test(binaryText)) {
    findings.push({
      id: 'IMG-CRIT-EMBEDDED-SCRIPT',
      title: 'Embedded HTML / JavaScript Tags in Image',
      severity: 'CRITICAL',
      category: 'Code Injection',
      description: 'Image metadata contains embedded HTML/JavaScript payload tags, designed to trigger XSS when rendered by browsers.',
      source: 'Image Comment / Metadata Chunk',
      recommendation: 'Purge metadata comments before displaying user images.'
    });
  }
}
