/**
 * Sentry Console — File Type Detector & Magic Byte Parser
 * Determines actual file type using binary magic signatures (header bytes)
 * rather than relying solely on file extensions.
 */

export const FILE_TYPES = {
  PCAP: 'pcap',
  PCAPNG: 'pcapng',
  PDF: 'pdf',
  IMAGE_JPEG: 'image_jpeg',
  IMAGE_PNG: 'image_png',
  IMAGE_GIF: 'image_gif',
  OFFICE_DOCX: 'office_docx',
  OFFICE_OLE: 'office_ole',
  EMAIL_EML: 'email_eml',
  GENERIC: 'generic'
};

/**
 * Detect file type from ArrayBuffer and filename.
 * @param {ArrayBuffer} buffer
 * @param {string} fileName
 * @returns {{ type: string, extension: string, name: string, mime: string, isMagicVerified: boolean, warning: string|null }}
 */
export function detectFileType(inputBuffer, fileName = '') {
  let bytes;
  if (!inputBuffer) {
    bytes = new Uint8Array(0);
  } else if (inputBuffer instanceof Uint8Array) {
    bytes = inputBuffer.subarray(0, 1024);
  } else if (ArrayBuffer.isView(inputBuffer)) {
    bytes = new Uint8Array(inputBuffer.buffer, inputBuffer.byteOffset, Math.min(inputBuffer.byteLength, 1024));
  } else if (inputBuffer.byteLength !== undefined) {
    bytes = new Uint8Array(inputBuffer, 0, Math.min(inputBuffer.byteLength, 1024));
  } else {
    bytes = new Uint8Array(0);
  }

  const ext = (fileName || '').split('.').pop()?.toLowerCase() || '';

  // 1. PCAP Classic (0xa1b2c3d4 / 0xd4c3b2a1 / nanoseconds variants)
  if (bytes.length >= 4) {
    const magic32BE = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
    const magic32LE = ((bytes[3] << 24) | (bytes[2] << 16) | (bytes[1] << 8) | bytes[0]) >>> 0;

    if (magic32BE === 0xa1b2c3d4 || magic32LE === 0xa1b2c3d4 ||
        magic32BE === 0xa1b23c4d || magic32LE === 0xa1b23c4d) {
      return {
        type: FILE_TYPES.PCAP,
        extension: ext,
        name: fileName,
        mime: 'application/vnd.tcpdump.pcap',
        isMagicVerified: true,
        warning: null
      };
    }

    // 2. PCAPNG (0x0a0d0d0a - Section Header Block)
    if (magic32BE === 0x0a0d0d0a || magic32LE === 0x0a0d0d0a) {
      return {
        type: FILE_TYPES.PCAPNG,
        extension: ext,
        name: fileName,
        mime: 'application/x-pcapng',
        isMagicVerified: true,
        warning: null
      };
    }
  }

  // Extension fallbacks for PCAP / PCAPNG
  if (['pcap', 'cap'].includes(ext)) {
    return {
      type: FILE_TYPES.PCAP,
      extension: ext,
      name: fileName,
      mime: 'application/vnd.tcpdump.pcap',
      isMagicVerified: false,
      warning: null
    };
  }
  if (ext === 'pcapng') {
    return {
      type: FILE_TYPES.PCAPNG,
      extension: ext,
      name: fileName,
      mime: 'application/x-pcapng',
      isMagicVerified: false,
      warning: null
    };
  }

  // 3. PDF (%PDF- -> 0x25 0x50 0x44 0x46 0x2D)
  if (bytes.length >= 5 &&
      bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 &&
      bytes[3] === 0x46 && bytes[4] === 0x2D) {
    return {
      type: FILE_TYPES.PDF,
      extension: ext,
      name: fileName,
      mime: 'application/pdf',
      isMagicVerified: true,
      warning: ext !== 'pdf' ? `Extension '.${ext}' mismatches detected PDF header.` : null
    };
  }

  // 4. JPEG (0xFF 0xD8 0xFF)
  if (bytes.length >= 3 && bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) {
    return {
      type: FILE_TYPES.IMAGE_JPEG,
      extension: ext,
      name: fileName,
      mime: 'image/jpeg',
      isMagicVerified: true,
      warning: !['jpg', 'jpeg'].includes(ext) ? `Extension '.${ext}' mismatches detected JPEG image.` : null
    };
  }

  // 5. PNG (0x89 0x50 0x4E 0x47 0x0D 0x0A 0x1A 0x0A)
  if (bytes.length >= 8 &&
      bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47 &&
      bytes[4] === 0x0D && bytes[5] === 0x0A && bytes[6] === 0x1A && bytes[7] === 0x0A) {
    return {
      type: FILE_TYPES.IMAGE_PNG,
      extension: ext,
      name: fileName,
      mime: 'image/png',
      isMagicVerified: true,
      warning: ext !== 'png' ? `Extension '.${ext}' mismatches detected PNG image.` : null
    };
  }

  // 6. GIF (GIF87a or GIF89a -> 0x47 0x49 0x46 0x38)
  if (bytes.length >= 6 &&
      bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) {
    return {
      type: FILE_TYPES.IMAGE_GIF,
      extension: ext,
      name: fileName,
      mime: 'image/gif',
      isMagicVerified: true,
      warning: ext !== 'gif' ? `Extension '.${ext}' mismatches detected GIF image.` : null
    };
  }

  // 7. PK Zip / Office Open XML (0x50 0x4B 0x03 0x04 -> PK..)
  if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04) {
    return {
      type: FILE_TYPES.OFFICE_DOCX,
      extension: ext,
      name: fileName,
      mime: 'application/vnd.openxmlformats-officedocument',
      isMagicVerified: true,
      warning: null
    };
  }

  // 8. OLE2 Binary Office Format (0xD0 0xCF 0x11 0xE0)
  if (bytes.length >= 4 && bytes[0] === 0xD0 && bytes[1] === 0xCF && bytes[2] === 0x11 && bytes[3] === 0xE0) {
    return {
      type: FILE_TYPES.OFFICE_OLE,
      extension: ext,
      name: fileName,
      mime: 'application/msword',
      isMagicVerified: true,
      warning: null
    };
  }

  // 9. EML Email (Check text content for RFC 822 headers)
  const textHeader = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  if (/^(Received:|From:|To:|Subject:|MIME-Version:|Return-Path:)/im.test(textHeader) || ext === 'eml' || ext === 'msg') {
    return {
      type: FILE_TYPES.EMAIL_EML,
      extension: ext,
      name: fileName,
      mime: 'message/rfc822',
      isMagicVerified: true,
      warning: null
    };
  }

  // 10. Fallback: Generic File
  return {
    type: FILE_TYPES.GENERIC,
    extension: ext,
    name: fileName,
    mime: 'application/octet-stream',
    isMagicVerified: false,
    warning: `Unrecognized binary header. Analyzing as generic artifact.`
  };
}
