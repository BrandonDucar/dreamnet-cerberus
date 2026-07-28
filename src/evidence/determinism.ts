import crypto from 'node:crypto';
import fs from 'node:fs';

/**
 * Deterministically stringify any JSON value by recursively sorting object keys.
 */
export function canonicalizeJson(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return '[' + obj.map(item => canonicalizeJson(item)).join(',') + ']';
  }

  const sortedKeys = Object.keys(obj).sort();
  const keyValues = sortedKeys.map(key => {
    return `${JSON.stringify(key)}:${canonicalizeJson(obj[key])}`;
  });

  return '{' + keyValues.join(',') + '}';
}

/**
 * Calculate SHA-256 hash of a file synchronously in read-only mode.
 */
export function hashFileSha256(filePath: string): string {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Calculate SHA-256 digest of arbitrary text or buffer.
 */
export function sha256(content: string | Buffer): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Create a deterministic Scan ID from canonical receipt contents (excluding scanId itself).
 */
export function generateScanId(receiptData: Omit<any, 'scanId' | 'canonicalHash'>): { scanId: string; canonicalHash: string } {
  const canonicalStr = canonicalizeJson(receiptData);
  const hash = sha256(canonicalStr);
  const scanId = `SCN-${hash.substring(0, 16).toUpperCase()}`;
  return { scanId, canonicalHash: hash };
}
