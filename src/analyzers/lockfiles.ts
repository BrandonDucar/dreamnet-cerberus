import fs from 'node:fs';
import path from 'node:path';
import { Finding, FindingCategory, RiskLevel } from '../types.js';
import { sha256 } from '../evidence/determinism.js';

export function analyzeLockfiles(filePath: string, rootDir: string): Finding[] {
  const findings: Finding[] = [];
  const relativePath = path.relative(rootDir, filePath).replace(/\\/g, '/');

  try {
    const rawContent = fs.readFileSync(filePath, 'utf-8');
    const lines = rawContent.split(/\r?\n/);

    lines.forEach((lineText, index) => {
      const lineNum = index + 1;

      // Unencrypted HTTP package registry URL (RED)
      if (/http:\/\/[a-zA-Z0-9.-]+\/.*\.tgz/i.test(lineText)) {
        findings.push({
          id: `FND-LCK-${sha256(`${relativePath}:${lineNum}:http`).substring(0, 8).toUpperCase()}`,
          file: relativePath,
          line: lineNum,
          column: 1,
          category: 'UNKNOWN_OUTBOUND_DOMAIN' as FindingCategory,
          riskLevel: 'RED' as RiskLevel,
          title: 'Unencrypted Insecure HTTP Package Source in Lockfile',
          description: `Lockfile references dependency package resolution over plain HTTP.`,
          snippet: lineText.trim(),
          explanation: `Insecure HTTP package downloads are vulnerable to man-in-the-middle code injection.`,
          remediation: `Enforce HTTPS for all package registry sources in lockfile.`,
        });
      }
    });
  } catch (err) {
    // Read error
  }

  return findings;
}
