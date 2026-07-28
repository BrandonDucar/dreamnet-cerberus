import fs from 'node:fs';
import path from 'node:path';
import { Finding, FindingCategory, RiskLevel } from '../types.js';
import { sha256 } from '../evidence/determinism.js';

export function analyzeMakefiles(filePath: string, rootDir: string): Finding[] {
  const findings: Finding[] = [];
  const relativePath = path.relative(rootDir, filePath).replace(/\\/g, '/');

  try {
    const rawContent = fs.readFileSync(filePath, 'utf-8');
    const lines = rawContent.split(/\r?\n/);

    lines.forEach((lineText, index) => {
      const lineNum = index + 1;

      if (/(curl|wget)\s+.*\|\s*(ba)?sh/i.test(lineText)) {
        findings.push({
          id: `FND-MK-${sha256(`${relativePath}:${lineNum}`).substring(0, 8).toUpperCase()}`,
          file: relativePath,
          line: lineNum,
          column: 1,
          category: 'MAKEFILE_SECURITY' as FindingCategory,
          riskLevel: 'RED' as RiskLevel,
          title: 'Remote Script Piping in Makefile Target',
          description: `Makefile target downloads remote URL and pipes directly to shell.`,
          snippet: lineText.trim(),
          explanation: `Running make commands that execute unverified remote scripts allows remote code execution.`,
          remediation: `Remove remote shell piping from Makefile.`,
        });
      }
    });
  } catch (err) {
    // Read error
  }

  return findings;
}
