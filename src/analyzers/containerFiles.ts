import fs from 'node:fs';
import path from 'node:path';
import { Finding, FindingCategory, RiskLevel } from '../types.js';
import { sha256 } from '../evidence/determinism.js';

export function analyzeContainerFiles(filePath: string, rootDir: string): Finding[] {
  const findings: Finding[] = [];
  const relativePath = path.relative(rootDir, filePath).replace(/\\/g, '/');

  try {
    const rawContent = fs.readFileSync(filePath, 'utf-8');
    const lines = rawContent.split(/\r?\n/);

    lines.forEach((lineText, index) => {
      const lineNum = index + 1;

      // 1. Root volume mount of host filesystem (RED)
      if (/:(\/|\/host|\/root)/i.test(lineText) && /volumes:/i.test(rawContent)) {
        findings.push({
          id: `FND-CTR-${sha256(`${relativePath}:${lineNum}:vol`).substring(0, 8).toUpperCase()}`,
          file: relativePath,
          line: lineNum,
          column: 1,
          category: 'CONTAINER_SECURITY' as FindingCategory,
          riskLevel: 'RED' as RiskLevel,
          title: 'Dangerous Host Root Mount in Container Config',
          description: `Container configuration mounts root host filesystem into container.`,
          snippet: lineText.trim(),
          explanation: `Mounting host root filesystem into container allows containerized process to escape sandbox and gain full host root access.`,
          remediation: `Restrict volume mounts to minimal specific application subdirectories.`,
        });
      }

      // 2. Download and execute in Dockerfile RUN (RED)
      if (/RUN\s+.*(curl|wget)\s+.*\|\s*(ba)?sh/i.test(lineText)) {
        findings.push({
          id: `FND-CTR-${sha256(`${relativePath}:${lineNum}:runpipe`).substring(0, 8).toUpperCase()}`,
          file: relativePath,
          line: lineNum,
          column: 1,
          category: 'CONTAINER_SECURITY' as FindingCategory,
          riskLevel: 'RED' as RiskLevel,
          title: 'Unverified Remote Download in Dockerfile RUN Step',
          description: `Dockerfile RUN command pipes remote URL content into shell.`,
          snippet: lineText.trim(),
          explanation: `Piping unverified remote scripts during container build creates untrusted image builds.`,
          remediation: `Download file first, verify cryptographic checksum, then execute.`,
        });
      }
    });
  } catch (err) {
    // Read error
  }

  return findings;
}
