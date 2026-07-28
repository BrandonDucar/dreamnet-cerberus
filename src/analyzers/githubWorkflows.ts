import fs from 'node:fs';
import path from 'node:path';
import { Finding, FindingCategory, RiskLevel } from '../types.js';
import { sha256 } from '../evidence/determinism.js';

export function analyzeGitHubWorkflows(filePath: string, rootDir: string): Finding[] {
  const findings: Finding[] = [];
  const relativePath = path.relative(rootDir, filePath).replace(/\\/g, '/');

  try {
    const rawContent = fs.readFileSync(filePath, 'utf-8');
    const lines = rawContent.split(/\r?\n/);

    lines.forEach((lineText, index) => {
      const lineNum = index + 1;

      // 1. Dangerous pull_request_target checkout
      if (/pull_request_target/i.test(lineText) && rawContent.includes('actions/checkout')) {
        findings.push({
          id: `FND-GHA-${sha256(`${relativePath}:${lineNum}:prtarget`).substring(0, 8).toUpperCase()}`,
          file: relativePath,
          line: lineNum,
          column: 1,
          category: 'WORKFLOW_SECURITY' as FindingCategory,
          riskLevel: 'RED' as RiskLevel,
          title: 'Dangerous pull_request_target with Untrusted Code Checkout',
          description: `GitHub Workflow uses pull_request_target trigger combined with PR code checkout.`,
          snippet: lineText.trim(),
          explanation: `Combining pull_request_target with checking out untrusted pull request code grants repository write permissions and secrets access to external pull requests.`,
          remediation: `Use standard pull_request trigger or isolate untrusted PR code execution into a separate read-only workflow.`,
        });
      }

      // 2. Unpinned third-party action
      if (/uses:\s*[a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+@(v\d+|master|main)/i.test(lineText)) {
        findings.push({
          id: `FND-GHA-${sha256(`${relativePath}:${lineNum}:unpinned`).substring(0, 8).toUpperCase()}`,
          file: relativePath,
          line: lineNum,
          column: 1,
          category: 'WORKFLOW_SECURITY' as FindingCategory,
          riskLevel: 'YELLOW' as RiskLevel,
          title: 'Unpinned Third-Party GitHub Action Tag',
          description: `Workflow uses unpinned branch or mutable tag instead of immutable commit SHA.`,
          snippet: lineText.trim(),
          explanation: `Third-party actions referenced by mutable tags (e.g. @v1, @main) can be updated upstream without review.`,
          remediation: `Pin third-party GitHub Actions to immutable full 40-character commit SHAs.`,
        });
      }
    });
  } catch (err) {
    // Read error
  }

  return findings;
}
