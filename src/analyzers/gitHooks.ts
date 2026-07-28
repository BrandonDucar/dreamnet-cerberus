import fs from 'node:fs';
import path from 'node:path';
import { Finding, FindingCategory, RiskLevel } from '../types.js';
import { sha256 } from '../evidence/determinism.js';

export function analyzeGitHooks(filePath: string, rootDir: string): Finding[] {
  const findings: Finding[] = [];
  const relativePath = path.relative(rootDir, filePath).replace(/\\/g, '/');

  try {
    const rawContent = fs.readFileSync(filePath, 'utf-8');
    const lines = rawContent.split(/\r?\n/);
    const hookName = path.basename(filePath);

    let hasSuspiciousPattern = false;

    lines.forEach((lineText, index) => {
      const lineNum = index + 1;

      // 1. Check for remote fetch / curl / wget inside git hooks
      if (/curl\s+.*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh/i.test(lineText)) {
        hasSuspiciousPattern = true;
        findings.push({
          id: `FND-HOOK-${sha256(`${relativePath}:${lineNum}`).substring(0, 8).toUpperCase()}`,
          file: relativePath,
          line: lineNum,
          column: 1,
          category: 'GIT_HOOK' as FindingCategory,
          riskLevel: 'RED' as RiskLevel,
          title: `Malicious Remote Execution in Git Hook (${hookName})`,
          description: `Git hook "${hookName}" downloads and pipes remote code to a shell interpreter.`,
          snippet: lineText.trim(),
          explanation: `Git hooks execute automatically during git actions (commit, push, checkout). Executing untrusted remote scripts compromises developer environment.`,
          remediation: `Remove the remote script execution from the Git hook or delete the hook.`,
        });
      }
      // 2. Check for encoded commands / eval inside git hooks
      else if (/powershell.*-enc|eval\(|new\s+Function/i.test(lineText)) {
        hasSuspiciousPattern = true;
        findings.push({
          id: `FND-HOOK-${sha256(`${relativePath}:${lineNum}`).substring(0, 8).toUpperCase()}`,
          file: relativePath,
          line: lineNum,
          column: 1,
          category: 'GIT_HOOK' as FindingCategory,
          riskLevel: 'RED' as RiskLevel,
          title: `Suspicious Encoded Payload in Git Hook (${hookName})`,
          description: `Git hook "${hookName}" contains obfuscated or dynamic code evaluation.`,
          snippet: lineText.trim(),
          explanation: `Obfuscated commands in Git hooks are a common persistence and exfiltration vector.`,
          remediation: `Inspect and sanitize the Git hook contents.`,
        });
      }
    });

    // 3. Generic active git hook detection (YELLOW tier if non-empty script and no RED pattern)
    if (!hasSuspiciousPattern && lines.length > 0 && lines[0].startsWith('#!')) {
      findings.push({
        id: `FND-HOOK-${sha256(`${relativePath}:1`).substring(0, 8).toUpperCase()}`,
        file: relativePath,
        line: 1,
        column: 1,
        category: 'GIT_HOOK' as FindingCategory,
        riskLevel: 'YELLOW' as RiskLevel,
        title: `Active Git Hook File Present (${hookName})`,
        description: `Git hook "${hookName}" will execute automatically during Git lifecycle events.`,
        snippet: lines[0].trim(),
        explanation: `Git hooks can execute arbitrary local shell commands when developer runs git commit or push.`,
        remediation: `Verify that the Git hook script originates from trusted repository configuration.`,
      });
    }
  } catch (err) {
    // Read error
  }

  return findings;
}
