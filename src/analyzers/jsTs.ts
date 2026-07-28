import fs from 'node:fs';
import path from 'node:path';
import { Finding, FindingCategory, RiskLevel } from '../types.js';
import { sha256 } from '../evidence/determinism.js';

export function analyzeJavaScriptTypeScript(filePath: string, rootDir: string): Finding[] {
  const findings: Finding[] = [];
  const relativePath = path.relative(rootDir, filePath).replace(/\\/g, '/');

  try {
    const rawContent = fs.readFileSync(filePath, 'utf-8');
    const lines = rawContent.split(/\r?\n/);

    lines.forEach((lineText, index) => {
      const lineNum = index + 1;
      const trimmed = lineText.trim();
      if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) return;

      // 1. Dynamic Code Execution: eval(), new Function() (RED)
      if (/\beval\s*\(|new\s+Function\s*\(/i.test(lineText)) {
        findings.push({
          id: `FND-JSTS-${sha256(`${relativePath}:${lineNum}:eval`).substring(0, 8).toUpperCase()}`,
          file: relativePath,
          line: lineNum,
          column: lineText.indexOf('eval') >= 0 ? lineText.indexOf('eval') + 1 : lineText.indexOf('Function') + 1,
          category: 'DANGEROUS_API' as FindingCategory,
          riskLevel: 'RED' as RiskLevel,
          title: 'Dynamic Code Evaluation (eval / new Function)',
          description: `JavaScript/TypeScript code executes arbitrary string content dynamically.`,
          snippet: trimmed,
          explanation: `Using eval() or new Function() allows runtime execution of unverified text, bypassing static security controls.`,
          remediation: `Refactor code to avoid dynamic code generation or use strict JSON parsing.`,
        });
      }

      // 2. Process Execution APIs: child_process.exec, execSync, spawn (YELLOW / RED if combined with remote fetch)
      if (/\b(child_process|execSync|execFile|spawnSync)\b|\brequire\s*\(\s*['"]child_process['"]\s*\)/i.test(lineText)) {
        const isRemoteCombine = /fetch\(|http\.get|axios|got|https/i.test(rawContent);
        const risk: RiskLevel = isRemoteCombine ? 'RED' : 'YELLOW';

        findings.push({
          id: `FND-JSTS-${sha256(`${relativePath}:${lineNum}:proc`).substring(0, 8).toUpperCase()}`,
          file: relativePath,
          line: lineNum,
          column: 1,
          category: 'DANGEROUS_API' as FindingCategory,
          riskLevel: risk,
          title: `Child Process Execution API Used (${risk === 'RED' ? 'Combined with Network Fetch' : 'Local Process Call'})`,
          description: `Code invokes Node.js child_process execution primitives.`,
          snippet: trimmed,
          explanation: `Child process primitives allow execution of arbitrary shell binaries on host machine.`,
          remediation: `Ensure command arguments are sanitized and avoid shell interpolation.`,
        });
      }

      // 3. Remote Fetch + Dynamic Code Execution combination (RED)
      if (/\b(fetch|http|https|axios|got)\b/i.test(lineText) && (rawContent.includes('eval(') || rawContent.includes('new Function'))) {
        findings.push({
          id: `FND-JSTS-${sha256(`${relativePath}:${lineNum}:remotefunc`).substring(0, 8).toUpperCase()}`,
          file: relativePath,
          line: lineNum,
          column: 1,
          category: 'DOWNLOAD_AND_EXECUTE' as FindingCategory,
          riskLevel: 'RED' as RiskLevel,
          title: 'Remote Network Fetch Combined with Dynamic Evaluation',
          description: `Code fetches remote content and passes it into dynamic evaluation APIs.`,
          snippet: trimmed,
          explanation: `Downloading JavaScript dynamically over network and executing it via eval/Function is a severe remote code execution flaw.`,
          remediation: `Never execute remote network code dynamically. Use verified package imports.`,
        });
      }

      // 4. Obfuscation Patterns (Hex / Base64 charcodes) (RED)
      if (/String\.fromCharCode\s*\(\s*(\d+\s*,\s*){4,}/i.test(lineText) || /\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){5,}/i.test(lineText)) {
        findings.push({
          id: `FND-JSTS-${sha256(`${relativePath}:${lineNum}:obfus`).substring(0, 8).toUpperCase()}`,
          file: relativePath,
          line: lineNum,
          column: 1,
          category: 'OBFUSCATION' as FindingCategory,
          riskLevel: 'RED' as RiskLevel,
          title: 'Obfuscated Character Code / Hex String Array',
          description: `Code uses character code arrays or heavy hex escaping to obfuscate execution logic.`,
          snippet: trimmed,
          explanation: `Character code obfuscation is used to hide malicious logic from static code review.`,
          remediation: `Deobfuscate code and express logic in plain TypeScript/JavaScript.`,
        });
      }
    });
  } catch (err) {
    // Read error
  }

  return findings;
}
