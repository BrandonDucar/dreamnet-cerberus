import fs from 'node:fs';
import path from 'node:path';
import { Finding, FindingCategory, RiskLevel } from '../types.js';
import { sha256 } from '../evidence/determinism.js';

const SUSPICIOUS_LIFECYCLE_PATTERNS = [
  { pattern: /curl\s+.*\|\s*(ba)?sh/i, title: 'Lifecycle Script Piped Remote Execution', risk: 'RED' as RiskLevel },
  { pattern: /wget\s+.*\|\s*(ba)?sh/i, title: 'Lifecycle Script Piped Remote Execution', risk: 'RED' as RiskLevel },
  { pattern: /powershell.*-enc(odedcommand)?/i, title: 'Encoded PowerShell in Lifecycle Script', risk: 'RED' as RiskLevel },
  { pattern: /eval\(|new\s+Function/i, title: 'Dynamic Code Evaluation in Lifecycle Script', risk: 'RED' as RiskLevel },
  { pattern: /node\s+-e\s+['"].*(fetch|http|net|child_process)/i, title: 'Inline Node Execution with Network/Process in Lifecycle Script', risk: 'RED' as RiskLevel },
  { pattern: /download|fetch|curl|wget/i, title: 'Remote Download in Lifecycle Script', risk: 'RED' as RiskLevel },
];

export function analyzePackageJson(filePath: string, rootDir: string): Finding[] {
  const findings: Finding[] = [];
  const relativePath = path.relative(rootDir, filePath).replace(/\\/g, '/');

  try {
    const rawContent = fs.readFileSync(filePath, 'utf-8');
    const lines = rawContent.split(/\r?\n/);
    const json = JSON.parse(rawContent);

    if (!json.scripts || typeof json.scripts !== 'object') {
      return findings;
    }

    const lifecycleScriptKeys = [
      'preinstall', 'install', 'postinstall',
      'prepublish', 'prepare', 'prepack', 'postpack'
    ];

    for (const [key, value] of Object.entries(json.scripts)) {
      if (typeof value !== 'string') continue;

      const isLifecycle = lifecycleScriptKeys.includes(key.toLowerCase());
      
      // Find line number of script key in package.json
      const lineIndex = lines.findIndex(l => l.includes(`"${key}"`));
      const lineNum = lineIndex >= 0 ? lineIndex + 1 : 1;

      if (isLifecycle) {
        let matchedSuspicious = false;

        for (const rule of SUSPICIOUS_LIFECYCLE_PATTERNS) {
          if (rule.pattern.test(value)) {
            matchedSuspicious = true;
            findings.push({
              id: `FND-PKG-${sha256(`${relativePath}:${lineNum}:${key}`).substring(0, 8).toUpperCase()}`,
              file: relativePath,
              line: lineNum,
              column: 1,
              category: 'LIFECYCLE_SCRIPT' as FindingCategory,
              riskLevel: rule.risk,
              title: `${rule.title} (${key})`,
              description: `Package lifecycle script "${key}" contains dangerous execution pattern: "${value}"`,
              snippet: `"${key}": "${value}"`,
              explanation: `Automatic execution of lifecycle script "${key}" during npm/pnpm install runs unverified code with user privileges.`,
              remediation: `Remove lifecycle script "${key}" or replace with an explicit manual build command.`,
            });
            break;
          }
        }

        if (!matchedSuspicious) {
          // Standard lifecycle script warning (YELLOW tier)
          findings.push({
            id: `FND-PKG-${sha256(`${relativePath}:${lineNum}:${key}`).substring(0, 8).toUpperCase()}`,
            file: relativePath,
            line: lineNum,
            column: 1,
            category: 'LIFECYCLE_SCRIPT' as FindingCategory,
            riskLevel: 'YELLOW' as RiskLevel,
            title: `Package Lifecycle Script Detected (${key})`,
            description: `Package lifecycle script "${key}" will execute automatically upon installation.`,
            snippet: `"${key}": "${value}"`,
            explanation: `Lifecycle scripts execute automatically when a dependency is installed. Review script logic before running install.`,
            remediation: `Inspect script contents or run installation with --ignore-scripts flag.`,
          });
        }
      }
    }
  } catch (err) {
    // Malformed JSON or read error
  }

  return findings;
}
