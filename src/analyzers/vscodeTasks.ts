import fs from 'node:fs';
import path from 'node:path';
import { Finding, FindingCategory, RiskLevel } from '../types.js';
import { sha256 } from '../evidence/determinism.js';

export function analyzeVSCodeTasks(filePath: string, rootDir: string): Finding[] {
  const findings: Finding[] = [];
  const relativePath = path.relative(rootDir, filePath).replace(/\\/g, '/');

  try {
    const rawContent = fs.readFileSync(filePath, 'utf-8');

    if (/runOn\s*:\s*['"]folderOpen['"]/i.test(rawContent)) {
      findings.push({
        id: `FND-VSC-${sha256(`${relativePath}:folderOpen`).substring(0, 8).toUpperCase()}`,
        file: relativePath,
        line: 1,
        column: 1,
        category: 'VSCODE_TASK' as FindingCategory,
        riskLevel: 'RED' as RiskLevel,
        title: 'Automatic Code Execution on Workspace Open (folderOpen)',
        description: `VS Code configuration contains automated task configured to run when folder is opened.`,
        snippet: `"runOn": "folderOpen"`,
        explanation: `Configuring tasks to run automatically on folder open executes untrusted commands simply by opening the repository in an editor.`,
        remediation: `Remove "runOn": "folderOpen" setting from .vscode/tasks.json.`,
      });
    }
  } catch (err) {
    // Read error
  }

  return findings;
}
