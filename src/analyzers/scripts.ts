import fs from 'node:fs';
import path from 'node:path';
import { Finding, FindingCategory, RiskLevel } from '../types.js';
import { sha256 } from '../evidence/determinism.js';

export function analyzeScripts(filePath: string, rootDir: string): Finding[] {
  const findings: Finding[] = [];
  const relativePath = path.relative(rootDir, filePath).replace(/\\/g, '/');

  try {
    const rawContent = fs.readFileSync(filePath, 'utf-8');
    const lines = rawContent.split(/\r?\n/);

    lines.forEach((lineText, index) => {
      const lineNum = index + 1;
      const trimmed = lineText.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) return;

      // 1. Remote download and pipe to shell (RED)
      if (/(curl|wget)\s+.*\|\s*(ba)?sh/i.test(lineText) || /Invoke-WebRequest.*\|\s*iex/i.test(lineText)) {
        findings.push({
          id: `FND-SCR-${sha256(`${relativePath}:${lineNum}:pipe`).substring(0, 8).toUpperCase()}`,
          file: relativePath,
          line: lineNum,
          column: 1,
          category: 'DOWNLOAD_AND_EXECUTE' as FindingCategory,
          riskLevel: 'RED' as RiskLevel,
          title: 'Remote Download Piped to Shell Interpreter',
          description: `Script downloads remote content and pipes directly into a shell interpreter.`,
          snippet: trimmed,
          explanation: `Piping unverified remote HTTP content into bash/sh/PowerShell allows arbitrary remote code execution without integrity checks.`,
          remediation: `Download content to a file, verify checksum/signature, then execute safely.`,
        });
      }

      // 2. Encoded PowerShell Payload (RED)
      if (/powershell.*-enc(odedcommand)?\s+[A-Za-z0-9+/=]{10,}/i.test(lineText)) {
        findings.push({
          id: `FND-SCR-${sha256(`${relativePath}:${lineNum}:psenc`).substring(0, 8).toUpperCase()}`,
          file: relativePath,
          line: lineNum,
          column: 1,
          category: 'OBFUSCATION' as FindingCategory,
          riskLevel: 'RED' as RiskLevel,
          title: 'Encoded PowerShell Payload',
          description: `Script contains base64-encoded PowerShell execution command.`,
          snippet: trimmed,
          explanation: `Encoded PowerShell commands are standard malware evasion techniques to hide payload actions.`,
          remediation: `Decode and inspect the PowerShell command payload.`,
        });
      }

      // 3. Credential Harvesting (RED)
      if (/\/etc\/(shadow|passwd)|\.ssh\/id_rsa|\.aws\/credentials|AWS_SECRET_ACCESS_KEY|AZURE_OPENAI_API_KEY/i.test(lineText) && /(cat|curl|wget|nc|netcat|scp)/i.test(lineText)) {
        findings.push({
          id: `FND-SCR-${sha256(`${relativePath}:${lineNum}:cred`).substring(0, 8).toUpperCase()}`,
          file: relativePath,
          line: lineNum,
          column: 1,
          category: 'CREDENTIAL_ACCESS' as FindingCategory,
          riskLevel: 'RED' as RiskLevel,
          title: 'Credential Access and Potential Exfiltration',
          description: `Script attempts to read or transmit sensitive key/credential files.`,
          snippet: trimmed,
          explanation: `Accessing private SSH keys, AWS credentials, or system password shadow files poses extreme security risk.`,
          remediation: `Remove credential harvesting commands from script.`,
        });
      }

      // 4. Persistence Mechanisms (RED)
      if (/crontab\s+-|systemctl\s+enable|reg\s+add.*CurrentVersion\\Run/i.test(lineText)) {
        findings.push({
          id: `FND-SCR-${sha256(`${relativePath}:${lineNum}:persist`).substring(0, 8).toUpperCase()}`,
          file: relativePath,
          line: lineNum,
          column: 1,
          category: 'PERSISTENCE' as FindingCategory,
          riskLevel: 'RED' as RiskLevel,
          title: 'System Persistence Mechanism Installation',
          description: `Script attempts to install crontab, systemd service, or Windows registry autostart key.`,
          snippet: trimmed,
          explanation: `Modifying system startup rules allows unauthorized software to maintain persistent background access.`,
          remediation: `Remove persistence commands.`,
        });
      }
    });
  } catch (err) {
    // Read error
  }

  return findings;
}
