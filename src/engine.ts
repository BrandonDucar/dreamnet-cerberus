import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { Finding, Provenance, CanonicalScanReceipt, ScanOptions } from './types.js';
import { hashFileSha256 } from './evidence/determinism.js';
import { buildCanonicalReceipt } from './evidence/receipt.js';
import { analyzePackageJson } from './analyzers/packageJson.js';
import { analyzeGitHooks } from './analyzers/gitHooks.js';
import { analyzeScripts } from './analyzers/scripts.js';
import { analyzeJavaScriptTypeScript } from './analyzers/jsTs.js';
import { analyzeGitHubWorkflows } from './analyzers/githubWorkflows.js';
import { analyzeVSCodeTasks } from './analyzers/vscodeTasks.js';
import { analyzeContainerFiles } from './analyzers/containerFiles.js';
import { analyzeMakefiles } from './analyzers/makefiles.js';
import { analyzeLockfiles } from './analyzers/lockfiles.js';

export async function scanRepository(targetPath: string, options: Partial<ScanOptions> = {}): Promise<CanonicalScanReceipt> {
  const absoluteTarget = path.resolve(targetPath);
  if (!fs.existsSync(absoluteTarget)) {
    throw new Error(`Scan target path does not exist: ${absoluteTarget}`);
  }

  const findings: Finding[] = [];
  const fileHashes: Record<string, string> = {};
  let totalFilesScanned = 0;

  function walkDirectory(currentDir: string) {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relativePath = path.relative(absoluteTarget, fullPath).replace(/\\/g, '/');

      // Skip node_modules, dist, build, .git internal objects
      if (entry.isDirectory()) {
        if (
          entry.name === 'node_modules' ||
          entry.name === 'dist' ||
          entry.name === 'build' ||
          (entry.name === '.git' && !relativePath.includes('hooks'))
        ) {
          continue;
        }
        walkDirectory(fullPath);
      } else if (entry.isFile()) {
        totalFilesScanned++;
        const fileHash = hashFileSha256(fullPath);
        fileHashes[relativePath] = fileHash;

        // Dispatch to static analyzers based on file type and path
        const fileName = entry.name.toLowerCase();

        // 1. package.json
        if (fileName === 'package.json') {
          findings.push(...analyzePackageJson(fullPath, absoluteTarget));
        }
        // 2. Git hooks (.husky/ or .git/hooks/)
        else if (relativePath.includes('.husky') || relativePath.includes('.git/hooks')) {
          findings.push(...analyzeGitHooks(fullPath, absoluteTarget));
        }
        // 3. Shell / PowerShell scripts
        else if (/\.(sh|bash|zsh|ps1|bat|cmd)$/i.test(fileName)) {
          findings.push(...analyzeScripts(fullPath, absoluteTarget));
        }
        // 4. JavaScript / TypeScript
        else if (/\.(js|mjs|cjs|ts|tsx)$/i.test(fileName)) {
          findings.push(...analyzeJavaScriptTypeScript(fullPath, absoluteTarget));
        }
        // 5. GitHub Workflows
        else if (relativePath.startsWith('.github/workflows/')) {
          findings.push(...analyzeGitHubWorkflows(fullPath, absoluteTarget));
        }
        // 6. VS Code Tasks
        else if (relativePath.startsWith('.vscode/')) {
          findings.push(...analyzeVSCodeTasks(fullPath, absoluteTarget));
        }
        // 7. Container files
        else if (fileName === 'dockerfile' || fileName.startsWith('docker-compose')) {
          findings.push(...analyzeContainerFiles(fullPath, absoluteTarget));
        }
        // 8. Makefiles
        else if (fileName === 'makefile') {
          findings.push(...analyzeMakefiles(fullPath, absoluteTarget));
        }
        // 9. Lockfiles
        else if (fileName === 'package-lock.json' || fileName === 'yarn.lock' || fileName === 'pnpm-lock.yaml') {
          findings.push(...analyzeLockfiles(fullPath, absoluteTarget));
        }
      }
    }
  }

  walkDirectory(absoluteTarget);

  const provenance: Provenance = {
    scannerName: '@dreamnet/cerberus',
    scannerVersion: '1.0.0',
    nodeVersion: process.version,
    platform: process.platform,
    scannedAt: new Date().toISOString(),
  };

  return buildCanonicalReceipt(
    path.basename(absoluteTarget),
    totalFilesScanned,
    findings,
    fileHashes,
    provenance
  );
}
