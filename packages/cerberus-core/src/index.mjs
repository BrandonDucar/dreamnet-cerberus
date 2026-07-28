import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const CERBERUS_VERSION = '0.1.0';

export const DEFAULT_POLICY = Object.freeze({
  schema: 'dreamnet.cerberus-policy.v1',
  allowedVerdicts: ['green'],
  internalScopes: ['@dreamnet/'],
  limits: {
    maxFiles: 12_000,
    maxTotalBytes: 250 * 1024 * 1024,
    maxTextBytesPerFile: 2 * 1024 * 1024,
    maxFindings: 2_000,
    maxNetworkDestinations: 500,
  },
  thresholds: {
    yellow: 15,
    orange: 40,
    red: 70,
  },
  suspiciousHosts: [
    'pastebin.com',
    'gist.githubusercontent.com',
    'raw.githubusercontent.com',
    'cdn.discordapp.com',
    'media.discordapp.net',
    'api.telegram.org',
    'ipfs.io',
    'gateway.pinata.cloud',
  ],
});

const SKIPPED_DIRECTORY_NAMES = new Set([
  'node_modules',
  '.venv',
  'venv',
  'dist',
  'build',
  'coverage',
  '.next',
  '.svelte-kit',
  '.wrangler',
  '.cache',
  '__pycache__',
]);

const DOCUMENT_EXTENSIONS = new Set([
  '.md',
  '.mdx',
  '.txt',
  '.rst',
  '.adoc',
]);

const EXECUTABLE_EXTENSIONS = new Set([
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.ts',
  '.tsx',
  '.py',
  '.sh',
  '.bash',
  '.zsh',
  '.fish',
  '.ps1',
  '.bat',
  '.cmd',
  '.rb',
  '.pl',
  '.php',
  '.lua',
]);

const BINARY_EXTENSIONS = new Set([
  '.7z',
  '.avi',
  '.bmp',
  '.class',
  '.dll',
  '.dmg',
  '.doc',
  '.docx',
  '.eot',
  '.exe',
  '.gif',
  '.gz',
  '.ico',
  '.jar',
  '.jpeg',
  '.jpg',
  '.mov',
  '.mp3',
  '.mp4',
  '.msi',
  '.otf',
  '.pdf',
  '.png',
  '.pyc',
  '.so',
  '.tar',
  '.tgz',
  '.ttf',
  '.wasm',
  '.webm',
  '.webp',
  '.woff',
  '.woff2',
  '.xls',
  '.xlsx',
  '.zip',
]);

const NODE_LOCKFILES = [
  'package-lock.json',
  'npm-shrinkwrap.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'bun.lock',
  'bun.lockb',
];

const GENERIC_RULES = [
  {
    id: 'execution.dynamic-function',
    category: 'execution',
    severity: 'high',
    message: 'Dynamic JavaScript evaluation primitive detected.',
    pattern: /\b(?:new\s+Function|Function)\s*\(|\beval\s*\(/,
  },
  {
    id: 'execution.node-child-process',
    category: 'execution',
    severity: 'high',
    message: 'Node child-process execution capability detected.',
    pattern: /\b(?:child_process|execSync|execFileSync|spawnSync|execFile|spawn)\b/,
  },
  {
    id: 'execution.python-dynamic',
    category: 'execution',
    severity: 'high',
    message: 'Python dynamic execution or unsafe deserialization primitive detected.',
    pattern: /\b(?:eval|exec|pickle\.loads?|marshal\.loads?)\s*\(/,
    filePattern: /\.(?:py|pyw)$/i,
  },
  {
    id: 'execution.python-process',
    category: 'execution',
    severity: 'high',
    message: 'Python operating-system command execution capability detected.',
    pattern: /\b(?:subprocess\.(?:run|Popen|call|check_output)|os\.system)\s*\(/,
    filePattern: /\.(?:py|pyw)$/i,
  },
  {
    id: 'execution.shell-pipe',
    category: 'execution',
    severity: 'critical',
    message: 'Remote content is piped directly into a shell.',
    pattern: /\b(?:curl|wget|iwr|irm)\b[^\r\n|]*\|[^\r\n]*(?:bash|sh|zsh|powershell|pwsh|cmd)\b/i,
  },
  {
    id: 'execution.encoded-powershell',
    category: 'execution',
    severity: 'critical',
    message: 'Encoded PowerShell execution detected.',
    pattern: /\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]*(?:-enc|-encodedcommand)\b/i,
  },
  {
    id: 'execution.decode-and-run',
    category: 'execution',
    severity: 'high',
    message: 'Encoded content is decoded near an execution primitive.',
    pattern: /(?:base64|fromCharCode|atob|Convert\.FromBase64String)[\s\S]{0,240}(?:eval|Function|exec|Invoke-Expression|iex)\b/i,
  },
  {
    id: 'credential.harvesting',
    category: 'credential',
    severity: 'critical',
    message: 'Credential, wallet, browser-profile, or private-key harvesting behavior detected.',
    pattern: /(?:\.ssh[\\/](?:id_rsa|id_ed25519)|\.aws[\\/]credentials|\.config[\\/]gcloud|browser.*(?:profile|cookie)|metamask|wallet.*(?:seed|mnemonic)|process\.env[\s\S]{0,160}(?:TOKEN|SECRET|PRIVATE_KEY|PASSWORD))/i,
  },
  {
    id: 'persistence.system',
    category: 'execution',
    severity: 'high',
    message: 'System persistence behavior detected.',
    pattern: /\b(?:schtasks|crontab|systemctl\s+enable|launchctl\s+load|reg\s+add|New-ScheduledTask|StartupItems)\b/i,
  },
  {
    id: 'filesystem.permission-change',
    category: 'execution',
    severity: 'medium',
    message: 'Executable permission or ownership change detected.',
    pattern: /\b(?:chmod\s+(?:\+x|[0-7]*7[0-7]*)|chown\s|icacls\s)\b/i,
  },
  {
    id: 'network.dynamic-fetch-execute',
    category: 'network',
    severity: 'critical',
    message: 'Network response is dynamically executed.',
    pattern: /\bfetch\s*\([\s\S]{0,500}(?:new\s+Function|Function\s*\(|eval\s*\()/i,
  },
  {
    id: 'network.direct-ip',
    category: 'network',
    severity: 'high',
    message: 'Executable content references a direct IP address.',
    pattern: /\bhttps?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/i,
  },
  {
    id: 'analysis.environment-fingerprint',
    category: 'integrity',
    severity: 'medium',
    message: 'Environment fingerprinting or anti-analysis behavior detected.',
    pattern: /\b(?:IsDebuggerPresent|detect[-_]?vm|virtualbox|vmware|sandboxie|process\.platform|os\.hostname)\b/i,
  },
];

const PROMPT_INJECTION_RULES = [
  {
    id: 'prompt.override',
    severity: 'high',
    message: 'Repository text attempts to override trusted instructions.',
    pattern: /\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions?\b/i,
  },
  {
    id: 'prompt.secret-request',
    severity: 'critical',
    message: 'Repository text instructs an agent to read or disclose sensitive local material.',
    pattern: /\b(?:read|open|copy|upload|send|exfiltrate)\b[^\r\n]{0,180}(?:\.ssh|\.env|credentials|private key|seed phrase|mnemonic|browser cookies?)\b/i,
  },
  {
    id: 'prompt.concealment',
    severity: 'high',
    message: 'Repository text instructs an agent to conceal an action from the operator.',
    pattern: /\b(?:do not|don['’]t|never)\s+(?:tell|show|inform|mention)[^\r\n]{0,100}(?:user|operator|developer|owner)\b/i,
  },
];

const SEVERITY_POINTS = {
  critical: 70,
  high: 30,
  medium: 12,
  low: 3,
};

function sha256(input) {
  return createHash('sha256').update(input).digest('hex');
}

function normalizePath(value) {
  return String(value).replaceAll('\\', '/').replace(/^\.\/+/, '');
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, stableValue(value[key])]),
  );
}

function stableStringify(value) {
  return JSON.stringify(stableValue(value));
}

function mergePolicy(policy = {}) {
  return {
    ...DEFAULT_POLICY,
    ...policy,
    limits: { ...DEFAULT_POLICY.limits, ...(policy.limits || {}) },
    thresholds: { ...DEFAULT_POLICY.thresholds, ...(policy.thresholds || {}) },
    allowedVerdicts: policy.allowedVerdicts || DEFAULT_POLICY.allowedVerdicts,
    internalScopes: policy.internalScopes || DEFAULT_POLICY.internalScopes,
    suspiciousHosts: policy.suspiciousHosts || DEFAULT_POLICY.suspiciousHosts,
  };
}

function isWithinRoot(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function fileHash(filePath) {
  const hash = createHash('sha256');
  const fd = fs.openSync(filePath, 'r');
  const buffer = Buffer.allocUnsafe(64 * 1024);
  try {
    let bytesRead = 0;
    do {
      bytesRead = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead > 0) hash.update(buffer.subarray(0, bytesRead));
    } while (bytesRead > 0);
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest('hex');
}

function shouldSkipDirectory(relativePath) {
  const normalized = normalizePath(relativePath);
  const parts = normalized.split('/');
  if (parts[0] === '.git') return normalized !== '.git/hooks';
  return parts.some((part) => SKIPPED_DIRECTORY_NAMES.has(part));
}

function collectFiles(root, includePaths, limits) {
  const files = [];
  const skipped = [];
  let totalBytes = 0;
  let limitReached = false;

  function addPath(absolutePath, relativePath) {
    if (limitReached) return;
    const normalized = normalizePath(relativePath);
    let stat;
    try {
      stat = fs.lstatSync(absolutePath);
    } catch (error) {
      skipped.push({ path: normalized, reason: `lstat_failed:${error.code || 'unknown'}` });
      return;
    }

    if (files.length >= limits.maxFiles) {
      limitReached = true;
      skipped.push({ path: normalized, reason: 'max_files_reached' });
      return;
    }

    if (stat.isSymbolicLink()) {
      const target = fs.readlinkSync(absolutePath);
      files.push({
        path: normalized,
        absolutePath,
        kind: 'symlink',
        size: Buffer.byteLength(target),
        mode: stat.mode,
        digest: sha256(target),
        linkTarget: target,
      });
      return;
    }

    if (stat.isDirectory()) {
      if (shouldSkipDirectory(normalized)) {
        skipped.push({ path: normalized, reason: 'generated_or_dependency_directory' });
        return;
      }

      let entries = [];
      try {
        entries = fs.readdirSync(absolutePath, { withFileTypes: true });
      } catch (error) {
        skipped.push({ path: normalized, reason: `readdir_failed:${error.code || 'unknown'}` });
        return;
      }

      for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
        if (files.length >= limits.maxFiles || totalBytes >= limits.maxTotalBytes) {
          limitReached = true;
          break;
        }
        if (normalized === '' && entry.name === '.git') {
          const hooks = path.join(absolutePath, '.git', 'hooks');
          if (fs.existsSync(hooks)) addPath(hooks, '.git/hooks');
          continue;
        }
        addPath(path.join(absolutePath, entry.name), path.join(normalized, entry.name));
      }
      return;
    }

    if (!stat.isFile()) {
      skipped.push({ path: normalized, reason: 'unsupported_file_type' });
      return;
    }

    if (totalBytes + stat.size > limits.maxTotalBytes) {
      limitReached = true;
      skipped.push({ path: normalized, reason: 'max_total_bytes_reached' });
      return;
    }

    totalBytes += stat.size;
    files.push({
      path: normalized,
      absolutePath,
      kind: 'file',
      size: stat.size,
      mode: stat.mode,
      digest: fileHash(absolutePath),
    });
  }

  if (includePaths?.length) {
    const expandedPaths = new Set(includePaths.map(normalizePath));
    for (const requested of includePaths) {
      if (path.posix.basename(normalizePath(requested)).toLowerCase() !== 'package.json') continue;
      const directory = path.posix.dirname(normalizePath(requested));
      for (const lockfile of NODE_LOCKFILES) {
        const candidate = directory === '.' ? lockfile : `${directory}/${lockfile}`;
        if (fs.existsSync(path.resolve(root, candidate))) expandedPaths.add(candidate);
      }
    }

    for (const requested of expandedPaths) {
      const absolute = path.resolve(root, requested);
      if (!isWithinRoot(root, absolute)) {
        skipped.push({ path: normalizePath(requested), reason: 'path_outside_artifact_root' });
        continue;
      }
      if (!fs.existsSync(absolute)) {
        skipped.push({ path: normalizePath(requested), reason: 'path_missing' });
        continue;
      }
      addPath(absolute, path.relative(root, absolute));
    }
  } else {
    addPath(root, '');
  }

  const uniqueFiles = [...new Map(files.map((file) => [file.path, file])).values()]
    .sort((a, b) => a.path.localeCompare(b.path));

  return {
    files: uniqueFiles,
    skipped,
    totalBytes,
    limitReached,
  };
}

function isLikelyText(file) {
  const extension = path.extname(file.path).toLowerCase();
  if (BINARY_EXTENSIONS.has(extension)) return false;
  if (file.size === 0) return true;
  const fd = fs.openSync(file.absolutePath, 'r');
  const sample = Buffer.alloc(Math.min(8_192, file.size));
  try {
    fs.readSync(fd, sample, 0, sample.length, 0);
  } finally {
    fs.closeSync(fd);
  }
  return !sample.includes(0);
}

function readText(file, policy, limitations) {
  if (file.kind !== 'file' || !isLikelyText(file)) return null;
  if (file.size > policy.limits.maxTextBytesPerFile) {
    limitations.push(`Content scan skipped for oversized file: ${file.path}`);
    return null;
  }
  try {
    return fs.readFileSync(file.absolutePath, 'utf8');
  } catch (error) {
    limitations.push(`Content scan failed for ${file.path}: ${error.code || 'unknown'}`);
    return null;
  }
}

function lineNumber(text, index) {
  return text.slice(0, index).split(/\r?\n/).length;
}

function isDocumentation(filePath) {
  return DOCUMENT_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

function isExecutionSurface(filePath) {
  const normalized = normalizePath(filePath).toLowerCase();
  const base = path.posix.basename(normalized);
  const extension = path.posix.extname(normalized);
  return (
    EXECUTABLE_EXTENSIONS.has(extension) ||
    base === 'dockerfile' ||
    base.startsWith('dockerfile.') ||
    base === 'makefile' ||
    base === 'setup.py' ||
    base === 'pyproject.toml' ||
    base === 'package.json' ||
    normalized.startsWith('.husky/') ||
    normalized.startsWith('.git/hooks/') ||
    normalized.startsWith('.github/workflows/') ||
    normalized.startsWith('.vscode/') ||
    normalized.includes('/.vscode/') ||
    normalized.includes('.devcontainer')
  );
}

function lowerSeverity(severity) {
  return {
    critical: 'high',
    high: 'medium',
    medium: 'low',
    low: 'low',
  }[severity] || severity;
}

function isTestOrFixture(filePath) {
  return /(?:^|\/)(?:__tests__|test|tests|fixtures?)(?:\/|$)/i.test(normalizePath(filePath)) ||
    /\.(?:spec|test)\.[cm]?[jt]sx?$/i.test(filePath);
}

function matchedLine(text, index) {
  const start = text.lastIndexOf('\n', Math.max(0, index - 1)) + 1;
  const end = text.indexOf('\n', index);
  return text.slice(start, end === -1 ? text.length : end);
}

function findingId(finding) {
  return `cerb_${sha256([
    finding.ruleId,
    finding.file,
    finding.line || '',
    finding.evidenceHash || '',
  ].join('|')).slice(0, 16)}`;
}

function createFindingCollector(policy) {
  const findings = new Map();
  return {
    add(input) {
      if (findings.size >= policy.limits.maxFindings) return;
      const finding = {
        ruleId: input.ruleId,
        severity: input.severity,
        category: input.category,
        file: normalizePath(input.file),
        line: input.line || null,
        message: input.message,
        evidenceHash: input.evidenceHash || null,
        autoRun: Boolean(input.autoRun),
      };
      const id = findingId(finding);
      if (!findings.has(id)) findings.set(id, { id, ...finding });
    },
    values() {
      return [...findings.values()].sort((a, b) => {
        const rank = { critical: 0, high: 1, medium: 2, low: 3 };
        return (rank[a.severity] - rank[b.severity]) ||
          a.file.localeCompare(b.file) ||
          (a.line || 0) - (b.line || 0);
      });
    },
  };
}

function addPatternFinding(collector, file, text, rule, options = {}) {
  const match = text.match(rule.pattern);
  if (!match || typeof match.index !== 'number') return false;
  let severity = rule.severity;
  if (isDocumentation(file.path) && !options.preserveSeverity) {
    severity = lowerSeverity(lowerSeverity(lowerSeverity(severity)));
  }
  if (isTestOrFixture(file.path) && !options.preserveSeverity) {
    severity = lowerSeverity(lowerSeverity(lowerSeverity(severity)));
  }
  if (/\b(?:pattern|message)\s*:/.test(matchedLine(text, match.index))) {
    severity = lowerSeverity(lowerSeverity(lowerSeverity(severity)));
  }
  collector.add({
    ruleId: rule.id,
    severity,
    category: rule.category,
    file: file.path,
    line: lineNumber(text, match.index),
    message: rule.message,
    evidenceHash: sha256(match[0]),
    autoRun: options.autoRun,
  });
  return true;
}

function collectNetworkDestinations(file, text, destinations, collector, policy) {
  const urlPattern = /\bhttps?:\/\/[^\s"'`()<>\\]+/gi;
  for (const match of text.matchAll(urlPattern)) {
    if (destinations.size >= policy.limits.maxNetworkDestinations) break;
    try {
      const parsed = new URL(match[0].replace(/[),.;]+$/, ''));
      const key = `${parsed.protocol}//${parsed.host}`;
      destinations.set(key, {
        scheme: parsed.protocol.replace(':', ''),
        host: parsed.hostname.toLowerCase(),
        port: parsed.port || null,
        files: [...new Set([...(destinations.get(key)?.files || []), file.path])].slice(0, 20),
      });

      if (policy.suspiciousHosts.some((host) => parsed.hostname === host || parsed.hostname.endsWith(`.${host}`))) {
        let severity = isExecutionSurface(file.path) ? 'high' : 'medium';
        if (isTestOrFixture(file.path)) {
          severity = lowerSeverity(lowerSeverity(lowerSeverity(severity)));
        }
        collector.add({
          ruleId: 'network.suspicious-destination',
          severity,
          category: 'network',
          file: file.path,
          line: lineNumber(text, match.index),
          message: `Suspicious outbound destination category detected: ${parsed.hostname}.`,
          evidenceHash: sha256(parsed.hostname),
        });
      }
    } catch {
      // Malformed URLs remain covered by content rules without entering output.
    }
  }
}

function scanFilename(file, root, collector) {
  if (/[\u202A-\u202E\u2066-\u2069\u200B-\u200D\uFEFF]/u.test(file.path)) {
    collector.add({
      ruleId: 'unicode.filename-control',
      severity: 'high',
      category: 'integrity',
      file: file.path,
      message: 'Filename contains bidirectional or zero-width control characters.',
      evidenceHash: sha256(file.path),
    });
  } else if (file.path !== file.path.normalize('NFKC')) {
    collector.add({
      ruleId: 'unicode.filename-normalization',
      severity: 'medium',
      category: 'integrity',
      file: file.path,
      message: 'Filename changes under Unicode compatibility normalization.',
      evidenceHash: sha256(file.path),
    });
  }

  if (file.kind === 'symlink') {
    const resolved = path.resolve(path.dirname(file.absolutePath), file.linkTarget);
    const outside = path.isAbsolute(file.linkTarget) || !isWithinRoot(root, resolved);
    collector.add({
      ruleId: outside ? 'filesystem.symlink-outside-root' : 'filesystem.symlink',
      severity: outside ? 'high' : 'medium',
      category: 'integrity',
      file: file.path,
      message: outside
        ? 'Symlink resolves outside the artifact root.'
        : 'Symlink requires explicit review before materialization.',
      evidenceHash: sha256(file.linkTarget),
    });
  }
}

function scanGenericContent(file, text, collector) {
  if (!isExecutionSurface(file.path) && !isDocumentation(file.path)) return;
  for (const rule of GENERIC_RULES) {
    if (rule.filePattern && !rule.filePattern.test(file.path)) continue;
    addPatternFinding(collector, file, text, rule);
  }

  if (/[\u202A-\u202E\u2066-\u2069\u200B-\u200D\uFEFF]/u.test(text)) {
    collector.add({
      ruleId: 'unicode.content-control',
      severity: isExecutionSurface(file.path) ? 'high' : 'medium',
      category: 'integrity',
      file: file.path,
      message: 'Content contains bidirectional or zero-width control characters.',
      evidenceHash: sha256('unicode-control'),
    });
  }

  if (isDocumentation(file.path) || /(?:AGENTS|CLAUDE|SOUL|copilot-instructions)\.md$/i.test(file.path)) {
    for (const rule of PROMPT_INJECTION_RULES) {
      addPatternFinding(
        collector,
        file,
        text,
        { ...rule, category: 'promptInjection' },
        { preserveSeverity: true },
      );
    }
  }
}

function parseJson(text) {
  try {
    return { value: JSON.parse(text), error: null };
  } catch (error) {
    return { value: null, error };
  }
}

function dangerousScript(script) {
  return GENERIC_RULES.some((rule) => ['critical', 'high'].includes(rule.severity) && rule.pattern.test(script));
}

function dependencyPurl(ecosystem, name, version) {
  const safeName = encodeURIComponent(name).replaceAll('%2F', '/');
  return `pkg:${ecosystem}/${safeName}@${encodeURIComponent(version)}`;
}

function levenshtein(a, b) {
  const rows = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i += 1) rows[i][0] = i;
  for (let j = 0; j <= b.length; j += 1) rows[0][j] = j;
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      rows[i][j] = Math.min(
        rows[i - 1][j] + 1,
        rows[i][j - 1] + 1,
        rows[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
  }
  return rows[a.length][b.length];
}

const COMMON_NPM_PACKAGES = [
  'axios',
  'chalk',
  'commander',
  'dotenv',
  'express',
  'lodash',
  'react',
  'typescript',
  'vite',
  'zod',
];

function scanPackageJson(file, text, fileSet, collector, sbom, policy) {
  const parsed = parseJson(text);
  if (parsed.error) {
    collector.add({
      ruleId: 'manifest.package-json-invalid',
      severity: 'high',
      category: 'integrity',
      file: file.path,
      message: 'package.json could not be parsed as JSON.',
      evidenceHash: sha256(parsed.error.message),
    });
    return;
  }

  const manifest = parsed.value;
  const scripts = manifest.scripts && typeof manifest.scripts === 'object' ? manifest.scripts : {};
  for (const lifecycle of ['preinstall', 'install', 'postinstall', 'prepare']) {
    if (typeof scripts[lifecycle] !== 'string') continue;
    collector.add({
      ruleId: `npm.lifecycle.${lifecycle}`,
      severity: dangerousScript(scripts[lifecycle]) ? 'critical' : 'high',
      category: 'execution',
      file: file.path,
      message: `Automatic npm lifecycle script declared: ${lifecycle}.`,
      evidenceHash: sha256(scripts[lifecycle]),
      autoRun: true,
    });
  }

  let dependencyCount = 0;
  for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const dependencies = manifest[section];
    if (!dependencies || typeof dependencies !== 'object') continue;
    for (const [name, rawVersion] of Object.entries(dependencies)) {
      dependencyCount += 1;
      const version = String(rawVersion);
      sbom.push({
        ecosystem: 'npm',
        name,
        version,
        relationship: section,
        sourceFile: file.path,
        purl: dependencyPurl('npm', name, version),
      });

      if (/^(?:git\+|https?:\/\/|github:|gitlab:|bitbucket:)/i.test(version)) {
        collector.add({
          ruleId: 'dependency.remote-source',
          severity: /^[a-f0-9]{40}$/i.test(version.split('#').at(-1) || '') ? 'medium' : 'high',
          category: 'dependency',
          file: file.path,
          message: `Dependency ${name} resolves from a remote source instead of an immutable registry version.`,
          evidenceHash: sha256(`${name}@${version}`),
        });
      }

      if (version === '*' || /^latest$/i.test(version)) {
        collector.add({
          ruleId: 'dependency.unbounded-version',
          severity: 'medium',
          category: 'dependency',
          file: file.path,
          message: `Dependency ${name} uses an unbounded version.`,
          evidenceHash: sha256(name),
        });
      }

      if (policy.internalScopes.some((scope) => name.startsWith(scope)) && !/^workspace:/.test(version)) {
        collector.add({
          ruleId: 'dependency.internal-scope-confusion',
          severity: 'high',
          category: 'dependency',
          file: file.path,
          message: `Internal-scope dependency ${name} is not constrained to the workspace.`,
          evidenceHash: sha256(`${name}@${version}`),
        });
      }

      const normalizedName = name.replace(/^@[^/]+\//, '').toLowerCase();
      const lookalike = COMMON_NPM_PACKAGES.find(
        (known) => known !== normalizedName && normalizedName.length >= 4 && levenshtein(known, normalizedName) === 1,
      );
      if (lookalike) {
        collector.add({
          ruleId: 'dependency.lookalike-name',
          severity: 'high',
          category: 'dependency',
          file: file.path,
          message: `Dependency ${name} is visually similar to common package ${lookalike}.`,
          evidenceHash: sha256(name),
        });
      }
    }
  }

  if (dependencyCount > 0) {
    const directory = path.posix.dirname(file.path);
    const prefixes = directory === '.' ? [''] : [`${directory}/`];
    const hasLockfile = prefixes.some(
      (prefix) => NODE_LOCKFILES.some((name) => fileSet.has(`${prefix}${name}`)),
    );
    if (!hasLockfile) {
      collector.add({
        ruleId: 'dependency.lockfile-missing',
        severity: 'medium',
        category: 'dependency',
        file: file.path,
        message: 'Package dependencies are declared without a recognized lockfile.',
        evidenceHash: sha256(file.path),
      });
    }
  }
}

function scanRequirements(file, text, sbom, collector) {
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    if (/^(?:-e\s+)?(?:git\+|https?:\/\/)/i.test(line)) {
      collector.add({
        ruleId: 'dependency.python-remote-source',
        severity: 'high',
        category: 'dependency',
        file: file.path,
        message: 'Python dependency resolves from a remote source.',
        evidenceHash: sha256(line),
      });
      continue;
    }
    const match = line.match(/^([A-Za-z0-9_.-]+)==([^;\s]+)(?:;.*)?$/);
    if (match) {
      sbom.push({
        ecosystem: 'pypi',
        name: match[1],
        version: match[2],
        relationship: 'dependency',
        sourceFile: file.path,
        purl: dependencyPurl('pypi', match[1], match[2]),
      });
    } else {
      collector.add({
        ruleId: 'dependency.python-unpinned',
        severity: 'medium',
        category: 'dependency',
        file: file.path,
        message: 'Python dependency is not exactly pinned.',
        evidenceHash: sha256(line),
      });
    }
  }
}

function scanHook(file, text, collector) {
  if (!/^(?:\.husky|\.git\/hooks)\//i.test(file.path) || /\.sample$/i.test(file.path)) return;
  collector.add({
    ruleId: 'autorun.git-hook',
    severity: 'medium',
    category: 'execution',
    file: file.path,
    message: 'Automatic Git hook is present and requires explicit review.',
    evidenceHash: file.digest,
    autoRun: true,
  });
  if (dangerousScript(text)) {
    collector.add({
      ruleId: 'autorun.git-hook-dangerous',
      severity: 'critical',
      category: 'execution',
      file: file.path,
      message: 'Git hook contains high-risk execution behavior.',
      evidenceHash: file.digest,
      autoRun: true,
    });
  }
}

function scanGithubWorkflow(file, text, collector) {
  if (!/^\.github\/workflows\/.*\.ya?ml$/i.test(file.path)) return;
  if (/(?:^|\n)\s*(?:(?:on\s*:\s*)|(?:-\s*))?pull_request_target\s*:?(?:\s|$)/i.test(text)) {
    collector.add({
      ruleId: 'ci.pull-request-target',
      severity: 'high',
      category: 'ci',
      file: file.path,
      message: 'Workflow uses pull_request_target and requires strict untrusted-code isolation.',
      evidenceHash: sha256('pull_request_target'),
      autoRun: true,
    });
  }
  if (/^\s*permissions\s*:\s*write-all\s*$/im.test(text)) {
    collector.add({
      ruleId: 'ci.write-all',
      severity: 'critical',
      category: 'ci',
      file: file.path,
      message: 'Workflow grants write-all token permissions.',
      evidenceHash: sha256('permissions:write-all'),
      autoRun: true,
    });
  }
  for (const match of text.matchAll(/^\s*(?:-\s*)?uses\s*:\s*["']?([^"'\s#]+)["']?\s*$/gim)) {
    const reference = match[1];
    if (reference.startsWith('./') || /^docker:\/\/.+@sha256:[a-f0-9]{64}$/i.test(reference)) continue;
    const separator = reference.lastIndexOf('@');
    const revision = separator >= 0 ? reference.slice(separator + 1) : '';
    if (!/^[a-f0-9]{40}$/i.test(revision)) {
      collector.add({
        ruleId: 'ci.action-unpinned',
        severity: 'high',
        category: 'ci',
        file: file.path,
        line: lineNumber(text, match.index),
        message: `Third-party action is not pinned to a full commit SHA: ${reference.split('@')[0]}.`,
        evidenceHash: sha256(reference),
        autoRun: true,
      });
    }
  }
  if (/\$\{\{\s*github\.event\.(?:pull_request\.(?:title|body|head\.ref)|issue\.title|comment\.body)/i.test(text) &&
      /\brun\s*:\s*[|>]?/i.test(text)) {
    collector.add({
      ruleId: 'ci.untrusted-expression-shell',
      severity: 'high',
      category: 'ci',
      file: file.path,
      message: 'Untrusted event text may flow into a shell execution step.',
      evidenceHash: sha256('github.event-shell'),
      autoRun: true,
    });
  }
}

function scanDockerfile(file, text, collector) {
  const base = path.posix.basename(file.path).toLowerCase();
  if (base !== 'dockerfile' && !base.startsWith('dockerfile.')) return;
  for (const match of text.matchAll(/^\s*FROM\s+([^\s]+).*$/gim)) {
    const image = match[1];
    if (!/@sha256:[a-f0-9]{64}$/i.test(image)) {
      collector.add({
        ruleId: 'container.base-image-mutable',
        severity: 'medium',
        category: 'dependency',
        file: file.path,
        line: lineNumber(text, match.index),
        message: 'Container base image is not pinned by digest.',
        evidenceHash: sha256(image),
      });
    }
  }
}

function scanVscodeAndDevcontainer(file, text, collector) {
  if (!/(^|\/)(?:\.vscode\/tasks\.json|devcontainer\.json|\.devcontainer\/.*\.json)$/i.test(file.path)) return;
  if (/\b(?:postCreateCommand|postStartCommand|initializeCommand|shell|command)\b/i.test(text)) {
    collector.add({
      ruleId: 'editor.automatic-command',
      severity: 'high',
      category: 'execution',
      file: file.path,
      message: 'Editor or devcontainer configuration declares an execution surface.',
      evidenceHash: file.digest,
      autoRun: true,
    });
  }
}

function requestedCapabilities(findings, destinations) {
  const capabilities = new Set();
  for (const finding of findings) {
    if (finding.category === 'execution') capabilities.add('process/execute');
    if (finding.category === 'credential') capabilities.add('credentials/read');
    if (finding.category === 'ci') capabilities.add('ci/automation');
    if (finding.category === 'promptInjection') capabilities.add('agent/control-influence');
    if (finding.category === 'dependency') capabilities.add('packages/resolve');
  }
  if (destinations.length > 0) capabilities.add('network/egress');
  return [...capabilities].sort();
}

function scoreRisk(findings, intake, policy) {
  const scores = {
    provenance: 0,
    execution: 0,
    network: 0,
    dependency: 0,
    credential: 0,
    promptInjection: 0,
    ci: 0,
    integrity: 0,
  };

  if (!intake.source || intake.source.startsWith('local:')) scores.provenance += 25;
  if (!intake.sourceIdentity || intake.sourceIdentity === 'unverified') scores.provenance += 20;
  if (!intake.commit || !/^[a-f0-9]{40,64}$/i.test(intake.commit)) scores.provenance += 30;

  for (const finding of findings) {
    const category = finding.category in scores ? finding.category : 'integrity';
    scores[category] = Math.min(100, scores[category] + (SEVERITY_POINTS[finding.severity] || 0));
  }

  const scoreValues = Object.values(scores);
  const maximum = Math.max(...scoreValues);
  const average = scoreValues.reduce((sum, score) => sum + score, 0) / scoreValues.length;
  let overall = Math.min(100, Math.round(maximum * 0.65 + average * 0.35));

  const hasCritical = findings.some((finding) => finding.severity === 'critical');
  const highCount = findings.filter((finding) => finding.severity === 'high').length;
  const hasAutomaticLifecycle = findings.some((finding) => finding.autoRun && finding.ruleId.startsWith('npm.lifecycle.'));

  let verdict = overall >= policy.thresholds.red
    ? 'red'
    : overall >= policy.thresholds.orange
      ? 'orange'
      : overall >= policy.thresholds.yellow
        ? 'yellow'
        : 'green';

  if (hasCritical) {
    verdict = 'red';
    overall = Math.max(overall, 85);
  } else if (hasAutomaticLifecycle || highCount >= 2) {
    verdict = verdict === 'green' || verdict === 'yellow' ? 'orange' : verdict;
    overall = Math.max(overall, policy.thresholds.orange);
  } else if (scores.provenance > 0 && verdict === 'green') {
    verdict = 'yellow';
    overall = Math.max(overall, policy.thresholds.yellow);
  }

  return { scores, overall, verdict };
}

function artifactDigest(files) {
  const hash = createHash('sha256');
  for (const file of files) {
    hash.update(file.path);
    hash.update('\0');
    hash.update(file.kind);
    hash.update('\0');
    hash.update(String(file.mode));
    hash.update('\0');
    hash.update(String(file.size));
    hash.update('\0');
    hash.update(file.digest);
    hash.update('\0');
  }
  return `sha256:${hash.digest('hex')}`;
}

function receiptId(createdAt, digest) {
  const stamp = createdAt.replace(/[:.]/g, '-');
  return `cerberus_${stamp}_${digest.slice(-12)}`;
}

function countFindings(findings) {
  return findings.reduce(
    (counts, finding) => {
      counts[finding.severity] += 1;
      return counts;
    },
    { critical: 0, high: 0, medium: 0, low: 0 },
  );
}

function decisionReasons(verdict, findings, intake) {
  const reasons = [];
  if (!intake.source || intake.source.startsWith('local:')) reasons.push('source_identity_unverified');
  if (!intake.sourceIdentity || intake.sourceIdentity === 'unverified') reasons.push('publisher_identity_unverified');
  if (!intake.commit || !/^[a-f0-9]{40,64}$/i.test(intake.commit)) reasons.push('immutable_revision_unverified');
  if (findings.some((finding) => finding.severity === 'critical')) reasons.push('critical_static_finding');
  if (findings.some((finding) => finding.autoRun)) reasons.push('automatic_execution_surface');
  if (verdict === 'green') reasons.push('static_policy_pass');
  return reasons;
}

export function inspectArtifact(options) {
  const root = path.resolve(options.root || options.targetPath || '.');
  if (!fs.existsSync(root)) throw new Error(`Artifact path does not exist: ${root}`);
  if (!fs.statSync(root).isDirectory()) throw new Error('Cerberus Phase 1 expects an artifact directory.');

  const policy = mergePolicy(options.policy);
  const createdAt = options.createdAt || new Date().toISOString();
  const limitations = [
    'Static inspection only; no artifact code was executed.',
    'No threat-intelligence, registry, OSV, or network enrichment was performed.',
    'No dynamic detonation or system-call observation was performed.',
    'Receipt is hash-bound but unsigned until a signing identity is configured.',
  ];

  const collected = collectFiles(root, options.includePaths, policy.limits);
  if (collected.limitReached) limitations.push('Artifact traversal stopped at configured resource limits.');
  for (const skipped of collected.skipped) {
    if (skipped.reason === 'path_outside_artifact_root') {
      limitations.push(`Rejected requested path outside artifact root: ${skipped.path}`);
    }
  }

  const files = collected.files;
  const fileSet = new Set(files.map((file) => file.path));
  const collector = createFindingCollector(policy);
  const destinations = new Map();
  const sbom = [];

  for (const file of files) {
    scanFilename(file, root, collector);
    const text = readText(file, policy, limitations);
    if (text === null) continue;

    scanGenericContent(file, text, collector);
    collectNetworkDestinations(file, text, destinations, collector, policy);

    const base = path.posix.basename(file.path).toLowerCase();
    if (base === 'package.json') scanPackageJson(file, text, fileSet, collector, sbom, policy);
    if (/^requirements(?:-[^/]+)?\.txt$/i.test(base)) scanRequirements(file, text, sbom, collector);
    scanHook(file, text, collector);
    scanGithubWorkflow(file, text, collector);
    scanDockerfile(file, text, collector);
    scanVscodeAndDevcontainer(file, text, collector);
  }

  const findings = collector.values();
  const intake = {
    source: options.source || `local:${path.basename(root)}`,
    sourceIdentity: options.sourceIdentity || 'unverified',
    commit: options.commit || null,
    retrievedAt: options.retrievedAt || createdAt,
    declaredPurpose: options.declaredPurpose || 'security inspection',
    requestedBy: options.requestedBy || 'local-operator',
    requestedPermissions: options.requestedPermissions || [],
    snapshotMode: 'digest-only',
  };
  const digest = artifactDigest(files);
  const networkDestinations = [...destinations.values()].sort((a, b) => a.host.localeCompare(b.host));
  const risk = scoreRisk(findings, intake, policy);
  const allowed = policy.allowedVerdicts.includes(risk.verdict);
  const highRiskFiles = [...new Set(
    findings
      .filter((finding) => ['critical', 'high'].includes(finding.severity))
      .map((finding) => finding.file),
  )].sort();

  const receipt = {
    schema: 'dreamnet.security-receipt.v1',
    receiptId: receiptId(createdAt, digest),
    createdAt,
    intake,
    artifact: {
      name: options.artifactName || path.basename(root),
      kind: options.artifactKind || 'repository',
      digest,
      fileCount: files.length,
      totalBytes: collected.totalBytes,
      includedPathCount: options.includePaths?.length || null,
      manifest: files.map((file) => ({
        path: file.path,
        kind: file.kind,
        mode: file.mode,
        size: file.size,
        digest: `sha256:${file.digest}`,
      })),
    },
    evidence: {
      staticFindings: findings,
      findingCounts: countFindings(findings),
      networkDestinations,
      requestedCapabilities: requestedCapabilities(findings, networkDestinations),
      observedCapabilities: [],
      highRiskFiles,
      skipped: collected.skipped.slice(0, 250),
    },
    sbom: {
      format: 'dreamnet.cerberus-sbom.v1',
      completeness: 'declared-direct-dependencies',
      components: [...new Map(sbom.map((component) => [
        `${component.ecosystem}|${component.name}|${component.version}|${component.sourceFile}`,
        component,
      ])).values()].sort((a, b) => a.purl.localeCompare(b.purl)),
    },
    riskScores: {
      ...risk.scores,
      overall: risk.overall,
    },
    verdict: risk.verdict,
    decision: {
      inspectionPassed: allowed,
      installationAllowed: allowed,
      executionAllowed: allowed,
      humanReviewRequired: !allowed,
      permittedVerdicts: policy.allowedVerdicts,
      reasons: decisionReasons(risk.verdict, findings, intake),
    },
    scanner: {
      name: 'DreamNet Cerberus Repo Airlock',
      version: CERBERUS_VERSION,
      mode: 'static-offline',
      policy: policy.schema,
      rulesetDigest: `sha256:${sha256(stableStringify({
        generic: GENERIC_RULES.map((rule) => rule.id),
        prompt: PROMPT_INJECTION_RULES.map((rule) => rule.id),
        policy,
      }))}`,
    },
    limits: {
      configured: policy.limits,
      reached: collected.limitReached,
      limitations: [...new Set(limitations)],
    },
    attestation: {
      status: 'unsigned',
      signer: null,
      signature: null,
    },
    hashes: {
      contentSha256: digest,
      receiptSha256: null,
    },
  };

  receipt.hashes.receiptSha256 = `sha256:${sha256(stableStringify(receipt))}`;
  return receipt;
}

export function verifyReceipt(receipt) {
  const expected = receipt?.hashes?.receiptSha256;
  if (!expected || typeof expected !== 'string') {
    return { valid: false, reason: 'receipt_hash_missing' };
  }
  const copy = structuredClone(receipt);
  copy.hashes.receiptSha256 = null;
  const actual = `sha256:${sha256(stableStringify(copy))}`;
  return {
    valid: actual === expected,
    expected,
    actual,
    reason: actual === expected ? 'hash_match' : 'hash_mismatch',
  };
}

function safeSlug(value) {
  return String(value || 'artifact')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 56) || 'artifact';
}

export function renderReceiptMarkdown(receipt) {
  const rows = receipt.evidence.staticFindings
    .slice(0, 200)
    .map((finding) => {
      const location = finding.line ? `${finding.file}:${finding.line}` : finding.file;
      return `| ${finding.severity} | ${finding.ruleId} | ${location} | ${finding.message.replaceAll('|', '/')} |`;
    })
    .join('\n');

  return `# Cerberus Security Receipt

- Receipt: \`${receipt.receiptId}\`
- Artifact: \`${receipt.artifact.name}\`
- Digest: \`${receipt.artifact.digest}\`
- Verdict: **${receipt.verdict.toUpperCase()}**
- Installation allowed: **${receipt.decision.installationAllowed ? 'YES' : 'NO'}**
- Mode: \`${receipt.scanner.mode}\`
- Attestation: \`${receipt.attestation.status}\`

## Risk Scores

${Object.entries(receipt.riskScores).map(([name, score]) => `- ${name}: ${score}/100`).join('\n')}

## Findings

| Severity | Rule | Location | Finding |
| --- | --- | --- | --- |
${rows || '| low | none | none | No static findings. |'}

## Boundaries

${receipt.limits.limitations.map((limitation) => `- ${limitation}`).join('\n')}

## Integrity

- Content digest: \`${receipt.hashes.contentSha256}\`
- Receipt digest: \`${receipt.hashes.receiptSha256}\`
`;
}

export function writeReceipt(receipt, outDirectory) {
  const outDir = path.resolve(outDirectory);
  fs.mkdirSync(outDir, { recursive: true });
  const stem = `${receipt.createdAt.replace(/[:.]/g, '-')}-${safeSlug(receipt.artifact.name)}`;
  const jsonPath = path.join(outDir, `${stem}-security-receipt.json`);
  const markdownPath = path.join(outDir, `${stem}-security-receipt.md`);
  fs.writeFileSync(jsonPath, `${JSON.stringify(receipt, null, 2)}\n`, 'utf8');
  fs.writeFileSync(markdownPath, renderReceiptMarkdown(receipt), 'utf8');
  return { jsonPath, markdownPath };
}

export function summarizeReceipt(receipt) {
  return {
    receiptId: receipt.receiptId,
    artifact: receipt.artifact.name,
    digest: receipt.artifact.digest,
    verdict: receipt.verdict,
    installationAllowed: receipt.decision.installationAllowed,
    findings: receipt.evidence.findingCounts,
    overallRisk: receipt.riskScores.overall,
    limitations: receipt.limits.limitations,
  };
}
