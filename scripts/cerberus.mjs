#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {
  DEFAULT_POLICY,
  inspectArtifact,
  summarizeReceipt,
  verifyReceipt,
  writeReceipt,
} from '../packages/cerberus-core/src/index.mjs';

const COMMANDS = new Set(['inspect', 'gate', 'explain']);

function fail(message, exitCode = 1) {
  console.error(`[cerberus] ${message}`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const values = { _: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) {
      values._.push(token);
      continue;
    }

    const equalsAt = token.indexOf('=');
    if (equalsAt !== -1) {
      values[token.slice(2, equalsAt)] = token.slice(equalsAt + 1);
      continue;
    }

    const name = token.slice(2);
    const next = argv[index + 1];
    if (next && !next.startsWith('--')) {
      values[name] = next;
      index += 1;
    } else {
      values[name] = true;
    }
  }
  return values;
}

function printHelp() {
  console.log(`DreamNet Cerberus Repo Airlock

Usage:
  node scripts/cerberus.mjs inspect <path> [options]
  node scripts/cerberus.mjs gate <path> [options]
  node scripts/cerberus.mjs explain <receipt.json> [--json]

Options:
  --source <url-or-origin>       Declared artifact origin
  --source-identity <identity>   Publisher, owner, or organization
  --commit <sha>                 Immutable source revision
  --purpose <text>               Why this artifact is being inspected
  --requested-by <identity>      Operator or agent requesting intake
  --policy <path>                Cerberus policy JSON
  --out-dir <path>               Receipt directory
  --allow <verdicts>             Gate allowlist, e.g. green,yellow
  --changed-base <sha>           Inspect only files changed since a Git base
  --no-write                     Do not write receipt files
  --json                         Print the summary as JSON
  --help                         Show this help

Exit codes:
  0  completed and, for gate, allowed
  1  scanner or usage failure
  2  gate denied
`);
}

function mergePolicy(base, override) {
  return {
    ...base,
    ...override,
    limits: { ...base.limits, ...(override?.limits || {}) },
    thresholds: { ...base.thresholds, ...(override?.thresholds || {}) },
  };
}

function loadPolicy(policyPath) {
  const defaultPath = path.resolve('policies/cerberus-policy.v1.json');
  const selected = policyPath ? path.resolve(policyPath) : defaultPath;
  if (!fs.existsSync(selected)) {
    if (policyPath) fail(`policy not found: ${selected}`);
    return DEFAULT_POLICY;
  }

  try {
    return mergePolicy(DEFAULT_POLICY, JSON.parse(fs.readFileSync(selected, 'utf8')));
  } catch (error) {
    fail(`unable to parse policy ${selected}: ${error.message}`);
  }
}

function changedPaths(root, baseSha) {
  if (!/^[a-f0-9]{7,64}$/i.test(baseSha || '')) {
    fail('--changed-base must be a 7-64 character hexadecimal Git revision');
  }

  const output = execFileSync(
    'git',
    ['diff', '--name-only', '--diff-filter=ACMRTUXB', baseSha, 'HEAD', '--'],
    { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );

  return output
    .split(/\r?\n/)
    .map((entry) => entry.trim())
    .filter(Boolean)
    .filter((entry) => {
      const absolute = path.resolve(root, entry);
      return absolute === root || absolute.startsWith(`${root}${path.sep}`);
    });
}

function printSummary(receipt, asJson, receiptPaths = null) {
  const summary = {
    ...summarizeReceipt(receipt),
    receiptPaths,
  };
  if (asJson) {
    console.log(JSON.stringify(summary, null, 2));
    return;
  }

  console.log(`[cerberus] ${summary.artifact}`);
  console.log(`[cerberus] verdict=${summary.verdict} risk=${summary.overallRisk}/100 install=${summary.installationAllowed ? 'allowed' : 'denied'}`);
  console.log(`[cerberus] findings critical=${summary.findings.critical || 0} high=${summary.findings.high || 0} medium=${summary.findings.medium || 0} low=${summary.findings.low || 0}`);
  console.log(`[cerberus] digest=${summary.digest}`);
  if (receiptPaths) {
    console.log(`[cerberus] json=${receiptPaths.jsonPath}`);
    console.log(`[cerberus] markdown=${receiptPaths.markdownPath}`);
  }
}

function explainReceipt(receiptPath, asJson) {
  const absolute = path.resolve(receiptPath);
  if (!fs.existsSync(absolute)) fail(`receipt not found: ${absolute}`);
  let receipt;
  try {
    receipt = JSON.parse(fs.readFileSync(absolute, 'utf8'));
  } catch (error) {
    fail(`unable to parse receipt ${absolute}: ${error.message}`);
  }

  const verification = verifyReceipt(receipt);
  if (asJson) {
    console.log(JSON.stringify({ verification, receipt: summarizeReceipt(receipt) }, null, 2));
  } else {
    console.log(`[cerberus] receipt=${receipt.receiptId || 'unknown'}`);
    console.log(`[cerberus] integrity=${verification.valid ? 'valid' : 'invalid'} reason=${verification.reason}`);
    console.log(`[cerberus] verdict=${receipt.verdict || 'unknown'} install=${receipt.decision?.installationAllowed ? 'allowed' : 'denied'}`);
  }
  if (!verification.valid) process.exit(2);
}

const args = parseArgs(process.argv.slice(2));
if (args.help || args._.length === 0) {
  printHelp();
  process.exit(args.help ? 0 : 1);
}

const [command, target = '.'] = args._;
if (!COMMANDS.has(command)) fail(`unknown command: ${command}`);
if (command === 'explain') {
  explainReceipt(target, Boolean(args.json));
  process.exit(0);
}

const root = path.resolve(target);
if (!fs.existsSync(root)) fail(`artifact not found: ${root}`);
if (!fs.statSync(root).isDirectory()) fail(`artifact path must be a directory: ${root}`);

const policy = loadPolicy(args.policy);
let includePaths;
if (args['changed-base']) {
  try {
    includePaths = changedPaths(root, String(args['changed-base']));
  } catch (error) {
    fail(`unable to enumerate changed paths: ${error.stderr?.toString().trim() || error.message}`);
  }
  if (includePaths.length === 0) {
    console.log('[cerberus] no changed files; gate has no artifact surface to inspect');
    process.exit(0);
  }
}

const receipt = inspectArtifact({
  root,
  policy,
  includePaths,
  source: args.source,
  sourceIdentity: args['source-identity'],
  commit: args.commit,
  declaredPurpose: args.purpose,
  requestedBy: args['requested-by'],
});

const receiptPaths = args['no-write']
  ? null
  : writeReceipt(receipt, args['out-dir'] || path.resolve('artifacts/ops/cerberus'));
printSummary(receipt, Boolean(args.json), receiptPaths);

if (command === 'gate') {
  const permitted = String(args.allow || policy.allowedVerdicts.join(','))
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
  if (permitted.some((verdict) => !['green', 'yellow'].includes(verdict))) {
    fail('command-line gate overrides may contain only green and yellow; Orange and Red cannot be bypassed');
  }
  if (!permitted.includes(receipt.verdict)) {
    console.error(`[cerberus] GATE DENIED: verdict ${receipt.verdict} is not in ${permitted.join(',')}`);
    process.exit(2);
  }
  console.log(`[cerberus] GATE ALLOWED: verdict ${receipt.verdict}`);
}
