import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { analyzePackageJson } from '../../src/analyzers/packageJson.js';
import { analyzeGitHooks } from '../../src/analyzers/gitHooks.js';
import { analyzeScripts } from '../../src/analyzers/scripts.js';
import { analyzeJavaScriptTypeScript } from '../../src/analyzers/jsTs.js';

test('analyzePackageJson - detects suspicious postinstall downloader', () => {
  const fixturePath = path.resolve('fixtures/adversarial/postinstall-downloader/package.json');
  const rootDir = path.resolve('fixtures/adversarial/postinstall-downloader');
  const findings = analyzePackageJson(fixturePath, rootDir);

  assert.ok(findings.length > 0);
  assert.equal(findings[0].riskLevel, 'RED');
  assert.equal(findings[0].category, 'LIFECYCLE_SCRIPT');
});

test('analyzeGitHooks - detects malicious remote execution in pre-commit hook', () => {
  const fixturePath = path.resolve('fixtures/adversarial/husky-malicious/.husky/pre-commit');
  const rootDir = path.resolve('fixtures/adversarial/husky-malicious');
  const findings = analyzeGitHooks(fixturePath, rootDir);

  assert.ok(findings.length > 0);
  assert.equal(findings[0].riskLevel, 'RED');
  assert.equal(findings[0].category, 'GIT_HOOK');
});

test('analyzeScripts - detects encoded PowerShell command payload', () => {
  const fixturePath = path.resolve('fixtures/adversarial/obfuscated-powershell/setup.ps1');
  const rootDir = path.resolve('fixtures/adversarial/obfuscated-powershell');
  const findings = analyzeScripts(fixturePath, rootDir);

  assert.ok(findings.length > 0);
  assert.equal(findings[0].riskLevel, 'RED');
  assert.equal(findings[0].category, 'OBFUSCATION');
});

test('analyzeJavaScriptTypeScript - detects remote fetch + new Function evaluation', () => {
  const fixturePath = path.resolve('fixtures/adversarial/remote-eval/index.ts');
  const rootDir = path.resolve('fixtures/adversarial/remote-eval');
  const findings = analyzeJavaScriptTypeScript(fixturePath, rootDir);

  assert.ok(findings.length > 0);
  assert.ok(findings.some(f => f.riskLevel === 'RED'));
});
