import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { scanRepository } from '../../src/engine.js';
import { DEFAULT_CERBERUS_POLICY } from '../../src/policy/defaultPolicy.js';
import { evaluatePolicy } from '../../src/policy/evaluator.js';

test('Integration - Adversarial Fixtures are strictly classified RED', async () => {
  const adversarialTargets = [
    'fixtures/adversarial/husky-malicious',
    'fixtures/adversarial/remote-eval',
    'fixtures/adversarial/postinstall-downloader',
    'fixtures/adversarial/obfuscated-powershell'
  ];

  for (const relTarget of adversarialTargets) {
    const absTarget = path.resolve(relTarget);
    const receipt = await scanRepository(absTarget);
    const evalResult = evaluatePolicy(receipt.findings, DEFAULT_CERBERUS_POLICY);

    assert.equal(receipt.riskLevel, 'RED', `Expected ${relTarget} to be classified RED, got ${receipt.riskLevel}`);
    assert.equal(evalResult.verdict, 'QUARANTINED_RED');
    assert.ok(receipt.findings.some(f => f.riskLevel === 'RED'));
  }
});

test('Integration - Benign Fixtures avoid false RED classifications', async () => {
  const benignTargets = [
    'fixtures/benign/standard-react-app',
    'fixtures/benign/clean-cli-tool'
  ];

  for (const relTarget of benignTargets) {
    const absTarget = path.resolve(relTarget);
    const receipt = await scanRepository(absTarget);

    assert.notEqual(receipt.riskLevel, 'RED', `Expected ${relTarget} to avoid RED risk level, got ${receipt.riskLevel}`);
    assert.equal(receipt.findingsCount.RED, 0);
  }
});
