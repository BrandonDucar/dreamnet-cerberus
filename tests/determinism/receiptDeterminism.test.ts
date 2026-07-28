import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { scanRepository } from '../../src/engine.js';

test('Determinism - Scanning identical target twice produces identical Scan ID and Canonical Hash', async () => {
  const targetPath = path.resolve('fixtures/adversarial/remote-eval');

  const receipt1 = await scanRepository(targetPath);
  const receipt2 = await scanRepository(targetPath);

  assert.equal(receipt1.scanId, receipt2.scanId);
  assert.equal(receipt1.canonicalHash, receipt2.canonicalHash);
  assert.deepEqual(receipt1.fileHashes, receipt2.fileHashes);
  assert.equal(receipt1.findings.length, receipt2.findings.length);
});
