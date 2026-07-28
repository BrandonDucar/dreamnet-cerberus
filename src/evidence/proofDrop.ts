import { CanonicalScanReceipt, ProofDropBundle } from '../types.js';
import { sha256 } from './determinism.js';

export function generateProofDrop(receipt: CanonicalScanReceipt): ProofDropBundle {
  const bundleId = `DROP-${receipt.scanId.substring(4)}`;
  const proofHashes = [
    receipt.canonicalHash,
    ...receipt.findings.map(f => sha256(`${f.id}:${f.file}:${f.line}:${f.category}`))
  ];

  const summary = `Cerberus Static Defense Scan on ${receipt.targetPath}: ` +
    `Risk=${receipt.riskLevel}, Files=${receipt.totalFilesScanned}, ` +
    `RED=${receipt.findingsCount.RED}, YELLOW=${receipt.findingsCount.YELLOW}, GREEN=${receipt.findingsCount.GREEN}. ` +
    `Verdict=${receipt.policyVerdict}.`;

  return {
    bundleId,
    scanId: receipt.scanId,
    summary,
    riskLevel: receipt.riskLevel,
    proofHashes,
    quarantined: receipt.riskLevel === 'RED',
    generatedAt: new Date().toISOString(),
  };
}
