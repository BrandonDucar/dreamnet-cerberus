import { CanonicalScanReceipt, Finding, Provenance, RiskLevel } from '../types.js';
import { generateScanId } from './determinism.js';

export function buildCanonicalReceipt(
  targetPath: string,
  totalFilesScanned: number,
  findings: Finding[],
  fileHashes: Record<string, string>,
  provenance: Provenance
): CanonicalScanReceipt {
  // Sort findings deterministically by file, line, category, id
  const sortedFindings = [...findings].sort((a, b) => {
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    if ((a.line || 0) !== (b.line || 0)) return (a.line || 0) - (b.line || 0);
    return a.id.localeCompare(b.id);
  });

  // Sort fileHashes keys deterministically
  const sortedFileHashes: Record<string, string> = {};
  Object.keys(fileHashes).sort().forEach(k => {
    sortedFileHashes[k] = fileHashes[k];
  });

  // Count findings by risk level
  const findingsCount = {
    GREEN: sortedFindings.filter(f => f.riskLevel === 'GREEN').length,
    YELLOW: sortedFindings.filter(f => f.riskLevel === 'YELLOW').length,
    RED: sortedFindings.filter(f => f.riskLevel === 'RED').length,
  };

  // Determine overall risk level
  let overallRisk: RiskLevel = 'GREEN';
  if (findingsCount.RED > 0) {
    overallRisk = 'RED';
  } else if (findingsCount.YELLOW > 0) {
    overallRisk = 'YELLOW';
  }

  let policyVerdict: CanonicalScanReceipt['policyVerdict'] = 'APPROVED_GREEN';
  if (overallRisk === 'RED') {
    policyVerdict = 'QUARANTINED_RED';
  } else if (overallRisk === 'YELLOW') {
    policyVerdict = 'REVIEW_REQUIRED_YELLOW';
  }

  // Pure deterministic payload (excluding dynamic scannedAt timestamp)
  const baseReceiptData = {
    targetPath,
    totalFilesScanned,
    riskLevel: overallRisk,
    findingsCount,
    findings: sortedFindings,
    fileHashes: sortedFileHashes,
    policyVerdict,
    provenance: {
      scannerName: provenance.scannerName,
      scannerVersion: provenance.scannerVersion,
      nodeVersion: provenance.nodeVersion,
      platform: provenance.platform,
    },
  };

  const { scanId, canonicalHash } = generateScanId(baseReceiptData);

  return {
    scanId,
    canonicalHash,
    ...baseReceiptData,
    provenance,
  };
}
