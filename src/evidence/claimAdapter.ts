import { AtomicClaim, CanonicalScanReceipt } from '../types.js';

export function receiptToAtomicClaims(receipt: CanonicalScanReceipt): AtomicClaim[] {
  const claims: AtomicClaim[] = [];
  const timestamp = new Date().toISOString();

  // Root Claim: Policy Verdict
  claims.push({
    claimId: `CLM-ROOT-${receipt.scanId.substring(4)}`,
    subject: `repository:${receipt.targetPath}`,
    predicate: 'hasPolicyVerdict',
    object: receipt.policyVerdict,
    evidenceRef: receipt.scanId,
    riskLevel: receipt.riskLevel,
    timestamp,
  });

  // Individual Finding Claims
  receipt.findings.forEach((finding, idx) => {
    claims.push({
      claimId: `CLM-${receipt.scanId.substring(4)}-${idx + 1}`,
      subject: `file:${finding.file}`,
      predicate: `exhibitsFindingCategory:${finding.category}`,
      object: `risk:${finding.riskLevel}`,
      evidenceRef: `${receipt.scanId}:${finding.id}`,
      riskLevel: finding.riskLevel,
      timestamp,
    });
  });

  return claims;
}
