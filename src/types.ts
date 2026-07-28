export type RiskLevel = 'GREEN' | 'YELLOW' | 'RED';

export type FindingCategory =
  | 'LIFECYCLE_SCRIPT'
  | 'DANGEROUS_API'
  | 'DOWNLOAD_AND_EXECUTE'
  | 'GIT_HOOK'
  | 'OBFUSCATION'
  | 'CREDENTIAL_ACCESS'
  | 'PERSISTENCE'
  | 'UNKNOWN_OUTBOUND_DOMAIN'
  | 'CONTAINER_SECURITY'
  | 'WORKFLOW_SECURITY'
  | 'MAKEFILE_SECURITY'
  | 'VSCODE_TASK';

export interface Finding {
  id: string; // FND-XXXXXX
  file: string; // Relative path
  line: number | null;
  column: number | null;
  category: FindingCategory;
  riskLevel: RiskLevel;
  title: string;
  description: string;
  snippet: string | null;
  explanation: string;
  remediation: string;
}

export interface FileEntry {
  path: string;
  sha256: string;
  sizeBytes: number;
}

export interface PolicyRule {
  ruleId: string;
  category: FindingCategory;
  pattern: string;
  maxAllowedRisk: RiskLevel;
  description: string;
}

export interface PolicyConfig {
  version: string;
  name: string;
  rules: PolicyRule[];
  quarantineThreshold: RiskLevel;
}

export interface ScanOptions {
  targetPath: string;
  policyFile?: string | null;
  format?: 'json' | 'human';
  outputFile?: string | null;
}

export interface Provenance {
  scannerName: string;
  scannerVersion: string;
  nodeVersion: string;
  platform: string;
  scannedAt: string;
}

export interface CanonicalScanReceipt {
  scanId: string;
  canonicalHash: string;
  targetPath: string;
  totalFilesScanned: number;
  riskLevel: RiskLevel;
  findingsCount: {
    GREEN: number;
    YELLOW: number;
    RED: number;
  };
  findings: Finding[];
  fileHashes: Record<string, string>; // Sorted path -> sha256
  policyVerdict: 'APPROVED_GREEN' | 'REVIEW_REQUIRED_YELLOW' | 'QUARANTINED_RED';
  provenance: Provenance;
}

export interface ProofDropBundle {
  bundleId: string;
  scanId: string;
  summary: string;
  riskLevel: RiskLevel;
  proofHashes: string[];
  quarantined: boolean;
  generatedAt: string;
}

export interface AtomicClaim {
  claimId: string;
  subject: string;
  predicate: string;
  object: string;
  evidenceRef: string;
  riskLevel: RiskLevel;
  timestamp: string;
}

export interface QuarantineRecord {
  quarantineId: string;
  targetPath: string;
  quarantinedAt: string;
  reason: string;
  receiptId: string;
  riskLevel: RiskLevel;
  isolatedLocation: string;
}
