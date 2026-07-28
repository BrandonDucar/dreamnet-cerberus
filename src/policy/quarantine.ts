import fs from 'node:fs';
import path from 'node:path';
import { CanonicalScanReceipt, QuarantineRecord } from '../types.js';

export function quarantineRepository(
  targetPath: string,
  receipt: CanonicalScanReceipt,
  reason: string,
  quarantineVaultRoot: string = path.join(process.cwd(), '.cerberus-quarantine')
): QuarantineRecord {
  if (!fs.existsSync(quarantineVaultRoot)) {
    fs.mkdirSync(quarantineVaultRoot, { recursive: true });
  }

  const quarantineId = `QRT-${Date.now()}-${receipt.scanId.substring(4)}`;
  const isolatedDir = path.join(quarantineVaultRoot, quarantineId);
  fs.mkdirSync(isolatedDir, { recursive: true });

  const record: QuarantineRecord = {
    quarantineId,
    targetPath,
    quarantinedAt: new Date().toISOString(),
    reason,
    receiptId: receipt.scanId,
    riskLevel: receipt.riskLevel,
    isolatedLocation: isolatedDir,
  };

  // Write isolation metadata
  fs.writeFileSync(
    path.join(isolatedDir, 'quarantine-manifest.json'),
    JSON.stringify({ record, receipt }, null, 2),
    'utf-8'
  );

  return record;
}
