import fs from 'node:fs';
import { Finding, PolicyConfig, RiskLevel } from '../types.js';
import { DEFAULT_CERBERUS_POLICY } from './defaultPolicy.js';

export function loadPolicy(policyFilePath?: string | null): PolicyConfig {
  if (!policyFilePath) {
    return DEFAULT_CERBERUS_POLICY;
  }

  try {
    const raw = fs.readFileSync(policyFilePath, 'utf-8');
    return JSON.parse(raw) as PolicyConfig;
  } catch (err) {
    console.warn(`[Cerberus] Failed to load policy file ${policyFilePath}. Falling back to default policy.`);
    return DEFAULT_CERBERUS_POLICY;
  }
}

export function evaluatePolicy(findings: Finding[], policy: PolicyConfig): {
  overallRisk: RiskLevel;
  verdict: 'APPROVED_GREEN' | 'REVIEW_REQUIRED_YELLOW' | 'QUARANTINED_RED';
  violatingFindings: Finding[];
} {
  const redCount = findings.filter(f => f.riskLevel === 'RED').length;
  const yellowCount = findings.filter(f => f.riskLevel === 'YELLOW').length;

  let overallRisk: RiskLevel = 'GREEN';
  let verdict: 'APPROVED_GREEN' | 'REVIEW_REQUIRED_YELLOW' | 'QUARANTINED_RED' = 'APPROVED_GREEN';

  if (redCount > 0) {
    overallRisk = 'RED';
    verdict = 'QUARANTINED_RED';
  } else if (yellowCount > 0) {
    overallRisk = 'YELLOW';
    verdict = 'REVIEW_REQUIRED_YELLOW';
  }

  const violatingFindings = findings.filter(f => f.riskLevel === 'RED' || f.riskLevel === 'YELLOW');

  return {
    overallRisk,
    verdict,
    violatingFindings,
  };
}
