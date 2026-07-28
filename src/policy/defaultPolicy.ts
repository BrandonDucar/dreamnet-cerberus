import { PolicyConfig } from '../types.js';

export const DEFAULT_CERBERUS_POLICY: PolicyConfig = {
  version: '1.0.0',
  name: 'DreamNet Airflow Supply-Chain Zero-Trust Policy',
  quarantineThreshold: 'RED',
  rules: [
    {
      ruleId: 'POL-001',
      category: 'LIFECYCLE_SCRIPT',
      pattern: '.*download.*|.*curl.*|.*eval.*',
      maxAllowedRisk: 'YELLOW',
      description: 'Prohibit dynamic code download or evaluation in npm package lifecycle scripts.'
    },
    {
      ruleId: 'POL-002',
      category: 'DANGEROUS_API',
      pattern: 'eval|new Function',
      maxAllowedRisk: 'YELLOW',
      description: 'Prohibit dynamic JS/TS code evaluation in source files.'
    },
    {
      ruleId: 'POL-003',
      category: 'DOWNLOAD_AND_EXECUTE',
      pattern: 'curl.*sh|wget.*bash|Invoke-WebRequest.*iex',
      maxAllowedRisk: 'GREEN',
      description: 'Prohibit unverified remote URL execution.'
    },
    {
      ruleId: 'POL-004',
      category: 'GIT_HOOK',
      pattern: '.*',
      maxAllowedRisk: 'YELLOW',
      description: 'Require review for active Git hook scripts.'
    },
    {
      ruleId: 'POL-005',
      category: 'OBFUSCATION',
      pattern: 'powershell.*-enc|String.fromCharCode',
      maxAllowedRisk: 'GREEN',
      description: 'Prohibit obfuscated payloads.'
    }
  ]
};
