# Cerberus Policy Schema & Risk Classification

## Risk Levels

| Level | Description | Action Required |
|---|---|---|
| **GREEN** | Low risk / clean file patterns. | Execution permitted under standard policy. |
| **YELLOW** | Warning / active lifecycle script or unpinned dependency. | Human or specialized Quorum review required. |
| **RED** | High risk / malware pattern / dangerous code execution. | Immediate quarantine and execution prohibited. |

## Policy JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "CerberusPolicyConfig",
  "type": "object",
  "properties": {
    "version": { "type": "string" },
    "name": { "type": "string" },
    "quarantineThreshold": { "type": "string", "enum": ["GREEN", "YELLOW", "RED"] },
    "rules": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "ruleId": { "type": "string" },
          "category": { "type": "string" },
          "pattern": { "type": "string" },
          "maxAllowedRisk": { "type": "string", "enum": ["GREEN", "YELLOW", "RED"] },
          "description": { "type": "string" }
        },
        "required": ["ruleId", "category", "pattern", "maxAllowedRisk", "description"]
      }
    }
  },
  "required": ["version", "name", "quarantineThreshold", "rules"]
}
```
