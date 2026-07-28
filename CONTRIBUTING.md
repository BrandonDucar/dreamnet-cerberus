# Contributing to DreamNet Cerberus

We welcome contributions to expand Cerberus threat detection rules, static AST parsers, and policy evaluators!

## Guidelines
1. **Never Add Lifecycle Scripts**: Do not add `preinstall`, `postinstall`, or `prepare` scripts to `package.json`. Cerberus must remain plug-and-play and execute zero lifecycle hooks upon install.
2. **Add Adversarial & Benign Fixtures**: When adding a new threat detector, add both a malicious fixture under `fixtures/adversarial/` and a clean fixture under `fixtures/benign/` to prevent false positive regressions.
3. **Maintain Determinism**: Ensure all scan receipts, file list hashes, and findings sorting remain 100% deterministic.
