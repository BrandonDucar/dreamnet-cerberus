# 🛡️ DreamNet Cerberus (@dreamnet/cerberus)
> **Supply-Chain Defense Layer & Pre-Execution Inspection Engine**

DreamNet Cerberus is a zero-trust, static pre-execution analysis engine designed to inspect unfamiliar repositories before any agent, container runtime, or IDE developer environment executes scripts, installs dependencies, opens workspace files, or commits code.

---

## ⚡ Key Features

- 🔍 **Read-Only Static Analysis**: Parses files safely without executing `npm install`, lifecycle scripts, or dynamic code.
- 🎯 **Multi-Layer Threat Inspection**: Scans `package.json` lifecycle hooks, `.husky/` Git hooks, Shell/PowerShell scripts, dangerous JS/TS APIs (`eval`, `new Function`), Dockerfiles, Makefiles, lockfiles, and `.vscode/tasks.json`.
- 📊 **Deterministic Canonical Receipts**: Generates deterministic `Scan ID` (`SCN-XXXXXXXX`) and SHA-256 canonical hash digests for proof verification.
- 🛑 **Quarantine Isolation Vault**: Automatically locks dangerous (`RED`) repositories into isolated `.cerberus-quarantine` storage with signed manifests.
- 🔗 **Nexus v2 Adapter Interface**: Stubbed interface for Temporal Nexus v2 workflow integration.
- 📦 **Plug-and-Play (Zero Lifecycle Scripts)**: `@dreamnet/cerberus` contains **NO** `postinstall` or `prepare` scripts to ensure zero-risk installation.

---

## 🚀 CLI Quick Start

```bash
# Build the TypeScript CLI
npm run build

# 1. Scan an unfamiliar repository
node dist/cli.js scan fixtures/adversarial/husky-malicious

# 2. Save scan receipt to canonical JSON file
node dist/cli.js scan fixtures/adversarial/remote-eval --out receipt.json

# 3. Explain a specific security finding
node dist/cli.js explain FND-HOOK-ABC12345

# 4. Check active security policy configuration
node dist/cli.js policy check

# 5. Quarantine a dangerous repository into isolated vault
node dist/cli.js quarantine fixtures/adversarial/postinstall-downloader
```

---

## 🔒 Safe Sandbox Workflow

1. **Intake**: Clone or receive untrusted repository target in isolated workspace.
2. **Scan**: Run `cerberus scan <target-path>` in read-only mode.
3. **Verdict Evaluation**:
   - `GREEN`: Proceed under standard developer/agent policy.
   - `YELLOW`: Require human peer review or specialized Quorum approval.
   - `RED`: Prohibit installation/execution and quarantine using `cerberus quarantine <target-path>`.
4. **Receipt Attestation**: Generate signed Proof Drop bundle and submit atomic claims to Claim Factory.

---

## 🧪 Test Suite

```bash
# Run unit, integration, determinism, and fixture tests
npm run test
```

---

## 📄 License
[MIT License](LICENSE)
