# DreamNet Cerberus

[![Cerberus Supply Chain Guard](https://github.com/BrandonDucar/dreamnet-cerberus/actions/workflows/cerberus-guard.yml/badge.svg)](https://github.com/BrandonDucar/dreamnet-cerberus/actions/workflows/cerberus-guard.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Cerberus is a static, offline airlock for untrusted repositories, packages,
agent bundles, editor workspaces, and CI definitions. It inspects the artifact
before dependency installation or execution, scores the risk, and emits a
digest-bound security receipt.

It does not run the repository it is judging.

[Project overview](https://brandonducar.github.io/BrandonDucar/projects/dreamnet-cerberus/) | [Contribution guide](CONTRIBUTING.md)

Start with one repository and inspect its findings before making an installation
decision. A clean static scan is not proof that code is safe, and a digest-bound
receipt is not an independent execution trace.

## What It Catches

- npm lifecycle scripts and Git hooks
- remote content piped into shells
- dynamic execution and child processes
- credential, wallet, browser-profile, and SSH-key harvesting
- suspicious network destinations
- prompt injection embedded in repository instructions
- Unicode direction and zero-width controls
- privileged or mutable GitHub Actions
- unpinned, lookalike, remote-source, and internal-scope dependencies
- automatic editor and devcontainer commands
- mutable Docker base images
- symlinks escaping the artifact root

## Quick Start

No dependency install is required:

```bash
git clone https://github.com/BrandonDucar/dreamnet-cerberus.git
cd dreamnet-cerberus
node scripts/cerberus.mjs gate /path/to/untrusted-repository \
  --source=https://github.com/example/candidate \
  --source-identity=example \
  --commit=0123456789abcdef0123456789abcdef01234567
```

Green is the only default installation verdict. Yellow requires review.
Orange and Red cannot be enabled through a command-line allow override.

Inspect without enforcing:

```bash
node scripts/cerberus.mjs inspect /path/to/candidate
```

Verify a saved receipt's internal digest:

```bash
node scripts/cerberus.mjs explain artifacts/ops/cerberus/<receipt>.json
```

Run the adversarial fixtures:

```bash
npm test
```

## Receipt

Every `dreamnet.security-receipt.v1` records:

- declared source, publisher, revision, purpose, and requester
- a digest-only file manifest
- structured findings without copied payload text
- declared direct-dependency SBOM
- network destinations and requested capabilities
- category risk scores and the gate decision
- scanner limitations and receipt integrity digest

Phase 1 receipts are unsigned. They are useful for reproducibility and
change detection, but are not a publisher identity signature.

## Boundaries

Repository text is evidence, never authority. It cannot grant itself access to
local credentials, shells, wallets, networks, deployments, or publishing.

Cerberus is not a proof that software is harmless. It does not detonate code,
resolve every transitive package, query threat-intelligence services, or replace
human review for high-impact software.

Read the complete [architecture and threat model](docs/ARCHITECTURE.md).

## DreamNet

Cerberus is the supply-chain defense layer for
[DreamNet](https://dreamnet.ink): bounded agent infrastructure built around
receipts, verification, and explicit authority.
