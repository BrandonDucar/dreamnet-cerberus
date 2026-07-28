# DreamNet Cerberus Architecture & Design

## System Architecture

DreamNet Cerberus is a zero-trust, static pre-execution defense layer designed to inspect untrusted repositories before any agent, container runtime, or IDE developer environment executes scripts, installs dependencies, or builds artifacts.

```mermaid
graph TD
    A[Untrusted Repository Source] -->|Read-Only Inspection| B[Cerberus Core Engine]
    B --> C[Static Analyzers]
    
    C --> C1[package.json Lifecycle Analyzer]
    C --> C2[Git Hooks Analyzer]
    C --> C3[Shell/PowerShell Analyzer]
    C --> C4[JS/TS Static AST Analyzer]
    C --> C5[GitHub Workflows Analyzer]
    C --> C6[VS Code Tasks Analyzer]
    C --> C7[Container & Makefile Analyzer]
    C --> C8[Lockfile Integrity Analyzer]

    C1 & C2 & C3 & C4 & C5 & C6 & C7 & C8 --> D[Policy Evaluator]

    D -->|Match Rules & Risk Matrix| E{Risk Level?}
    E -->|GREEN| F[APPROVED: Proceed Execution]
    E -->|YELLOW| G[REVIEW REQUIRED: Human / Quorum Approval]
    E -->|RED| H[QUARANTINED: Prohibit Execution]

    D --> I[Deterministic Receipt Generator]
    I --> J[Canonical Scan Receipt JSON]
    I --> K[Proof Drop Bundle]
    I --> L[Atomic Claims]

    L --> M[Temporal Nexus v2 Adapter]
```

## Core Architectural Principles

1. **Strict Read-Only Static Analysis**: Cerberus NEVER executes `npm install`, lifecycle scripts (`postinstall`, `prepare`), or untrusted JS/TS code during analysis.
2. **Deterministic Receipt Hashing**: Canonical JSON serialization ensures that scanning identical repository contents yields the exact same `Scan ID` and `Canonical Hash`.
3. **Multi-Vector Threat Inspection**: Inspects 9 distinct file layers to detect obfuscated commands, remote code downloads, credential theft, and unauthorized persistence mechanisms.
4. **Isolated Quarantine Vault**: Repositories classified as `RED` are automatically moved into an isolated quarantine vault (`.cerberus-quarantine`) with a signed manifest.
