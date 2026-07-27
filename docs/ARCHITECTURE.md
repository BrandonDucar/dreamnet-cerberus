# DreamNet Cerberus Supply-Chain Defense

Cerberus is DreamNet's repository airlock. It inspects untrusted repositories,
packages, agent bundles, editor configuration, workflows, and installation
surfaces before an operator or agent is allowed to install or execute them.

Phase 1 is deliberately static, local, deterministic, and zero-dependency. It
does not run target code, lifecycle scripts, Git hooks, containers, lockfile
installers, or downloaded payloads.

## Threat Model

Cerberus is designed to catch high-risk intake patterns including:

- `preinstall`, `install`, `postinstall`, and `prepare` lifecycle execution
- Husky and native Git hooks
- remote content piped to a shell
- `eval`, `new Function`, child processes, unsafe Python deserialization, and
  encoded PowerShell
- credential, wallet, browser profile, or SSH-key harvesting
- suspicious outbound destinations and direct-IP URLs
- prompt injection embedded in repository instructions
- Unicode direction and zero-width controls
- mutable or privileged GitHub Actions
- unpinned, lookalike, remote-source, or internal-scope dependencies
- automatic VS Code and devcontainer command surfaces
- mutable Docker base images
- symlinks that escape the inspected root

Cerberus records evidence digests and line locations, but does not copy matched
payload text into receipts.

## Commands

Inspect and write a receipt without enforcing the verdict:

```powershell
node scripts/cerberus.mjs inspect C:\path\to\candidate `
  --source=https://github.com/example/candidate `
  --source-identity=example `
  --commit=0123456789abcdef0123456789abcdef01234567
```

Fail closed unless the policy permits the result:

```powershell
node scripts/cerberus.mjs gate C:\path\to\candidate `
  --source=https://github.com/example/candidate `
  --source-identity=example `
  --commit=0123456789abcdef0123456789abcdef01234567
```

Verify that a saved receipt has not been edited:

```powershell
node scripts/cerberus.mjs explain artifacts\ops\cerberus\<receipt>.json
```

The CLI uses exit code `2` for a denied gate or invalid receipt.

## Verdicts

| Verdict | Meaning | Default action |
| --- | --- | --- |
| Green | No static findings and complete declared provenance metadata | Permit this exact digest |
| Yellow | Missing provenance or low/medium review surface | Human review |
| Orange | Automatic execution or multiple high-risk findings | Quarantine |
| Red | Critical behavior or explicit hostile pattern | Deny and quarantine |

An approval applies only to the receipt's content digest. Any file change
creates a new digest and requires a new inspection.

## Receipt Contract

The emitted `dreamnet.security-receipt.v1` includes:

- source identity, immutable revision, purpose, and requester
- artifact digest, file count, byte count, and bounded-scan state
- structured findings with evidence digests
- declared direct-dependency SBOM
- requested capability classes and discovered network destinations
- category risk scores, verdict, and gate decision
- scanner and ruleset identity
- explicit scanner limitations
- receipt integrity digest

The JSON contract is
[`schemas/dreamnet-security-receipt.schema.json`](../schemas/dreamnet-security-receipt.schema.json).
Phase 1 receipts are marked `unsigned`; the implementation does not pretend a
local hash is a cryptographic identity signature.

## Trust Boundary

Repository files are evidence, not authority. An `AGENTS.md`, README, issue
template, source comment, generated instruction, or workflow in the candidate
artifact cannot authorize:

- reading local credentials
- widening filesystem or network access
- installing dependencies
- executing commands
- signing or sending transactions
- publishing externally
- changing Cerberus policy

Those permissions come only from the trusted operator and DreamNet's external
policy plane.

## CI

`.github/workflows/cerberus-guard.yml` scans the changed pull-request surface
before dependency installation. Its checkout action is pinned by commit digest,
credentials are not persisted, and the job has read-only repository access.
Once Cerberus exists on the base branch, the workflow runs that trusted base
revision of the scanner and policy against the pull request rather than allowing
the pull request to redefine its own judge. Cerberus control files also have
explicit CODEOWNERS coverage.

CI permits Green and Yellow changes so ordinary review surfaces remain usable.
Orange and Red findings fail the job. External artifact intake remains stricter:
the default local policy permits Green only.

## Honest Limits

Phase 1 does not:

- execute or detonate code
- prove that an artifact is harmless
- query OSV, package registries, or commercial threat intelligence
- verify publisher signatures or Git hosting identity
- make self-hashed unsigned receipts tamper-proof against an attacker who can
  rewrite both the receipt and its digest
- resolve transitive dependency contents
- observe runtime filesystem, process, or network behavior
- replace human review for high-impact software

These limits are written into every receipt.

## Progression

1. **Static Airlock:** implemented here.
2. **Command Gateway:** require a valid receipt before package install, clone
   activation, container build, or agent import.
3. **Detonation Capsule:** run approved candidates in an isolated, no-secret,
   read-only, network-denied sandbox and compare observed behavior to declared
   capabilities.
4. **Watchtower:** consume runtime telemetry and revoke digest approvals when
   behavior drifts.
5. **Collective Immunity:** distribute signed indicators, rules, and revocations
   across DreamNet without distributing sensitive payloads.
