# Security Policy

## Reporting

Do not publish a working exploit or credential material in a public issue.
Use GitHub's private vulnerability reporting for this repository.

Include:

- affected revision
- rule or trust boundary involved
- minimal reproduction
- expected and observed verdict
- whether code execution occurred
- suggested containment, if known

## Scope

Security issues include:

- scanner bypasses that turn a hostile artifact Green
- path escapes or symlink traversal
- target-code execution during static inspection
- receipt or digest confusion
- CI self-judging or policy substitution
- accidental disclosure of matched payloads or secrets

False positives and new detection ideas can use normal GitHub issues when they
do not include sensitive payloads.

## Current Boundary

Version `0.1.x` is static analysis. Receipts are digest-bound but unsigned.
Do not treat a Green result as a proof that an artifact is harmless.
