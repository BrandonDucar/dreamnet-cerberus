# Security Policy

## Reporting Security Vulnerabilities
If you discover a security vulnerability or threat evasion in DreamNet Cerberus, please report it directly to:
**Email**: brandonducar@gmail.com

Please do not open public GitHub issues for undisclosed security vulnerabilities.

## Security Architecture
- Cerberus operates strictly in read-only mode during static scanning.
- Cerberus contains zero install lifecycle hooks.
- Quarantined artifacts are stored in isolated vault directories (`.cerberus-quarantine`) with permissions locked down.
