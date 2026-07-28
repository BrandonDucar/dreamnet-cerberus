# DreamNet Cerberus Threat Model

## Threat Vectors Covered

### 1. npm / pnpm Lifecycle Script Exploitation (STRIDE: Elevation of Privilege)
- **Attack Vector**: A dependency package includes a malicious `postinstall` or `preinstall` script that executes immediately when `npm install` is executed.
- **Cerberus Defense**: Analyzes `package.json` for dynamic code execution, `curl | sh` piping, encoded PowerShell payloads, or remote downloads in lifecycle hooks.

### 2. Git Hook Weaponization (STRIDE: Tampering / Executing)
- **Attack Vector**: `.husky/` or `.git/hooks/` scripts contain hidden malware execution commands that trigger when a developer runs `git commit` or `git push`.
- **Cerberus Defense**: Scans all `.husky/` and `.git/hooks/` scripts in read-only mode for shell piping, remote downloads, and obfuscation.

### 3. Remote Download & Dynamic Evaluation (STRIDE: Remote Code Execution)
- **Attack Vector**: Source code calls `fetch()` or `http.get()` to download dynamic code over HTTP/HTTPS and passes it into `eval()` or `new Function()`.
- **Cerberus Defense**: Static AST tokenizer flags remote network requests combined with dynamic function execution.

### 4. Obfuscated PowerShell & Shell Payloads (STRIDE: Information Disclosure / Exfiltration)
- **Attack Vector**: PowerShell scripts use `-EncodedCommand` with base64 strings to execute hidden background payload downloads.
- **Cerberus Defense**: Regex pattern matcher identifies base64-encoded PowerShell invocations and character-code obfuscation arrays.

### 5. IDE Workspace Auto-Execution (STRIDE: Unauthorized Access)
- **Attack Vector**: `.vscode/tasks.json` defines a task configured with `"runOn": "folderOpen"`.
- **Cerberus Defense**: Detects `folderOpen` tasks in `.vscode/` and flags as `RED`.
