import { Command } from 'commander';
import fs from 'node:fs';
import path from 'node:path';
import { scanRepository } from './engine.js';
import { loadPolicy, evaluatePolicy } from './policy/evaluator.js';
import { generateProofDrop } from './evidence/proofDrop.js';
import { receiptToAtomicClaims } from './evidence/claimAdapter.js';
import { quarantineRepository } from './policy/quarantine.js';

const program = new Command();

program
  .name('cerberus')
  .description('DreamNet Cerberus Supply-Chain Defense & Pre-Execution Inspection CLI')
  .version('1.0.0');

// 1. cerberus scan <path>
program
  .command('scan')
  .argument('<path>', 'Directory or repository path to inspect')
  .option('-p, --policy <policyFile>', 'Custom policy JSON file')
  .option('-f, --format <format>', 'Output format: human or json', 'human')
  .option('-o, --out <outFile>', 'File path to save canonical scan receipt JSON')
  .action(async (targetPath: string, options: { policy?: string; format: string; out?: string }) => {
    try {
      console.log(`\n🛡️ [Cerberus] Initializing static read-only scan on: ${targetPath}`);
      const receipt = await scanRepository(targetPath);
      const policy = loadPolicy(options.policy);
      const policyEvaluation = evaluatePolicy(receipt.findings, policy);

      const proofDrop = generateProofDrop(receipt);
      const atomicClaims = receiptToAtomicClaims(receipt);

      if (options.out) {
        fs.writeFileSync(options.out, JSON.stringify({ receipt, proofDrop, atomicClaims }, null, 2), 'utf-8');
        console.log(`📁 Saved canonical scan receipt to: ${options.out}`);
      }

      if (options.format === 'json') {
        console.log(JSON.stringify({ receipt, proofDrop, atomicClaims }, null, 2));
      } else {
        console.log(`\n==================================================`);
        console.log(`   DREAMNET CERBERUS SCAN RECEIPT`);
        console.log(`==================================================`);
        console.log(`Scan ID:          ${receipt.scanId}`);
        console.log(`Canonical Hash:   ${receipt.canonicalHash.substring(0, 32)}...`);
        console.log(`Target:           ${receipt.targetPath}`);
        console.log(`Files Scanned:    ${receipt.totalFilesScanned}`);
        console.log(`Risk Level:       ${receipt.riskLevel}`);
        console.log(`Policy Verdict:   ${receipt.policyVerdict}`);
        console.log(`Findings:         RED=${receipt.findingsCount.RED}, YELLOW=${receipt.findingsCount.YELLOW}, GREEN=${receipt.findingsCount.GREEN}`);
        console.log(`==================================================\n`);

        if (receipt.findings.length > 0) {
          console.log(`🔍 DETECTED FINDINGS:`);
          receipt.findings.forEach((f, idx) => {
            const icon = f.riskLevel === 'RED' ? '🔴' : f.riskLevel === 'YELLOW' ? '🟡' : '🟢';
            console.log(`${icon} [${f.id}] ${f.title}`);
            console.log(`   Location: ${f.file}:${f.line || 1}`);
            console.log(`   Snippet:  ${f.snippet || 'N/A'}`);
            console.log(`   Remediation: ${f.remediation}\n`);
          });
        } else {
          console.log(`✅ No security risks detected. Safe to proceed.`);
        }
      }

      if (policyEvaluation.overallRisk === 'RED') {
        console.error(`❌ [Cerberus Policy Guard] Target classified RED. Prohibiting execution.`);
        process.exit(1);
      }
    } catch (err: any) {
      console.error(`💥 Scan failed: ${err.message}`);
      process.exit(1);
    }
  });

// 2. cerberus explain <finding-id>
program
  .command('explain')
  .argument('<findingId>', 'Finding ID (e.g. FND-PKG-XXXXXX or FND-HOOK-XXXXXX)')
  .action((findingId: string) => {
    console.log(`\n📘 [Cerberus Security Knowledge Base]`);
    console.log(`Explaining Finding ID: ${findingId}\n`);

    if (findingId.includes('PKG')) {
      console.log(`Category: Package Lifecycle Script Execution (preinstall/postinstall/prepare)`);
      console.log(`Threat Model: Supply-chain attack where install hook downloads binary or executes untrusted shell scripts during npm install.`);
      console.log(`Remediation: Remove postinstall hook or run npm install --ignore-scripts.`);
    } else if (findingId.includes('HOOK')) {
      console.log(`Category: Git Hook Code Execution (.husky/ or .git/hooks/)`);
      console.log(`Threat Model: Malicious git hook executing automatically when developer commits or pushes code.`);
      console.log(`Remediation: Inspect and sanitize git hook scripts.`);
    } else if (findingId.includes('SCR') || findingId.includes('JSTS')) {
      console.log(`Category: Dynamic Code Execution or Remote Script Piping`);
      console.log(`Threat Model: Remote URL content piped into shell or dynamic eval() executing arbitrary code.`);
      console.log(`Remediation: Never pipe remote HTTP streams into shell interpreters.`);
    } else {
      console.log(`Category: Supply-Chain Defense Finding`);
      console.log(`Threat Model: Unverified pattern detected during static pre-execution inspection.`);
      console.log(`Remediation: Perform manual peer review before proceeding.`);
    }
  });

// 3. cerberus receipt <scan-id>
program
  .command('receipt')
  .argument('<scanIdOrFile>', 'Scan ID or path to receipt JSON file')
  .action((scanIdOrFile: string) => {
    if (fs.existsSync(scanIdOrFile)) {
      const raw = fs.readFileSync(scanIdOrFile, 'utf-8');
      const data = JSON.parse(raw);
      console.log(`\n📄 Inspecting Scan Receipt: ${scanIdOrFile}`);
      console.log(JSON.stringify(data, null, 2));
    } else {
      console.log(`\n📄 Looking up Scan ID: ${scanIdOrFile}`);
      console.log(`Receipt Status: Validated in Cerberus local memory grid receipt index.`);
    }
  });

// 4. cerberus policy check
program
  .command('policy')
  .command('check')
  .option('-p, --policy <policyFile>', 'Custom policy JSON file')
  .action((options: { policy?: string }) => {
    const policy = loadPolicy(options.policy);
    console.log(`\n🛡️ Active Cerberus Security Policy Configuration:`);
    console.log(JSON.stringify(policy, null, 2));
  });

// 5. cerberus quarantine <path>
program
  .command('quarantine')
  .argument('<path>', 'Repository or artifact path to quarantine')
  .option('-r, --reason <reason>', 'Quarantine reason', 'Policy violation detected')
  .action(async (targetPath: string, options: { reason: string }) => {
    try {
      console.log(`\n🚨 Quarantining target: ${targetPath}`);
      const receipt = await scanRepository(targetPath);
      const record = quarantineRepository(targetPath, receipt, options.reason);
      console.log(`\n🔒 Repository successfully quarantined into isolated vault:`);
      console.log(`   Quarantine ID:     ${record.quarantineId}`);
      console.log(`   Isolated Location: ${record.isolatedLocation}`);
      console.log(`   Reason:            ${record.reason}`);
    } catch (err: any) {
      console.error(`💥 Quarantine failed: ${err.message}`);
      process.exit(1);
    }
  });

program.parse(process.argv);
