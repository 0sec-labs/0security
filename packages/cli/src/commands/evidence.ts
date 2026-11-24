/** `0 evidence verify <folder> --pub <key>`: check a signed evidence folder offline. Free: no license, no network. */
import { readFileSync, statSync } from "node:fs";
import type { Command } from "commander";
import { EVIDENCE_SIGNATURE_FILE, verifyEvidenceFolder, type EvidenceVerification } from "./evidence-signature.js";
import { finishWithError, UsageError } from "./output.js";

export interface EvidenceVerifyOptions { pub?: string; json?: boolean }
export interface EvidenceVerifyDeps { out(text: string): void; err(text: string): void }

const defaults: EvidenceVerifyDeps = { out: text => process.stdout.write(`${text}\n`), err: text => process.stderr.write(`${text}\n`) };

/** Exit 0 when the signature and every file match, 1 when something does not, 2 for a usage error. */
export function runEvidenceVerify(folder: string, options: EvidenceVerifyOptions, deps: EvidenceVerifyDeps = defaults): EvidenceVerification | undefined {
  try {
    if (!options.pub) throw new UsageError("--pub <file> is required: the public key (PEM) that matches the signing key.");
    let pem: string;
    try {
      if (statSync(options.pub).size > 16 * 1024) throw new Error("size");
      pem = readFileSync(options.pub, "utf8");
    } catch { throw new UsageError(`--pub '${options.pub}' cannot be read as a public key file.`); }
    if (/PRIVATE KEY/.test(pem)) throw new UsageError("--pub must be the public key. That file holds a private key: do not share it.");
    const result = verifyEvidenceFolder(folder, pem);
    if (options.json) deps.out(JSON.stringify(result, null, 2));
    else if (result.ok) {
      deps.out(`Signature valid. ${result.filesChecked} files match what was signed${result.signedAt ? ` on ${result.signedAt}` : ""}.`);
      deps.out(`Key id: ${result.keyId}`);
      if (result.commit) deps.out(`Repository commit: ${result.commit}`);
      deps.out("This shows the files are unchanged since the holder of this key signed them. It does not show the findings are right.");
    } else {
      deps.out(`Verification FAILED for '${folder}'.`);
      for (const problem of result.problems) deps.out(`- ${problem.message}`);
    }
    process.exitCode = result.ok ? 0 : 1;
    return result;
  } catch (error) {
    finishWithError(error, deps, options.json);
    return undefined;
  }
}

export function registerEvidenceCommand(program: Command, deps: EvidenceVerifyDeps = defaults): void {
  const evidence = program.command("evidence").description("Check evidence folders signed with 0security findings evidence --sign");
  evidence.command("verify <folder>")
    .description(`Check offline that ${EVIDENCE_SIGNATURE_FILE} is signed by this key and no file was changed, added or removed`)
    .option("--pub <file>", "Public key (PEM) that matches the signing key (required)")
    .option("--json", "Print the result as JSON")
    .addHelpText("after", "\nFree and offline: needs no license. Exit 0 when valid, 1 when not.")
    .action((folder: string, options: EvidenceVerifyOptions) => { runEvidenceVerify(folder, options, deps); });
}
