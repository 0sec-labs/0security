/**
 * The pattern-scanner pre-pass: run each chosen scanner on the folder, without a shell and with a timeout, and turn its SARIF
 * into leads. A scanner that is missing, fails or times out is skipped with a note, except where `--rules` needs it.
 */
import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { homeStateDir, parseSarif, scannerArguments, scannerById, scannerTakesRules, scrubSecretLead, type PrePassLeads } from "@0/engine/shared";

const exec = promisify(execFile);
const DEFAULT_TIMEOUT_SECONDS = 120;

export interface PrePassIo {
  env?: NodeJS.ProcessEnv;
  /** Where "not installed" and "did not finish" notes go. */
  note?: (text: string) => void;
  /** Overrides every scanner's time limit (tests). */
  timeoutSeconds?: number;
}

function tail(error: unknown): string {
  const text = String((error as { stderr?: string }).stderr || (error as Error).message || "");
  return text.replace(/[^\x20-\x7e\n]/g, "").trim().split("\n").slice(-4).join(" | ").slice(0, 500);
}

export async function runPrePass(folder: string, scanners: string[], rules: string[] = [], io: PrePassIo = {}): Promise<PrePassLeads | undefined> {
  const env = io.env ?? process.env;
  const note = io.note ?? (() => undefined);
  const lists = await Promise.all(scanners.map(async id => {
    const spec = scannerById(id);
    if (!spec) return undefined;
    const binary = [spec.pathEnv ? env[spec.pathEnv] : undefined, join(homeStateDir(), "bin", spec.command), spec.command].filter((value): value is string => !!value).find(candidate => candidate === spec.command || existsSync(candidate));
    const useRules = rules.length > 0 && scannerTakesRules(spec);
    const missing = () => {
      if (useRules) throw new Error(`--rules needs ${spec.id}, which is not installed.`);
      if (spec.install) note(`${spec.id} is not installed, so it was skipped. Install it: ${spec.install}`);
      return undefined;
    };
    if (!binary) return missing();
    const seconds = io.timeoutSeconds ?? spec.timeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS;
    // A scanner such as Checkov writes its SARIF to a file in a scratch folder, not to standard output.
    const out = spec.outputFile ? mkdtempSync(join(tmpdir(), "0-scanner-")) : "";
    const report = (): string | undefined => { if (!spec.outputFile) return undefined; try { return readFileSync(join(out, spec.outputFile), "utf8"); } catch { return undefined; } };
    try {
      let stdout: string;
      try { stdout = (await exec(binary, scannerArguments(spec, folder, useRules ? rules : undefined, out), { env, timeout: seconds * 1000, maxBuffer: 128 * 1024 * 1024, windowsHide: true })).stdout; if (spec.outputFile) stdout = report() ?? stdout; }
      // A scanner that exits non-zero because it found something still wrote its report.
      catch (error) {
        const failure = error as { stdout?: string; killed?: boolean; signal?: string; code?: string };
        stdout = report() ?? failure.stdout ?? "";
        if (!stdout.trim().startsWith("{")) {
          if (failure.code === "ENOENT") return missing();
          if (failure.killed || failure.signal === "SIGTERM") {
            note(`${spec.id} did not finish within ${seconds} seconds and was skipped.`);
            if (useRules) throw new Error(`${spec.id} did not finish within ${seconds} seconds.`);
            return undefined;
          }
          if (useRules) throw new Error(`${spec.id} could not run your rules: ${tail(error)}`);
          note(`${spec.id} failed and was skipped: ${tail(error)}`);
          return undefined;
        }
      }
      const parsed = parseSarif(stdout, { tool: spec.id, roots: [folder] }).findings;
      const leads = spec.reportsSecrets ? parsed.map(scrubSecretLead) : parsed;
      return { tool: spec.id, leads: useRules ? leads.map(lead => ({ ...lead, ruleSource: "custom" as const })) : leads };
    } catch (error) {
      if (useRules) throw error;
      note(`${spec.id} output could not be read and was skipped: ${(error as Error).message}`);
      return undefined;
    } finally {
      if (out) rmSync(out, { recursive: true, force: true });
    }
  }));
  const ran = lists.filter((entry): entry is NonNullable<typeof entry> => entry !== undefined);
  if (!ran.length) return undefined;
  const leads = ran.flatMap(entry => entry.leads);
  return { tools: ran.map(entry => entry.tool), leads, total: leads.length };
}
