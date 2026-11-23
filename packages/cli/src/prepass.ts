/**
 * The pattern-scanner pre-pass: run each chosen scanner on the folder, without a shell and with a timeout, and turn its SARIF
 * into leads. A scanner that is missing, fails or times out is skipped with a note, except where `--rules` needs it.
 */
import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
  /** The folder the scanners run in (default: this process's). Trivy reads `.trivyignore` from there. */
  cwd?: string;
  /** When true, honors in-repo scanner config and ignore files (.gitleaks.toml, .trivyignore). Off by default. */
  repoIgnores?: boolean;
}

function tail(error: unknown): string {
  const text = String((error as { stderr?: string }).stderr || (error as Error).message || "");
  return text.replace(/[^\x20-\x7e\n]/g, "").trim().split("\n").slice(-4).join(" | ").slice(0, 500);
}

export async function runPrePass(folder: string, scanners: string[], rules: string[] = [], io: PrePassIo = {}): Promise<PrePassLeads | undefined> {
  const env = io.env ?? process.env;
  const note = io.note ?? (() => undefined);
  const repoIgnores = Boolean(io.repoIgnores);

  let scratch = "";
  let emptyConfig = "";
  let emptyIgnore = "";
  let gitleaksConfig = "";

  if (!repoIgnores) {
    scratch = mkdtempSync(join(tmpdir(), "0-prepass-isolation-"));
    emptyConfig = join(scratch, "empty");
    emptyIgnore = join(scratch, "empty");
    gitleaksConfig = join(scratch, "gitleaks.toml");
    writeFileSync(emptyConfig, "");
    writeFileSync(gitleaksConfig, 'title = "0 default gitleaks config"\n\n[extend]\nuseDefault = true\n');
  }

  // Scanners that were not found. They are reported after the run: one line when none ran, else one line each.
  const absent: Array<NonNullable<ReturnType<typeof scannerById>>> = [];
  try {
    const lists = await Promise.all(scanners.map(async id => {
      const spec = scannerById(id);
      if (!spec) return undefined;
      const binary = [spec.pathEnv ? env[spec.pathEnv] : undefined, join(homeStateDir(), "bin", spec.command), spec.command].filter((value): value is string => !!value).find(candidate => candidate === spec.command || existsSync(candidate));
      const useRules = rules.length > 0 && scannerTakesRules(spec);
      const missing = () => {
        if (useRules) throw new Error(`--rules needs ${spec.id}, which is not installed.`);
        absent.push(spec);
        return undefined;
      };
      if (!binary) return missing();
      const forced = repoIgnores ? undefined : spec.repoConfigFiles?.find(name => existsSync(join(folder, name)));
      if (forced) {
        note(`${spec.id} was skipped: it always reads ${forced} from the scanned folder and cannot be told not to. Pass --repo-ignores to run it anyway.`);
        return undefined;
      }
      const seconds = io.timeoutSeconds ?? spec.timeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS;
      // A scanner such as Checkov writes its SARIF to a file in a scratch folder, not to standard output.
      const out = spec.outputFile ? mkdtempSync(join(tmpdir(), "0-scanner-")) : "";
      const report = (): string | undefined => { if (!spec.outputFile) return undefined; try { return readFileSync(join(out, spec.outputFile), "utf8"); } catch { return undefined; } };
      try {
        let stdout: string;
        const isolationOptions = { repoIgnores, emptyConfig, emptyIgnore, gitleaksConfig };
        try { stdout = (await exec(binary, scannerArguments(spec, folder, useRules ? rules : undefined, out, isolationOptions), { env, cwd: io.cwd, timeout: seconds * 1000, maxBuffer: 128 * 1024 * 1024, windowsHide: true })).stdout; if (spec.outputFile) stdout = report() ?? stdout; }
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
    if (!ran.length && absent.length === scanners.length && absent.length > 0) {
      const hints = absent.filter(spec => spec.install).map(spec => `${spec.label}: ${spec.install}`);
      note(`No pattern scanner is installed, so the scan runs without leads.${hints.length ? ` Install one: ${hints.join("; ")}` : ""}`);
    } else for (const spec of absent) if (spec.install) note(`${spec.id} is not installed, so it was skipped. Install it: ${spec.install}`);
    if (!ran.length) return undefined;
    const leads = ran.flatMap(entry => entry.leads);
    return { tools: ran.map(entry => entry.tool), leads, total: leads.length };
  } finally {
    if (scratch) {
      try { rmSync(scratch, { recursive: true, force: true }); } catch { /* ignore cleanup error */ }
    }
  }
}
