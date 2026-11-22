/**
 * Scanners the pre-pass can run. A scanner is a command that prints a SARIF 2.1.0 log for a folder; its hits become leads
 * for the scan thread. Nothing else is assumed, so another scanner is one entry here (or, later, one extension).
 */
export interface ScannerSpec {
  id: string;
  label: string;
  /** Executable name looked up on PATH (and, for FoxGuard, next to `0`). */
  command: string;
  /** Arguments; `{folder}` is replaced by the folder, and `--config {rules}` by one `--config <path>` per rule path. `{out}` is a scratch folder (see outputFile). Must write SARIF to standard output unless outputFile is set. */
  args: string[];
  /** For a scanner that writes SARIF to a file instead: the file name inside the `{out}` folder it is given. */
  outputFile?: string;
  /** Environment variable that names the binary explicitly. */
  pathEnv?: string;
  /** What running it touches beyond the folder, shown to the user. */
  note?: string;
  /** How to install it; shown when it is not found. */
  install?: string;
  /** Seconds it may run before it is stopped. Default 120. */
  timeoutSeconds?: number;
  /** It reports secrets. Its leads never carry a snippet or a matched value into the scan prompt. */
  reportsSecrets?: boolean;
}

export const SCANNERS: readonly ScannerSpec[] = [
  { id: "foxguard", label: "FoxGuard", command: "foxguard", args: ["--format", "sarif", "{folder}"], pathEnv: "ZERO_FOXGUARD_PATH" },
  { id: "semgrep", label: "Semgrep", command: "semgrep", args: ["scan", "--sarif", "--quiet", "--metrics", "off", "--config", "{rules}", "{folder}"], pathEnv: "ZERO_SEMGREP_PATH", install: "brew install semgrep, or see https://semgrep.dev/docs/getting-started/", note: "downloads rules for --config when it is a registry pack" },
  { id: "opengrep", label: "OpenGrep", command: "opengrep", args: ["scan", "--sarif", "--quiet", "--config", "{rules}", "{folder}"], pathEnv: "ZERO_OPENGREP_PATH", install: "brew install opengrep, or see https://github.com/opengrep/opengrep" },
  { id: "gitleaks", label: "Gitleaks", command: "gitleaks", args: ["dir", "--report-format", "sarif", "--report-path", "-", "--redact", "--no-banner", "--no-color", "--exit-code", "0", "--log-level", "error", "{folder}"], pathEnv: "ZERO_GITLEAKS_PATH", install: "brew install gitleaks, or see https://github.com/gitleaks/gitleaks#installing", reportsSecrets: true },
  { id: "trivy", label: "Trivy", command: "trivy", args: ["fs", "--scanners", "vuln,misconfig,secret", "--format", "sarif", "--quiet", "--no-progress", "--disable-telemetry", "{folder}"], pathEnv: "ZERO_TRIVY_PATH", install: "brew install trivy, or see https://trivy.dev/latest/getting-started/installation/", timeoutSeconds: 300, reportsSecrets: true, note: "downloads its vulnerability database on first run" },
  { id: "osv-scanner", label: "OSV-Scanner", command: "osv-scanner", args: ["scan", "source", "--format", "sarif", "--allow-no-lockfiles", "--verbosity", "error", "-r", "{folder}"], pathEnv: "ZERO_OSV_SCANNER_PATH", install: "brew install osv-scanner, or see https://google.github.io/osv-scanner/installation/", timeoutSeconds: 180, note: "sends package names and versions from lockfiles to osv.dev and deps.dev" },
  { id: "checkov", label: "Checkov", command: "checkov", args: ["-d", "{folder}", "-o", "sarif", "--output-file-path", "{out}", "--quiet", "--skip-download"], outputFile: "results_sarif.sarif", pathEnv: "ZERO_CHECKOV_PATH", install: "pip install checkov, or see https://www.checkov.io/", note: "reads Terraform, CloudFormation, Kubernetes, Dockerfiles, GitHub Actions and more" },
];
export const DEFAULT_SCANNERS: readonly string[] = ["foxguard"];
const DEFAULT_RULES = "p/default";

export function scannerById(id: string): ScannerSpec | undefined { return SCANNERS.find(scanner => scanner.id === id); }

/** The scanner ids in `--scanner`, validated. Throws a message naming the valid ids. */
export function parseScannerList(values: readonly string[] | undefined): string[] {
  if (!values?.length) return [...DEFAULT_SCANNERS];
  const ids = values.flatMap(value => value.split(",")).map(value => value.trim()).filter(Boolean);
  const unknown = ids.filter(id => !scannerById(id));
  if (unknown.length) throw new Error(`Unknown scanner ${unknown.map(id => `'${id}'`).join(", ")}; choose from ${SCANNERS.map(scanner => scanner.id).join(", ")}.`);
  return [...new Set(ids)];
}

/** True when the scanner takes rule files (`--rules`). FoxGuard has its own rule format and is not given them. */
export function scannerTakesRules(spec: ScannerSpec): boolean { return spec.args.includes("{rules}"); }

/** The arguments for one scanner. `rules` are the user's rule paths; with none, the default pack is used. The scanner is run without a shell. */
export function scannerArguments(spec: ScannerSpec, folder: string, rules: readonly string[] | string = DEFAULT_RULES, out = ""): string[] {
  const list = typeof rules === "string" ? [rules] : rules.length ? rules : [DEFAULT_RULES];
  return spec.args.flatMap((arg, index) => {
    if (arg === "{rules}") return [];
    if (spec.args[index + 1] === "{rules}") return list.flatMap(rule => [arg, rule]);
    return [arg === "{folder}" ? folder : arg === "{out}" ? out : arg];
  });
}

/**
 * A lead from a scanner that reports secrets, with everything that could hold a secret value removed: the snippet, and any
 * "Match:" line in the title or text. The scanners are also run with redaction on; this is the second line of defence.
 */
export function scrubSecretLead<T extends { snippet?: string; description: string; title: string; ruleId: string }>(lead: T): T {
  const { snippet: _snippet, ...rest } = lead;
  const description = lead.description.split("\n").filter(line => !/^\s*(match|secret|code|value)\s*:/i.test(line)).join("\n").trim();
  const title = /^\s*(match|secret|code|value)\s*:/i.test(lead.title) ? lead.ruleId : lead.title;
  return { ...rest, title, description: description || title } as T;
}
