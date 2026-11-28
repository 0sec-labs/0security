/**
 * A static check of a SARIF log against what two kinds of consumer need, with no network and no schema download.
 * It stands in for importing the file into a viewer. It is written from the SARIF 2.1.0 spec and from GitHub code
 * scanning's documented upload limits; it does not replace the official JSON schema or a real import.
 *
 * errors: the log breaks the SARIF 2.1.0 spec in a way any consumer may reject.
 * warnings: the log is valid but a consumer may drop, move or fail to show a result (code scanning needs a location in
 * the repository, a viewer needs a line to highlight).
 */
export interface SarifConsumerReport {
  errors: string[];
  warnings: string[];
  results: number;
  rules: number;
}

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
const LEVELS = new Set(["none", "note", "warning", "error"]);
const KINDS = new Set(["notApplicable", "pass", "fail", "review", "open", "informational"]);
const SUPPRESSION_KINDS = new Set(["inSource", "external"]);
const SUPPRESSION_STATUS = new Set(["accepted", "underReview", "rejected"]);

/** GitHub code scanning upload limits, per run. */
export const CODE_SCANNING_LIMITS = { results: 25_000, rules: 25_000, locationsPerResult: 1_000 } as const;

const validUriReference = (uri: string): boolean => uri.length > 0 && !/[\s\\<>"{}|^`\u0000-\u001f\u007f]/.test(uri);
/** A path inside the repository: not a URL with a scheme, not rooted and not climbing out. */
const repoRelative = (uri: string): boolean => !/^[A-Za-z][A-Za-z0-9+.-]*:/.test(uri) && !uri.startsWith("/") && !uri.split("/").includes("..");

function checkRegion(region: unknown, at: string, errors: string[]): void {
  if (!isObject(region)) { errors.push(`${at}: region must be an object`); return; }
  const int = (k: string): number | undefined => (region[k] === undefined ? undefined : Number.isInteger(region[k]) && (region[k] as number) >= 1 ? (region[k] as number) : (errors.push(`${at}: ${k} must be an integer of at least 1`), undefined));
  const start = int("startLine"), end = int("endLine");
  int("startColumn"); int("endColumn");
  if (start === undefined && region["startLine"] === undefined && region["byteOffset"] === undefined && region["charOffset"] === undefined && !region["snippet"]) errors.push(`${at}: region has no startLine`);
  if (start !== undefined && end !== undefined && end < start) errors.push(`${at}: endLine ${end} is before startLine ${start}`);
}

function checkLocation(loc: unknown, at: string, errors: string[], warnings: string[]): void {
  if (!isObject(loc)) { errors.push(`${at}: location must be an object`); return; }
  const physical = loc["physicalLocation"];
  if (physical === undefined) return;
  if (!isObject(physical)) { errors.push(`${at}.physicalLocation must be an object`); return; }
  const artifact = physical["artifactLocation"];
  if (!isObject(artifact) || typeof artifact["uri"] !== "string") { errors.push(`${at}: physicalLocation needs artifactLocation.uri`); }
  else {
    const uri = artifact["uri"];
    if (!validUriReference(uri)) errors.push(`${at}: uri "${uri}" is not a valid URI reference`);
    else if (!repoRelative(uri)) warnings.push(`${at}: uri "${uri}" is not relative to the repository; code scanning and viewers resolve paths from the checkout root`);
  }
  if (physical["region"] === undefined) warnings.push(`${at}: no region, so a viewer has no line to show`);
  else checkRegion(physical["region"], `${at}.region`, errors);
}

export function checkSarifForConsumers(log: unknown): SarifConsumerReport {
  const errors: string[] = [], warnings: string[] = [];
  let results = 0, rules = 0;
  if (!isObject(log)) return { errors: ["the log is not a JSON object"], warnings, results, rules };
  if (log["version"] !== "2.1.0") errors.push(`version must be "2.1.0", got ${JSON.stringify(log["version"])}`);
  const runs = log["runs"];
  if (!Array.isArray(runs) || runs.length === 0) { errors.push("runs must be a non-empty array"); return { errors, warnings, results, rules }; }
  runs.forEach((run, ri) => {
    const at = `runs[${ri}]`;
    if (!isObject(run)) { errors.push(`${at} must be an object`); return; }
    const driver = isObject(run["tool"]) ? run["tool"]["driver"] : undefined;
    if (!isObject(driver) || typeof driver["name"] !== "string" || !driver["name"]) errors.push(`${at}.tool.driver.name is required`);
    const ruleList = isObject(driver) && Array.isArray(driver["rules"]) ? driver["rules"] : [];
    const ruleIds: string[] = [];
    const ruleIdSet = new Set<string>(); // set lookups keep a log with many rules and results linear
    ruleList.forEach((rule, i) => {
      if (!isObject(rule) || typeof rule["id"] !== "string" || !rule["id"]) { errors.push(`${at}.tool.driver.rules[${i}].id is required`); return; }
      if (ruleIdSet.has(rule["id"])) errors.push(`${at}: rule id ${rule["id"]} appears twice`);
      ruleIds.push(rule["id"]);
      ruleIdSet.add(rule["id"]);
    });
    rules += ruleList.length;
    if (ruleList.length > CODE_SCANNING_LIMITS.rules) warnings.push(`${at}: ${ruleList.length} rules; code scanning accepts ${CODE_SCANNING_LIMITS.rules} per run`);
    const list = run["results"];
    if (list === undefined) return;
    if (!Array.isArray(list)) { errors.push(`${at}.results must be an array`); return; }
    results += list.length;
    if (list.length > CODE_SCANNING_LIMITS.results) warnings.push(`${at}: ${list.length} results; code scanning accepts ${CODE_SCANNING_LIMITS.results} per run`);
    list.forEach((result, i) => {
      const rat = `${at}.results[${i}]`;
      if (!isObject(result)) { errors.push(`${rat} must be an object`); return; }
      const message = result["message"];
      if (!isObject(message) || (typeof message["text"] !== "string" && typeof message["id"] !== "string") || message["text"] === "") errors.push(`${rat}: message.text is required`);
      const ruleId = result["ruleId"];
      if (ruleId !== undefined && typeof ruleId !== "string") errors.push(`${rat}: ruleId must be a string`);
      else if (typeof ruleId === "string" && ruleList.length && !ruleIdSet.has(ruleId)) errors.push(`${rat}: ruleId ${ruleId} is not in tool.driver.rules`);
      if (result["ruleIndex"] !== undefined) {
        const idx = result["ruleIndex"];
        if (!Number.isInteger(idx) || (idx as number) < 0 || (idx as number) >= ruleList.length) errors.push(`${rat}: ruleIndex is out of range`);
        else if (typeof ruleId === "string" && ruleIds[idx as number] !== ruleId) errors.push(`${rat}: ruleIndex points at ${ruleIds[idx as number]}, not ${ruleId}`);
      }
      if (result["level"] !== undefined && !LEVELS.has(String(result["level"]))) errors.push(`${rat}: level ${JSON.stringify(result["level"])} is not none, note, warning or error`);
      if (result["kind"] !== undefined && !KINDS.has(String(result["kind"]))) errors.push(`${rat}: kind ${JSON.stringify(result["kind"])} is not a SARIF result kind`);
      const fingerprints = result["partialFingerprints"];
      if (fingerprints !== undefined) {
        if (!isObject(fingerprints) || Object.values(fingerprints).some((v) => typeof v !== "string")) errors.push(`${rat}: partialFingerprints must map names to strings`);
      }
      const locations = result["locations"];
      if (locations !== undefined && !Array.isArray(locations)) errors.push(`${rat}.locations must be an array`);
      const locs = Array.isArray(locations) ? locations : [];
      if (locs.length === 0) warnings.push(`${rat}: no location; code scanning needs at least one and a viewer has nothing to open`);
      if (locs.length > CODE_SCANNING_LIMITS.locationsPerResult) warnings.push(`${rat}: ${locs.length} locations; code scanning accepts ${CODE_SCANNING_LIMITS.locationsPerResult}`);
      locs.forEach((loc, li) => checkLocation(loc, `${rat}.locations[${li}]`, errors, warnings));
      for (const [fi, fix] of (Array.isArray(result["fixes"]) ? result["fixes"] : []).entries()) {
        const changes = isObject(fix) ? fix["artifactChanges"] : undefined;
        if (!Array.isArray(changes) || changes.length === 0) { errors.push(`${rat}.fixes[${fi}]: artifactChanges is required`); continue; }
        changes.forEach((change, ci) => {
          const reps = isObject(change) ? change["replacements"] : undefined;
          if (!isObject(change) || !isObject(change["artifactLocation"]) || typeof change["artifactLocation"]["uri"] !== "string") errors.push(`${rat}.fixes[${fi}].artifactChanges[${ci}]: artifactLocation.uri is required`);
          if (!Array.isArray(reps) || reps.length === 0) errors.push(`${rat}.fixes[${fi}].artifactChanges[${ci}]: replacements is required`);
          else reps.forEach((rep, k) => { if (!isObject(rep) || !isObject(rep["deletedRegion"])) errors.push(`${rat}.fixes[${fi}].artifactChanges[${ci}].replacements[${k}]: deletedRegion is required`); else checkRegion(rep["deletedRegion"], `${rat}.fixes[${fi}].replacements[${k}].deletedRegion`, errors); });
        });
      }
      for (const [fi, flow] of (Array.isArray(result["codeFlows"]) ? result["codeFlows"] : []).entries()) {
        const threads = isObject(flow) ? flow["threadFlows"] : undefined;
        if (!Array.isArray(threads) || threads.length === 0) errors.push(`${rat}.codeFlows[${fi}]: threadFlows is required`);
        else threads.forEach((t, ti) => { if (!isObject(t) || !Array.isArray(t["locations"]) || t["locations"].length === 0) errors.push(`${rat}.codeFlows[${fi}].threadFlows[${ti}]: locations is required`); });
      }
      for (const [si, s] of (Array.isArray(result["suppressions"]) ? result["suppressions"] : []).entries()) {
        if (!isObject(s) || !SUPPRESSION_KINDS.has(String(s["kind"]))) errors.push(`${rat}.suppressions[${si}]: kind must be inSource or external`);
        else if (s["status"] !== undefined && !SUPPRESSION_STATUS.has(String(s["status"]))) errors.push(`${rat}.suppressions[${si}]: status is not accepted, underReview or rejected`);
      }
    });
    for (const [ii, inv] of (Array.isArray(run["invocations"]) ? run["invocations"] : []).entries()) {
      if (!isObject(inv) || typeof inv["executionSuccessful"] !== "boolean") errors.push(`${at}.invocations[${ii}].executionSuccessful must be a boolean`);
    }
  });
  return { errors, warnings, results, rules };
}
