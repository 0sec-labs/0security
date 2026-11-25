// Pure scoring for the agent-config detection benchmark. No I/O. See docs/design/benchmark.md.
// A planted item is found when a finding has the same rule id, the same file and the same line, exactly.
const key = (ruleId, file, line) => `${ruleId}|${String(file).replace(/\\/g, "/")}|${line}`;

/** Scores the findings for the planted folder against the manifest. */
export function scorePlanted(manifest, findings) {
  const open = new Map(manifest.planted.map((p) => [key(p.ruleId, p.file, p.line), p]));
  const found = []; const decoyHits = []; const unexpected = []; let context = 0;
  for (const f of findings) {
    const k = key(f.ruleId, f.file, f.line);
    if (open.has(k)) { found.push(open.get(k).id); open.delete(k); continue; }
    const decoy = manifest.decoys.find((d) => d.file === f.file && f.line >= d.startLine && f.line <= d.endLine && d.ruleIds.includes(f.ruleId));
    if (decoy) { decoyHits.push({ decoy: decoy.id, ruleId: f.ruleId, file: f.file, line: f.line }); continue; }
    if (manifest.context.some((c) => c.file === f.file && c.ruleId === f.ruleId)) { context++; continue; }
    unexpected.push({ ruleId: f.ruleId, file: f.file, line: f.line });
  }
  const planted = manifest.planted.length;
  const falsePositives = decoyHits.length + unexpected.length;
  return {
    planted, found: found.length, missed: [...open.values()].map((p) => p.id),
    recall: planted ? found.length / planted : null,
    precision: found.length + falsePositives ? found.length / (found.length + falsePositives) : null,
    decoyHits, unexpected, falsePositives, context,
  };
}

/** The clean twin must produce no finding at all. */
export function scoreClean(findings) {
  return { findings: findings.map((f) => ({ ruleId: f.ruleId, file: f.file, line: f.line })), falsePositives: findings.length };
}

/** Checks that the manifest names real rules and has the parts the scorer reads. Returns a list of problems. */
export function validateManifest(manifest, ruleIds) {
  const problems = [];
  const ids = new Set();
  for (const p of manifest.planted ?? []) {
    if (ids.has(p.id)) problems.push(`duplicate id ${p.id}`);
    ids.add(p.id);
    if (!ruleIds.includes(p.ruleId)) problems.push(`${p.id}: unknown rule ${p.ruleId}`);
    if (!p.file || !Number.isInteger(p.line) || p.line < 1) problems.push(`${p.id}: needs a file and a line`);
  }
  for (const d of manifest.decoys ?? []) {
    if (ids.has(d.id)) problems.push(`duplicate id ${d.id}`);
    ids.add(d.id);
    for (const r of d.ruleIds ?? []) if (!ruleIds.includes(r)) problems.push(`${d.id}: unknown rule ${r}`);
    if (!(d.startLine <= d.endLine)) problems.push(`${d.id}: bad line range`);
  }
  return problems;
}

const pct = (x) => (x === null ? "n/a" : `${(x * 100).toFixed(0)}%`);

export function renderDetection(planted, clean) {
  const lines = [
    `Planted folder: ${planted.found}/${planted.planted} found (recall ${pct(planted.recall)}), precision ${pct(planted.precision)}, ${planted.decoyHits.length} decoy hits, ${planted.unexpected.length} other unexpected findings, ${planted.context} expected context findings.`,
    `Clean folder: ${clean.falsePositives} findings.`,
  ];
  if (planted.missed.length) lines.push(`Missed: ${planted.missed.join(", ")}`);
  for (const d of planted.decoyHits) lines.push(`Decoy hit ${d.decoy}: ${d.ruleId} at ${d.file}:${d.line}`);
  for (const u of planted.unexpected) lines.push(`Unexpected: ${u.ruleId} at ${u.file}:${u.line}`);
  for (const c of clean.findings) lines.push(`Clean folder finding: ${c.ruleId} at ${c.file}:${c.line}`);
  return lines.join("\n");
}
