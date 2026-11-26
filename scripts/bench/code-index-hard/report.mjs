#!/usr/bin/env node
// Turns raw result files of scripts/bench/code-index/run.mjs into the tables of docs/design/hard-benchmark.md.
//   node scripts/bench/code-index-hard/report.mjs <results.json>... [--out file.md]
// Re-scores nothing: it reads the scores the harness stored. Per fixture and arm: found per run, false positives per run,
// mean (min-max) of turns, tokens and seconds; per planted bug: runs that found it; bugs that only some arms found.
import { readFileSync, writeFileSync } from "node:fs";
import { mean, spread } from "../match.mjs";
import { range } from "../lib.mjs";

export function load(files) {
  const runs = [];
  for (const f of files) runs.push(...JSON.parse(readFileSync(f, "utf8")).runs);
  return runs;
}

const fmt = (xs, f = (x) => x.toFixed(1)) => (xs.length ? `${f(mean(xs))} (${range(spread(xs), f)})` : "n/a");
const k = (n) => `${Math.round(n / 1000)}k`;

/** Group by fixture then arm, keeping only runs that produced a report. Failed runs are counted, not scored. */
export function group(runs) {
  const out = new Map();
  for (const r of runs) {
    const key = `${r.fixture}|${r.arm}`;
    if (!out.has(key)) out.set(key, { fixture: r.fixture, arm: r.arm, all: [], ok: [] });
    const g = out.get(key);
    g.all.push(r);
    if (r.status === "complete") g.ok.push(r);
  }
  return [...out.values()];
}

export function render(runs, { plantedIds = {} } = {}) {
  const groups = group(runs);
  const fixtures = [...new Set(groups.map((g) => g.fixture))];
  const L = [];
  L.push("| fixture | arm | runs ok/total | found per run | found mean (range) | loose found mean | false pos. per run | unmatched mean | turns | tokens | time (s) | index tool calls |", "|---|---|---|---|---|---|---|---|---|---|---|---|");
  for (const g of groups) {
    const ok = g.ok;
    const col = (f) => ok.map(f).filter((x) => x !== null && x !== undefined);
    L.push(`| ${g.fixture} | ${g.arm} | ${ok.length}/${g.all.length} | ${col((r) => r.score.found).join(", ")} of ${ok[0]?.score.planted ?? "?"} | ${fmt(col((r) => r.score.found))} | ${fmt(col((r) => r.loose?.found ?? r.score.found))} | ${col((r) => r.score.falsePositives).join(", ")} | ${fmt(col((r) => r.score.unmatched.length))} | ${fmt(col((r) => r.turns), (x) => x.toFixed(0))} | ${fmt(col((r) => r.tokens), k)} | ${fmt(col((r) => r.seconds), (x) => x.toFixed(0))} | ${fmt(col((r) => r.indexToolCalls ?? 0))} |`);
  }
  for (const fx of fixtures) {
    const gs = groups.filter((g) => g.fixture === fx);
    const ids = plantedIds[fx] ?? [...new Set(gs.flatMap((g) => g.ok.flatMap((r) => [...r.score.foundIds, ...r.score.missedIds])))];
    L.push("", `### ${fx}: runs that found each planted bug`, "", `| bug | ${gs.map((g) => g.arm).join(" | ")} |`, `|---|${gs.map(() => "---").join("|")}|`);
    const only = [];
    for (const id of ids) {
      const cells = gs.map((g) => ({ arm: g.arm, hit: g.ok.filter((r) => r.score.foundIds.includes(id)).length, n: g.ok.length }));
      L.push(`| ${id} | ${cells.map((c) => `${c.hit}/${c.n}`).join(" | ")} |`);
      const rates = cells.filter((c) => c.n).map((c) => c.hit / c.n);
      if (rates.length > 1 && Math.max(...rates) > 0 && Math.min(...rates) < Math.max(...rates)) only.push(`${id}: ${cells.map((c) => `${c.arm} ${c.hit}/${c.n}`).join(", ")}`);
    }
    L.push("", `Bugs whose find rate differs between arms (${only.length}):`, "", ...(only.length ? only.map((o) => `- ${o}`) : ["- none"]));
    const fp = {};
    for (const g of gs) for (const r of g.ok) for (const h of [...(r.score.decoyHits ?? []).map((d) => d.decoy), ...(r.score.cleanHits ?? []).map((c) => c.path)]) fp[`${g.arm}: ${h}`] = (fp[`${g.arm}: ${h}`] ?? 0) + 1;
    L.push("", `False positives by arm and place (decoy id or clean file; count of runs): ${Object.keys(fp).length ? Object.entries(fp).map(([a, n]) => `${a} x${n}`).join("; ") : "none"}`);
  }
  return `${L.join("\n")}\n`;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const args = process.argv.slice(2);
  const outAt = args.indexOf("--out");
  const out = outAt >= 0 ? args.splice(outAt, 2)[1] : null;
  const text = render(load(args));
  if (out) writeFileSync(out, text); else process.stdout.write(text);
}
