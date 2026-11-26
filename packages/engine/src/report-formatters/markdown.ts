import { businessContextLabel } from "../shared/business-context.js";
import { executedPocFor, executedPocLine, reproductionFor, reproductionLine, proofLine, describeAttackerImpact, compareFindingsByBusinessContext, orderByScope, splitByScope } from "../shared/index.js";
import type { ScanReport, Finding, FindingRemediation, PocStep } from "../shared/index.js";

/**
 * Per-block cap on raw request/response evidence in the markdown report.
 *
 * This format is what a human reads by default, so it has to be readable —
 * a 200 KB response body pasted inline is not. But truncation must never be
 * SILENT: the previous implementation cut at 500 characters with no marker,
 * so a reader could not tell whether they were looking at the whole request
 * or the first paragraph of it, and a PoC that mattered could be sitting just
 * past the cut. Every elision below is annotated with the exact byte count
 * dropped and a pointer to the lossless formats.
 *
 * 4000 fits a realistic HTTP exchange or a source excerpt while still bounding
 * the page. `--format sarif` and `--format json` carry evidence in full.
 */
const EVIDENCE_BLOCK_LIMIT = 4000;

/** Longest single PoC step list rendered before summarising the remainder. */
const POC_STEP_LIMIT = 20;

/** Text from a scope file in one table cell or line: no pipes, line breaks, HTML or Markdown links. */
const inline = (text: string): string => text.replace(/[|\r\n]+/g, " ").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/([\\`*_{}\[\]()#+!~])/g, "\\$1");

export function formatMarkdown(report: ScanReport): string {
  const lines: string[] = [];
  const { inScope, outOfScope } = splitByScope(report.findings);
  const incomplete = report.executionSuccessful === false;

  lines.push("# 0 Scan Report");
  lines.push("");
  lines.push(`| Field | Value |`);
  lines.push(`|-------|-------|`);
  lines.push(`| Target | ${report.target} |`);
  lines.push(`| Started | ${report.startedAt} |`);
  lines.push(`| Duration | ${(report.durationMs / 1000).toFixed(1)}s |`);
  if (report.tier) lines.push(`| Tier | ${report.tier.name}${report.tier.reason ? `: ${report.tier.reason.replace(/[|\r\n]+/g, " ")}` : ""} |`);
  if (report.scopeInfo) lines.push(`| Declared scope | ${inline(report.scopeInfo.source)}; in scope: ${report.scopeInfo.inScopeVectors.map(inline).join(", ") || "none listed"}; out of scope: ${report.scopeInfo.outOfScopeVectors.map(inline).join(", ") || "none listed"} |`);
  lines.push("");
  if (incomplete) lines.push(report.scanFailure ? `The scan did not finish: ${report.scanFailure.message.replace(/\.+$/, "")}. Results may be incomplete.` : "Assessment did not complete successfully. Results may be incomplete.", "");

  // Summary
  lines.push("## Summary");
  lines.push("");
  if (report.summary.totalAttacks > 0) lines.push(`- **Attacks:** ${report.summary.totalAttacks}`);
  lines.push(`- **Findings:** ${report.summary.totalFindings}`);
  if (outOfScope.length) lines.push(`- **Outside declared scope:** ${outOfScope.length} (listed apart, not counted above)`);
  lines.push("", "### Technical severity", "");
  if (report.summary.critical > 0)
    lines.push(`- **Critical:** ${report.summary.critical}`);
  if (report.summary.high > 0) lines.push(`- **High:** ${report.summary.high}`);
  if (report.summary.medium > 0) lines.push(`- **Medium:** ${report.summary.medium}`);
  if (report.summary.low > 0) lines.push(`- **Low:** ${report.summary.low}`);
  lines.push("");

  if (report.tier?.skipped) {
    lines.push("## Scan skipped", "", `Skipped by tier ${report.tier.name}${report.tier.reason ? `: ${report.tier.reason}` : ""}. Nothing was scanned, so this report says nothing about the code.`, "");
  } else if (report.tier?.prepassOnly) {
    lines.push("## Pre-pass only", "", `Tier ${report.tier.name} runs the pattern scanners only. The findings below are scanner hits, not reviewed by a model; the code was not otherwise reviewed.`, "");
  }
  if (report.known) {
    const counts = report.known.findings;
    lines.push("## Known findings", "", `Given ${report.known.total} known item${report.known.total === 1 ? "" : "s"} from ${report.known.tools.join(", ") || "other tools"}. This report has ${counts.new} new and ${counts.alreadyKnown} already known findings; ${counts.confirmedIndependently} of the known ones were confirmed independently.${report.known.hidden ? ` ${report.known.hidden} finding${report.known.hidden === 1 ? " is" : "s are"} hidden by --only-new.` : ""}`, "");
  }

  const partial = report.coverage !== undefined && !report.coverage.complete;
  if (report.coverage) {
    lines.push("## Coverage", "");
    lines.push(`This scan ran in batches: ${report.coverage.statement}.`);
    if (report.coverage.opened !== undefined && report.coverage.inScope !== undefined) lines.push("", `The threads opened ${report.coverage.opened} of ${report.coverage.inScope} source files${report.coverage.rounds?.used ? ` after ${report.coverage.rounds.used} follow-up round${report.coverage.rounds.used === 1 ? "" : "s"}` : ""}.`);
    if (partial) {
      lines.push("", "The scan did not review everything, so the findings below are partial. A missing finding in code that was not reached means nothing.");
      const shown = report.coverage.pendingUnits.slice(0, 20);
      if (shown.length) {
        lines.push("", "Not reached:", "");
        for (const unit of shown) lines.push(`- ${unit.kind} \`${unit.path}${unit.startLine ? `:${unit.startLine}` : ""}\`${unit.reason ? ` (${unit.reason})` : ""}`);
        const more = report.coverage.pendingUnits.length - shown.length;
        if (more > 0) lines.push(`- and ${more} more`);
      }
    }
    lines.push("");
  }

  if (!report.coverage && report.fileCoverage) lines.push("## Files opened", "", `The scan opened ${report.fileCoverage.opened} of ${report.fileCoverage.inScope} source files${report.fileCoverage.rounds.used ? ` after ${report.fileCoverage.rounds.used} follow-up round${report.fileCoverage.rounds.used === 1 ? "" : "s"}` : ""}.${report.fileCoverage.unopenedCount ? ` Not opened: ${report.fileCoverage.unopened.slice(0, 20).join(", ")}${report.fileCoverage.unopenedCount > 20 ? `, and ${report.fileCoverage.unopenedCount - 20} more` : ""}.` : ""}`, "");

  if (report.warnings.length > 0) {
    lines.push("## Warnings");
    lines.push("");
    for (const warning of report.warnings) {
      lines.push(`- **${warning.stage}:** ${warning.message}`);
    }
    lines.push("");
  }

  if (report.reviewChecks?.length) {
    lines.push("## Review Checks (Advisory)", "");
    const literal = (text: string): string => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/([\\`*_{}\[\]()#+.!|~-])/g, "\\$1");
    for (const check of report.reviewChecks) {
      lines.push(`### ${check.status.toUpperCase()}: ${literal(check.name)}`, "");
      lines.push(`- **ID:** ${literal(check.id)}`);
      lines.push(`- **Reason:** ${literal(check.reason)}`);
      if (check.fix) lines.push(`- **Suggested fix:** ${literal(check.fix)}`);
      lines.push("");
    }
  }

  // Findings
  if (inScope.length > 0) {
    lines.push("## Findings");
    lines.push("");
    for (const finding of orderByScope(inScope, compareFindingsByBusinessContext)) {
      lines.push(formatFinding(finding));
    }
  } else {
    if (report.tier?.skipped) return lines.join("\n");
    lines.push(incomplete || partial || report.warnings.length > 0 ? "## No Confirmed Vulnerabilities" : "## No Findings");
    lines.push("");
    lines.push(
      report.tier?.prepassOnly
        ? "The pattern scanners reported nothing. No model reviewed this code."
        : partial
        ? `No vulnerabilities were confirmed in the code that was reviewed (${report.coverage!.statement}).`
        : report.warnings.length > 0
        ? "The scanner did not confirm vulnerabilities, but the scan produced warnings (see Warnings). Read them before relying on this result."
        : report.reviewChecks?.length
          ? "No security vulnerabilities were found in the inspected scope. Advisory review-check results are reported separately above."
          : incomplete ? "The scanner did not confirm vulnerabilities." : "No vulnerabilities were found in the reviewed scope. A scan with no findings is not proof that the code is safe."
    );
  }

  if (outOfScope.length > 0) {
    lines.push("", `## Outside declared scope (${outOfScope.length})`, "", "These findings match a vector the repository's scope file declares out of scope. They are listed here, not hidden, and are not counted in the summary or in the exit code.", "");
    for (const finding of [...outOfScope].sort(compareFindingsByBusinessContext)) lines.push(formatFinding(finding));
  }

  return lines.join("\n");
}

/**
 * Wrap `body` in a fence that is longer than any backtick run in `body`, so a
 * fence inside `body` cannot close the block early. CommonMark rejects a
 * backtick in the info string of a backtick fence, so `info` loses backticks
 * and line breaks (it can come from model output, e.g. a remediation language).
 */
function fenced(body: string, info = ""): string[] {
  let longest = 2;
  for (const match of body.matchAll(/`+/g)) longest = Math.max(longest, match[0].length);
  const fence = "`".repeat(longest + 1);
  return [fence + String(info).replace(/[`\r\n]/g, ""), body, fence];
}

/**
 * Render one evidence blob inside a fenced block, disclosing any elision.
 *
 * Returns the marker line separately from the body so the caller can place it
 * outside the code fence — a truncation note inside the fence would read as
 * part of the captured traffic, which is exactly the kind of ambiguity this
 * function exists to remove.
 */
function evidenceBlock(label: string, raw: string): string[] {
  const lines: string[] = [];
  lines.push(`**${label}:**`);
  if (!raw) {
    lines.push("");
    lines.push("_(not captured)_");
    return lines;
  }
  const truncated = raw.length > EVIDENCE_BLOCK_LIMIT;
  const body = truncated ? raw.slice(0, EVIDENCE_BLOCK_LIMIT) : raw;
  lines.push(...fenced(body));
  if (truncated) {
    lines.push(
      `_Truncated for readability: ${raw.length - EVIDENCE_BLOCK_LIMIT} of ` +
        `${raw.length} characters not shown. Use \`--format json\` or ` +
        `\`--format sarif\` for the complete evidence._`,
    );
  }
  return lines;
}

/** Render the structured remediation block when the finding carries one. */
function remediationSection(remediation: FindingRemediation): string[] {
  const lines: string[] = [];
  lines.push("**Remediation:**");
  lines.push("");
  lines.push(remediation.summary);
  if (remediation.steps.length > 0) {
    lines.push("");
    for (const step of remediation.steps) lines.push(`1. ${step}`);
  }
  if (remediation.codeExample) {
    const { before, after, language } = remediation.codeExample;
    lines.push("");
    lines.push("<details>");
    lines.push("<summary>Suggested change</summary>");
    lines.push("");
    lines.push("Before:");
    lines.push("");
    lines.push(...fenced(before, language));
    lines.push("");
    lines.push("After:");
    lines.push("");
    lines.push(...fenced(after, language));
    lines.push("</details>");
  }
  if (remediation.references.length > 0) {
    lines.push("");
    lines.push("References:");
    for (const ref of remediation.references) lines.push(`- ${ref}`);
  }
  lines.push("");
  return lines;
}

/**
 * Render the ordered PoC step graph as human-followable reproduction steps.
 *
 * A disclosure reader's first question is "how do I reproduce this"; when the
 * structured graph exists it answers that far better than the prose evidence
 * blob, so it is rendered ahead of the raw request/response.
 */
function reproductionSection(steps: PocStep[]): string[] {
  const lines: string[] = [];
  lines.push("**Reproduction steps:**");
  lines.push("");
  const shown = steps.slice(0, POC_STEP_LIMIT);
  shown.forEach((step, i) => {
    lines.push(`${i + 1}. **[${step.kind}]** ${step.summary}`);
  });
  if (steps.length > shown.length) {
    lines.push("");
    lines.push(
      `_${steps.length - shown.length} further step(s) omitted; the full graph ` +
        `is in \`--format json\`._`,
    );
  }
  lines.push("");
  return lines;
}

function formatFinding(finding: Finding): string {
  const lines: string[] = [];

  lines.push(`### ${finding.title}`);
  lines.push("");
  const attacker = describeAttackerImpact(finding);
  if (attacker) {
    lines.push(`- **${attacker.label ?? "What an attacker can do"}:** ${attacker.can}`);
    if (attacker.who) lines.push(`- **Who can do it:** ${attacker.who}`);
    if (attacker.gets) lines.push(`- **What they get:** ${attacker.gets}`);
  }
  lines.push(`- **Technical severity:** ${finding.severity}`);
  lines.push(`- **Category:** ${finding.category}`);
  lines.push(`- **Status:** ${finding.status}`);
  if (finding.scope === "out-of-scope") lines.push(`- **Scope:** out of scope (${inline(finding.scopeSource ?? "scope file")}): ${inline(finding.scopeReason ?? "no reason given")}`);
  if (finding.knownStatus) {
    const by = finding.knownBy ? ` (${finding.knownBy.tool} ${finding.knownBy.ruleId} at ${finding.knownBy.path}:${finding.knownBy.startLine})` : "";
    lines.push(`- **Known status:** ${finding.knownStatus}${finding.confirmedIndependently ? ", confirmed independently" : ""}${by}`);
  }
  // Severity justification: a bare "high" is an assertion; a CVSS vector is a
  // claim a vendor can check. Rendered only when actually present — this
  // formatter never synthesises one.
  if (finding.cvssScore !== undefined || finding.cvssVector) {
    const score = finding.cvssScore !== undefined ? `${finding.cvssScore}` : "n/a";
    const vector = finding.cvssVector ? ` (\`${finding.cvssVector}\`)` : "";
    lines.push(`- **CVSS:** ${score}${vector}`);
  }
  if (finding.confidence !== undefined) {
    lines.push(`- **Confidence:** ${(finding.confidence * 100).toFixed(0)}%`);
  }
  if (finding.triageNote && finding.triageStatus !== "accepted") {
    lines.push(`- **Triage:** ${finding.triageNote}`);
  }
  if (finding.triageStatus === "accepted") {
    lines.push(`- **Accepted risk:** ${finding.triageNote ?? "no reason recorded"}${finding.triageExpiresAt ? `; accepted until ${finding.triageExpiresAt.slice(0, 10)}` : ""}${finding.triageApprover ? `; approver (label): ${finding.triageApprover}` : ""}`);
  }
  const business = businessContextLabel(finding.businessContext);
  if (business) lines.push(`- **Business priority:** ${inline(business)}`);
  lines.push(`- **Description:** ${finding.description}`);
  lines.push("");

  if (finding.evidence.analysis) {
    lines.push(`**Evidence:** ${finding.evidence.analysis}`);
    lines.push("");
  }

  if (finding.pocSteps && finding.pocSteps.length > 0) {
    lines.push(...reproductionSection(finding.pocSteps));
  }

  const repro = reproductionFor(finding, finding.reproduction);
  if (repro) {
    lines.push(`**Proof:** ${repro.result ? reproductionLine(repro.result) : proofLine(repro.proof)}.`);
    lines.push("");
  }

  const executed = executedPocFor(finding, finding.executedPoc);
  if (executed) {
    lines.push(`**PoC execution:** \`${executed.outcome}\`. ${executedPocLine(executed)}.`);
    lines.push("");
  }

  if (finding.remediation) {
    lines.push(...remediationSection(finding.remediation));
  } else if (finding.reviewAnnotation?.fixExplanation) {
    lines.push("**How to fix:**");
    lines.push("");
    lines.push(finding.reviewAnnotation.fixExplanation);
    lines.push("");
  }

  lines.push("<details>");
  lines.push("<summary>Request / Response</summary>");
  lines.push("");
  lines.push(...evidenceBlock("Request", finding.evidence.request));
  lines.push("");
  lines.push(...evidenceBlock("Response", finding.evidence.response));
  lines.push("</details>");
  lines.push("");

  return lines.join("\n");
}
