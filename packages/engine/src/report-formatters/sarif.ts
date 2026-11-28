import { businessContextLabel } from "../shared/business-context.js";
import { posix, win32 } from "node:path";
import { executedPocFor, executedPocLine, attackerImpactSentence, describeAttackerImpact, compareFindingsByBusinessContext, reproductionFor, reproductionLine, proofLine } from "../shared/index.js";
import type { PocStep, ScanReport, Finding, Severity } from "../shared/index.js";
import { VERSION } from "../shared/index.js";

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number; endLine?: number };
    };
  }>;
  partialFingerprints?: Record<string, string>;
  codeFlows?: Array<{
    threadFlows: Array<{
      locations: Array<{
        location: {
          physicalLocation: {
            artifactLocation: { uri: string };
          };
          message: { text: string };
          properties?: Record<string, unknown>;
        };
      }>;
    }>;
  }>;
  /** SARIF 2.1.0 section 3.27.23: an accepted risk or a dismissal recorded outside the code. */
  /** SARIF 2.1.0 section 3.27.30: a proposed change, described in words and as a replacement of the cited lines. */
  fixes?: Array<{ description: { text: string }; artifactChanges: Array<{ artifactLocation: { uri: string }; replacements: Array<{ deletedRegion: { startLine: number; endLine?: number }; insertedContent: { text: string } }> }> }>;
  suppressions?: Array<{ kind: "external"; status: "accepted"; justification?: string; properties?: Record<string, unknown> }>;
  properties?: Record<string, unknown>;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: "error" | "warning" | "note" };
  properties?: Record<string, unknown>;
}

function severityToLevel(severity: Severity): "error" | "warning" | "note" {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
    case "info":
      return "note";
  }
}

function stableFingerprint(finding: Finding, target: string): string {
  // A location key ("loc:...") already says where the flaw is and is the same on every machine and every run; the title,
  // which a model words differently each time, and the target would only make the alert look new.
  if (finding.fingerprint?.startsWith("loc:")) return finding.fingerprint;
  return [
    finding.fingerprint,
    finding.templateId,
    finding.category,
    finding.title,
    target,
  ].filter(Boolean).join("|");
}

function actionSummary(step: PocStep): Record<string, unknown> {
  switch (step.action.type) {
    case "shell":
      return { type: "shell", command: step.action.cmd, cwd: step.action.cwd };
    case "http":
      return {
        type: "http",
        method: step.action.method,
        url: step.action.url,
        headers: step.action.headers,
      };
    case "docker":
      return { type: "docker", image: step.action.image, args: step.action.args };
    case "note":
      return { type: "note" };
  }
}

function pocStepsToCodeFlows(
  pocSteps: PocStep[] | undefined,
  target: string,
): SarifResult["codeFlows"] {
  if (!pocSteps || pocSteps.length === 0) return undefined;
  return [
    {
      threadFlows: [
        {
          locations: pocSteps.map((step) => ({
            location: {
              physicalLocation: {
                artifactLocation: { uri: target },
              },
              message: { text: `${step.kind}: ${step.summary}` },
              properties: {
                stepId: step.id,
                kind: step.kind,
                action: actionSummary(step),
                expect: step.expect,
              },
            },
          })),
        },
      ],
    },
  ];
}

/** Review annotations are relative to the reviewed source root, not the repository root. */
function annotationUri(annotationPath: string, target: string): string | undefined {
  // Persisted reports may bypass annotation validation. Never reinterpret an
  // absolute path, URL, or traversal as a location below the reviewed root.
  if (!annotationPath || annotationPath.startsWith("/") || annotationPath.includes("\\") || annotationPath.split("/").includes("..") || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(annotationPath)) return undefined;
  const encoded = (value: string) => value.split("/").map(part => encodeURIComponent(part)).join("/");
  const root = target.startsWith("repo:") ? target.slice(5) : target;
  if (/^file:\/\//i.test(root)) {
    try { return new URL(encoded(annotationPath), root.endsWith("/") ? root : root + "/").href; } catch { return undefined; }
  }
  if (/^[A-Za-z]:[\\/]/.test(root)) {
    const path = win32.join(root, annotationPath).replace(/\\/g, "/");
    return "file:///" + path.slice(0, 2) + encoded(path.slice(2));
  }
  if (root.startsWith("\\\\")) {
    const [host, ...parts] = win32.join(root, annotationPath).replace(/\\/g, "/").slice(2).split("/");
    return "file://" + host + "/" + encoded(parts.join("/"));
  }
  if (root.startsWith("/")) return "file://" + encoded(posix.join(root, annotationPath));
  // A remote clone/package label does not identify its checkout location.
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(root) || /^git@/.test(root)) return encoded(annotationPath);
  // Retain the original invocation-relative root without inventing an absolute
  // checkout based on whichever directory later renders a saved report.
  return encoded(posix.join(root || ".", annotationPath));
}

function findingLocation(finding: Finding, target: string): SarifResult["locations"][number]["physicalLocation"] {
  const annotation = finding.reviewAnnotation;
  if (typeof annotation?.path !== "string" || !annotation.path) return { artifactLocation: { uri: target } };
  const { path, startLine, endLine } = annotation;
  const uri = annotationUri(path, target);
  if (!uri) return { artifactLocation: { uri: target } };
  // A persisted annotation can carry a bad line. SARIF lines start at 1, so keep only the file then.
  if (!Number.isInteger(startLine) || startLine < 1) return { artifactLocation: { uri } };
  const end = endLine !== undefined && Number.isInteger(endLine) && endLine >= startLine ? { endLine } : {};
  return { artifactLocation: { uri }, region: { startLine, ...end } };
}

function findingToResult(finding: Finding, target: string, suppressOutOfScope = false): SarifResult {
  const result: SarifResult = {
    ruleId: finding.templateId,
    level: severityToLevel(finding.severity),
    message: { text: [finding.description, businessContextLabel(finding.businessContext), attackerImpactSentence(finding) ? `${describeAttackerImpact(finding)?.label ?? "What an attacker can do"}: ${attackerImpactSentence(finding)}` : ""].filter(Boolean).join("\n\n") },
    locations: [{ physicalLocation: findingLocation(finding, target) }],
    partialFingerprints: {
      primary: stableFingerprint(finding, target),
    },
  };

  const codeFlows = pocStepsToCodeFlows(finding.pocSteps, target);
  if (codeFlows) result.codeFlows = codeFlows;

  if (finding.triageStatus === "accepted" || finding.triageStatus === "suppressed") {
    result.suppressions = [{
      kind: "external", status: "accepted",
      ...(finding.triageNote ? { justification: finding.triageNote } : {}),
      properties: { triage: finding.triageStatus, ...(finding.triageExpiresAt ? { expiresAt: finding.triageExpiresAt } : {}), ...(finding.triageApprover ? { approver: finding.triageApprover } : {}) },
    }];
  }

  if (finding.scope && finding.scope !== undefined) {
    // Suppressions are opt-in (`--scope-sarif suppress`): GitHub code scanning dismisses a suppressed result.
    if (suppressOutOfScope && finding.scope === "out-of-scope" && !result.suppressions) {
      result.suppressions = [{ kind: "external", status: "accepted", justification: `Outside declared scope: ${finding.scopeReason ?? "no reason given"}`, properties: { scope: finding.scope, ...(finding.scopeSource ? { scopeSource: finding.scopeSource } : {}) } }];
    }
  }

  const fixExplanation = finding.reviewAnnotation?.fixExplanation;
  const replacement = finding.reviewAnnotation?.suggestion;
  if (fixExplanation && replacement) {
    // A SARIF fix needs a concrete change; the explanation alone goes in the result properties below.
    const place = findingLocation(finding, target);
    if (place.region) {
      result.fixes = [{ description: { text: fixExplanation }, artifactChanges: [{ artifactLocation: { uri: place.artifactLocation.uri }, replacements: [{ deletedRegion: place.region, insertedContent: { text: replacement.endsWith("\n") ? replacement : `${replacement}\n` } }] }] }];
    }
  }

  result.properties = {
    findingId: finding.id,
    category: finding.category,
    severity: finding.severity,
    status: finding.status,
    evidence: finding.evidence,
  };
  if (finding.scope) result.properties["scope"] = finding.scope;
  if (finding.scopeReason) result.properties["scopeReason"] = finding.scopeReason;
  if (finding.scopeSource) result.properties["scopeSource"] = finding.scopeSource;
  if (fixExplanation) result.properties["fixExplanation"] = fixExplanation;
  if (finding.ruleSource) result.properties["ruleSource"] = finding.ruleSource;
  if (finding.knownStatus) result.properties["knownStatus"] = finding.knownStatus;
  if (finding.knownBy) result.properties["knownBy"] = finding.knownBy;
  if (finding.confirmedIndependently) result.properties["confirmedIndependently"] = true;
  if (finding.businessContext) result.properties["businessContext"] = finding.businessContext;
  if (finding.impactAssessment) result.properties["impactAssessment"] = finding.impactAssessment;
  if (finding.cvssScore !== undefined) result.properties["cvssScore"] = finding.cvssScore;
  if (finding.cvssVector) result.properties["cvssVector"] = finding.cvssVector;
  if (finding.confidence !== undefined) result.properties["confidence"] = finding.confidence;
  if (finding.publishability) result.properties["publishability"] = finding.publishability;
  if (finding.noveltyVerdict) result.properties["noveltyVerdict"] = finding.noveltyVerdict;
  if (finding.dedupRefs) result.properties["dedupRefs"] = finding.dedupRefs;
  if (finding.advisoryMatches) result.properties["advisoryMatches"] = finding.advisoryMatches;
  if (finding.verification_result) result.properties["verificationResult"] = finding.verification_result;
  const reproduction = reproductionFor(finding, finding.reproduction);
  if (reproduction) {
    result.properties["reproduction"] = {
      ...(reproduction.proof ? { proof: reproduction.proof, proofLabel: proofLine(reproduction.proof) } : {}),
      ...(reproduction.result ? { result: reproduction.result, resultLabel: reproductionLine(reproduction.result) } : {}),
    };
  }
  const executedPoc = executedPocFor(finding, finding.executedPoc);
  // The stored record in full (so a reader can parse it with the same rules), plus the sentence. A derived "not attempted" record has no times and stays short.
  if (executedPoc) result.properties["executedPoc"] = {
    outcome: executedPoc.outcome, reason: executedPoc.reason, label: executedPocLine(executedPoc),
    ...(executedPoc.startedAt ? { schemaVersion: executedPoc.schemaVersion, harness: executedPoc.harness, stepIds: executedPoc.stepIds, startedAt: executedPoc.startedAt, finishedAt: executedPoc.finishedAt } : {}),
    ...(executedPoc.run ? { run: executedPoc.run } : {}),
  };
  if (finding.rootCause) result.properties["rootCause"] = finding.rootCause;
  if (finding.variantOf) result.properties["variantOf"] = finding.variantOf;
  if (finding.inlineValidation) result.properties["inlineValidation"] = finding.inlineValidation;
  if (finding.supplyChain) result.properties["supplyChain"] = finding.supplyChain;
  if (finding.kernelExploit) result.properties["kernelExploit"] = finding.kernelExploit;
  if (finding.semanticDedupe) result.properties["semanticDedupe"] = finding.semanticDedupe;
  if (finding.findingRank !== undefined) result.properties["findingRank"] = finding.findingRank;

  return result;
}

function findingToRule(finding: Finding): SarifRule {
  return {
    id: finding.templateId,
    name: finding.title,
    shortDescription: { text: finding.title },
    defaultConfiguration: { level: severityToLevel(finding.severity) },
    properties: {
      category: finding.category,
      severity: finding.severity,
    },
  };
}

export function formatSarif(report: ScanReport): string {
  // Deduplicate rules by templateId
  const rulesMap = new Map<string, SarifRule>();
  for (const finding of report.findings) {
    if (!rulesMap.has(finding.templateId)) {
      rulesMap.set(finding.templateId, findingToRule(finding));
    }
  }

  for (const check of report.reviewChecks ?? []) {
    rulesMap.set(`review-check/${check.id}`, {
      id: `review-check/${check.id}`, name: check.name,
      shortDescription: { text: check.name },
      defaultConfiguration: { level: "note" },
      properties: { advisory: true },
    });
  }
  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0" as const,
    runs: [
      {
        tool: {
          driver: {
            name: "0",
            version: VERSION,
            informationUri: "https://github.com/0sec-labs/0security",
            rules: Array.from(rulesMap.values()),
          },
        },
        results: [
          ...[...report.findings].sort(compareFindingsByBusinessContext).map((f) => findingToResult(f, report.target, report.scopeInfo?.sarifSuppress === true)),
          ...(report.reviewChecks ?? []).map(check => ({
            ruleId: `review-check/${check.id}`,
            kind: check.status === "pass" ? "pass" : check.status === "issue" ? "fail" : "open",
            level: "note",
            message: { text: `${check.name}: ${check.reason}${check.fix ? `\nSuggested fix: ${check.fix}` : ""}` },
            properties: { advisory: true, reviewCheck: check },
          })),
        ],
        invocations: [
          {
            executionSuccessful: report.executionSuccessful !== false,
            startTimeUtc: report.startedAt,
            endTimeUtc: report.completedAt,
          },
        ],
        // What a batched scan reviewed; complete is false when entry points were not reached.
        // The tier map's decision and the known set of a second-opinion scan.
        ...(report.scanStatus || report.scanFailure || report.coverage || report.fileCoverage || report.children || report.tier || report.known || report.scopeInfo || report.warnings?.length ? { properties: { ...(report.scanStatus ? { status: report.scanStatus } : {}), ...(report.scanFailure ? { failure: report.scanFailure } : {}), ...(report.coverage ? { coverage: report.coverage } : {}), ...(report.fileCoverage ? { fileCoverage: report.fileCoverage } : {}), ...(report.children ? { children: report.children } : {}), ...(report.tier ? { tier: report.tier } : {}), ...(report.known ? { known: report.known } : {}), ...(report.scopeInfo ? { scope: { source: report.scopeInfo.source, outOfScopeFindings: report.findings.filter(f => f.scope === "out-of-scope").length } } : {}), ...(report.warnings?.length ? { warnings: report.warnings.map(warning => warning.message) } : {}) } } : {}),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
