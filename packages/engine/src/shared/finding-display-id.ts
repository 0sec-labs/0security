/** Browser-safe display helpers. Full persisted identities remain unchanged. */
export function shortFindingFingerprint(fingerprint: string): string {
  const imported = /^(?:ci|sarif)-[a-f0-9]{64}:(?:sarif:)?(.+)$/i.exec(fingerprint);
  return (imported ? imported[1]! : fingerprint).slice(0, 10);
}

/** Skip structural prefixes; an import digest identifies the report, not the individual finding. */
export function findingFingerprintCode(fingerprint: string): string {
  const imported = /^(?:ci|sarif)-[a-f0-9]{64}:(?:sarif:)?(.+)$/i.exec(fingerprint);
  const located = /^loc:(.+)$/i.exec(fingerprint);
  const distinctive = imported?.[1] ?? located?.[1];
  // Ordinary family codes keep their previous spelling. Structured ones use ten digest digits.
  const clean = (distinctive ?? fingerprint).replace(/[^a-z0-9]/gi, "").slice(0, distinctive ? 10 : 6).toUpperCase();
  return `F-${clean || "000000"}`;
}
