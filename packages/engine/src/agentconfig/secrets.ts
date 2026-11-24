/** Decides whether a configuration value looks like a credential. Values are never stored or printed: callers get a redacted description. */
const PROVIDER_PREFIXES: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /^sk-ant-[A-Za-z0-9_-]{20,}$/, label: "Anthropic-style key" },
  { pattern: /^sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}$/, label: "OpenAI-style key" },
  { pattern: /^(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}$/, label: "GitHub token" },
  { pattern: /^github_pat_[A-Za-z0-9_]{40,}$/, label: "GitHub fine-grained token" },
  { pattern: /^glpat-[A-Za-z0-9_-]{16,}$/, label: "GitLab token" },
  { pattern: /^xox[abprs]-[A-Za-z0-9-]{10,}$/, label: "Slack token" },
  { pattern: /^(?:AKIA|ASIA)[A-Z0-9]{16}$/, label: "AWS access key id" },
  { pattern: /^AIza[A-Za-z0-9_-]{35}$/, label: "Google API key" },
  { pattern: /^(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}$/, label: "Stripe key" },
  { pattern: /^npm_[A-Za-z0-9]{30,}$/, label: "npm token" },
  { pattern: /^hf_[A-Za-z0-9]{30,}$/, label: "Hugging Face token" },
  { pattern: /^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/, label: "JSON web token" },
];
const REFERENCE = /^(?:\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\{env:[^}]*\}|\$\{\{[^}]*\}\}|%[A-Za-z_][A-Za-z0-9_]*%|<[^>]*>|\[[^\]]*\])$/;
const PLACEHOLDER = /(?:^|[^a-z])(?:your|example|placeholder|changeme|change-me|replace|dummy|redacted|todo|xxx+|none|null|test)(?:[^a-z]|$)/i;

export function entropy(value: string): number {
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const count of counts.values()) { const p = count / value.length; bits -= p * Math.log2(p); }
  return bits;
}

export interface SecretMatch { kind: string; redacted: string }

/** `ghp_…[40 characters]`: at most the first four characters and the length. */
export function redact(value: string): string {
  const prefix = [...value].slice(0, Math.min(4, Math.floor(value.length / 4))).join("");
  return `${prefix}...[${[...value].length} characters]`;
}

/** Bearer and Basic prefixes are not part of the credential. */
const strip = (value: string): string => value.trim().replace(/^(?:bearer|basic|token)\s+/i, "").replace(/^["']|["']$/g, "");

export function providerShape(raw: string): string | undefined {
  const value = strip(raw);
  return PROVIDER_PREFIXES.find(entry => entry.pattern.test(value))?.label;
}

/** A credential held in an env value or header, or nothing when the value is empty, a reference to the environment or a placeholder. */
export function looksLikeSecret(raw: string): SecretMatch | undefined {
  const value = strip(raw);
  if (value.length < 8 || REFERENCE.test(value) || /\$\{[^}]*\}/.test(value)) return undefined;
  const provider = providerShape(value);
  if (provider) return { kind: provider, redacted: redact(value) };
  if (PLACEHOLDER.test(value) || /^https?:\/\//i.test(value) || /\s/.test(value)) return undefined;
  if (value.length >= 20 && /^[A-Za-z0-9+/=_.~-]+$/.test(value) && /\d/.test(value) && /[A-Za-z]/.test(value) && entropy(value) >= 3.5) return { kind: "high-entropy value", redacted: redact(value) };
  return undefined;
}

/** Text that is safe to print: URL credentials and query values, provider-shaped keys and high-entropy words are replaced by a redacted form. */
export function scrub(text: string): string {
  return text
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@]*@/gi, "$1***@")
    .replace(/(\bhttps?:\/\/[^\s?#"']*)\?[^\s#"']*/gi, "$1?...")
    .split(/(\s+)/)
    .map(part => {
      const bare = part.replace(/^[^=]*=/, "");
      const secret = part.length >= 8 ? looksLikeSecret(bare) : undefined;
      return secret ? `${part.slice(0, part.length - bare.length)}${secret.redacted}` : part;
    })
    .join("");
}
