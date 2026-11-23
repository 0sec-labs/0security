/**
 * The finding category taxonomy and the one place a model's label becomes one of our categories.
 *
 * A model files a finding under whatever label fits its own words ("idor", "predictable password-reset token",
 * or the catch-all "missing-validation"). SARIF rule ids, `0 findings list --category`, issue labels, dedupe and the
 * attacker-impact text all read the category, so it has to name the vulnerability class, not the symptom.
 *
 * Precedence, first hit wins:
 *  1. A specific category we have (not one of the catch-alls below) is kept as given.
 *  2. A label we have an alias for ("broken-access-control", "sqli", "redos").
 *  3. A CWE the model gave, when the CWE names one class.
 *  4. The title, then the label, against the ordered rules below (specific classes before general ones).
 *  5. For `other` or an unknown label only: the description against the same rules.
 *  6. The category the model gave when it is one of ours, else `other`.
 * Rules 3 to 5 apply only when the model's category is a catch-all or unknown. A catch-all is a category that says how
 * a flaw was found or where it shows, not what it is: `missing-validation`, `other`, `security-misconfiguration`,
 * `information-disclosure`, `crypto-misuse`, `output-manipulation` and `ssrf` (models file XML entities and redirects there).
 * Existing category ids never change; new ones are added.
 */
import type { AttackCategory } from "./types.js";

/** Every category id. Existing ids are stable: saved databases and SARIF files carry them. */
export const ATTACK_CATEGORIES = [
  "prompt-injection",
  "jailbreak",
  "system-prompt-extraction",
  "data-exfiltration",
  "tool-misuse",
  "output-manipulation",
  "encoding-bypass",
  "multi-turn",
  "prototype-pollution",
  "path-traversal",
  "command-injection",
  "code-injection",
  "regex-dos",
  "unsafe-deserialization",
  "information-disclosure",
  "ssrf",
  "sql-injection",
  "xss",
  "cors",
  "security-misconfiguration",
  "missing-validation",
  "crypto-misuse",
  "heap-overflow",
  "out-of-bounds-read",
  "out-of-bounds-write",
  "use-after-free",
  "stack-buffer-overflow",
  "null-pointer-deref",
  "null-deref",
  "integer-overflow",
  "integer-truncation",
  "race-condition",
  "toctou",
  "type-confusion",
  "double-free",
  "format-string",
  "uninitialized-memory",
  "denial-of-service",
  "known-vulnerable-package",
  "supply-chain",
  "policy-violation",
  // Web application classes (OWASP Top 10 2021 families)
  "broken-access-control",
  "broken-authentication",
  "mass-assignment",
  "csrf",
  "open-redirect",
  "xxe",
  "hardcoded-secret",
  "insecure-randomness",
  "insecure-storage",
  "insecure-transport",
  "missing-rate-limit",
  "other",
] as const satisfies readonly AttackCategory[];

/** What each category is, with its usual CWE and OWASP Top 10 2021 family. Shown in docs and the tool prompt. */
export const NEW_CATEGORY_GUIDE: Record<string, string> = {
  "broken-access-control": "a missing or wrong authorization check: IDOR, BOLA, no role check, an unauthenticated destructive route (CWE-284, 285, 306, 639, 862, 863; A01)",
  "broken-authentication": "session fixation, a weak password policy, user enumeration, authentication bypass (CWE-204, 287, 384, 521, 613; A07)",
  "mass-assignment": "a request body sets fields it should not, such as an admin flag at registration (CWE-915; A01 or A04)",
  csrf: "a state-changing request with no anti-forgery check (CWE-352; A01)",
  "open-redirect": "a redirect to an attacker-chosen URL (CWE-601; A01)",
  xxe: "an XML parser that resolves external entities (CWE-611; A05)",
  "hardcoded-secret": "a key, signing secret or credential written in source or seeded as a default (CWE-259, 321, 798; A07)",
  "insecure-randomness": "a predictable token, id or seed where an attacker must not guess it (CWE-330, 338, 340; A02)",
  "insecure-storage": "a password or sensitive value stored in plaintext or unhashed (CWE-256, 312, 313, 522; A02)",
  "insecure-transport": "data or a database link sent without TLS (CWE-295, 319, 523; A02)",
  "missing-rate-limit": "no limit on attempts, so passwords or codes can be brute forced (CWE-307, 799; A04 or A07)",
};

/** Categories that say how a flaw shows, not what it is. A title or CWE that names a class can refine these. */
const CATCH_ALL = new Set<string>([
  "other", "missing-validation", "security-misconfiguration", "information-disclosure", "crypto-misuse", "output-manipulation", "ssrf",
]);

const idSet = new Set<string>(ATTACK_CATEGORIES);
export const isAttackCategory = (value: unknown): value is AttackCategory => typeof value === "string" && idSet.has(value);

/** Labels models use for a category we have. Compared after lowercasing and turning spaces and underscores into dashes. */
export const CATEGORY_ALIASES: Record<string, AttackCategory> = {
  idor: "broken-access-control", bola: "broken-access-control", bfla: "broken-access-control", "insecure-direct-object-reference": "broken-access-control",
  authorization: "broken-access-control", authz: "broken-access-control", "access-control": "broken-access-control", "missing-authorization": "broken-access-control",
  "missing-authentication": "broken-access-control", "privilege-escalation": "broken-access-control", "improper-authorization": "broken-access-control",
  "broken-object-level-authorization": "broken-access-control", "broken-function-level-authorization": "broken-access-control", "missing-access-control": "broken-access-control",
  authentication: "broken-authentication", "session-fixation": "broken-authentication", "session-management": "broken-authentication", "weak-password-policy": "broken-authentication",
  "weak-password": "broken-authentication", "user-enumeration": "broken-authentication", "account-enumeration": "broken-authentication", "authentication-bypass": "broken-authentication",
  "auth-bypass": "broken-authentication", "session-hijacking": "broken-authentication", "insecure-session": "broken-authentication",
  "mass-assign": "mass-assignment", overposting: "mass-assignment",
  "cross-site-request-forgery": "csrf", xsrf: "csrf",
  "unvalidated-redirect": "open-redirect", "unvalidated-redirects": "open-redirect", redirect: "open-redirect",
  "xml-external-entity": "xxe", "xml-external-entities": "xxe",
  "hardcoded-secrets": "hardcoded-secret", "hardcoded-credentials": "hardcoded-secret", "hardcoded-credential": "hardcoded-secret", "hard-coded-credentials": "hardcoded-secret",
  "hardcoded-key": "hardcoded-secret", "hardcoded-password": "hardcoded-secret", "default-credentials": "hardcoded-secret", secrets: "hardcoded-secret", "secret-exposure": "hardcoded-secret",
  "predictable-token": "insecure-randomness", "weak-randomness": "insecure-randomness", "insecure-random": "insecure-randomness", "weak-random": "insecure-randomness",
  "predictable-id": "insecure-randomness", "insecure-token": "insecure-randomness",
  "plaintext-storage": "insecure-storage", "cleartext-storage": "insecure-storage", "plaintext-passwords": "insecure-storage", "insecure-data-storage": "insecure-storage",
  "cleartext-transmission": "insecure-transport", "missing-tls": "insecure-transport", "missing-https": "insecure-transport", "insecure-communication": "insecure-transport",
  "rate-limiting": "missing-rate-limit", "missing-rate-limiting": "missing-rate-limit", "no-rate-limit": "missing-rate-limit", "brute-force": "missing-rate-limit",
  sqli: "sql-injection", sql: "sql-injection", "cross-site-scripting": "xss", "reflected-xss": "xss", "stored-xss": "xss", "dom-xss": "xss", "dom-based-xss": "xss",
  rce: "code-injection", "remote-code-execution": "code-injection", "arbitrary-code-execution": "code-injection", "os-command-injection": "command-injection", "shell-injection": "command-injection",
  deserialization: "unsafe-deserialization", "insecure-deserialization": "unsafe-deserialization", "unsafe-deserialisation": "unsafe-deserialization",
  redos: "regex-dos", "regex-denial-of-service": "regex-dos", dos: "denial-of-service", "resource-exhaustion": "denial-of-service",
  "info-leak": "information-disclosure", "information-leak": "information-disclosure", "information-exposure": "information-disclosure", "sensitive-data-exposure": "information-disclosure",
  "data-exposure": "information-disclosure", "information-leakage": "information-disclosure", "error-disclosure": "information-disclosure",
  misconfiguration: "security-misconfiguration", "security-misconfig": "security-misconfiguration", "insecure-configuration": "security-misconfiguration",
  "weak-crypto": "crypto-misuse", "weak-cryptography": "crypto-misuse", "cryptographic-failure": "crypto-misuse", "cryptographic-failures": "crypto-misuse",
  "directory-traversal": "path-traversal", lfi: "path-traversal", "local-file-inclusion": "path-traversal",
  "input-validation": "missing-validation", "improper-input-validation": "missing-validation",
  "vulnerable-dependency": "known-vulnerable-package", "outdated-dependency": "known-vulnerable-package", "vulnerable-component": "known-vulnerable-package", "vulnerable-components": "known-vulnerable-package",
  "ssrf-vulnerability": "ssrf", "server-side-request-forgery": "ssrf", "race": "race-condition",
};

/**
 * CWE to category, for CWEs that name one class. Generic CWEs (CWE-20 input validation, CWE-200 exposure,
 * CWE-16 configuration) are left out: they say too little to move a finding.
 */
export const CWE_CATEGORY: Record<number, AttackCategory> = {
  22: "path-traversal", 23: "path-traversal", 36: "path-traversal", 73: "path-traversal",
  78: "command-injection", 77: "command-injection", 88: "command-injection",
  79: "xss", 80: "xss", 83: "xss", 87: "xss",
  89: "sql-injection", 564: "sql-injection",
  94: "code-injection", 95: "code-injection", 96: "code-injection", 1336: "code-injection",
  209: "information-disclosure", 215: "information-disclosure", 532: "information-disclosure", 497: "information-disclosure", 201: "information-disclosure",
  200: "information-disclosure",
  312: "insecure-storage", 256: "insecure-storage", 257: "insecure-storage", 313: "insecure-storage", 522: "insecure-storage", 311: "insecure-storage",
  319: "insecure-transport", 523: "insecure-transport", 295: "insecure-transport", 297: "insecure-transport",
  798: "hardcoded-secret", 259: "hardcoded-secret", 321: "hardcoded-secret", 547: "hardcoded-secret", 1392: "hardcoded-secret",
  326: "crypto-misuse", 327: "crypto-misuse", 328: "crypto-misuse", 916: "crypto-misuse", 759: "crypto-misuse", 760: "crypto-misuse",
  330: "insecure-randomness", 331: "insecure-randomness", 335: "insecure-randomness", 338: "insecure-randomness", 340: "insecure-randomness", 341: "insecure-randomness", 342: "insecure-randomness", 343: "insecure-randomness",
  352: "csrf", 942: "cors", 16: "security-misconfiguration", 1004: "security-misconfiguration", 614: "security-misconfiguration", 489: "security-misconfiguration", 1021: "security-misconfiguration",
  502: "unsafe-deserialization", 918: "ssrf", 1333: "regex-dos", 1321: "prototype-pollution", 400: "denial-of-service", 770: "denial-of-service", 789: "denial-of-service", 674: "denial-of-service", 834: "denial-of-service",
  20: "missing-validation", 129: "missing-validation",
  284: "broken-access-control", 285: "broken-access-control", 306: "broken-access-control", 639: "broken-access-control", 862: "broken-access-control", 863: "broken-access-control",
  269: "broken-access-control", 266: "broken-access-control", 425: "broken-access-control", 566: "broken-access-control", 732: "broken-access-control",
  287: "broken-authentication", 288: "broken-authentication", 384: "broken-authentication", 521: "broken-authentication", 613: "broken-authentication", 204: "broken-authentication", 203: "broken-authentication", 290: "broken-authentication", 294: "broken-authentication", 620: "broken-authentication",
  915: "mass-assignment", 601: "open-redirect", 611: "xxe", 776: "xxe", 827: "xxe", 307: "missing-rate-limit", 799: "missing-rate-limit",
  494: "supply-chain", 829: "supply-chain", 1357: "known-vulnerable-package", 937: "known-vulnerable-package", 1104: "known-vulnerable-package",
  416: "use-after-free", 476: "null-pointer-deref", 787: "out-of-bounds-write", 125: "out-of-bounds-read", 119: "out-of-bounds-write",
  120: "stack-buffer-overflow", 121: "stack-buffer-overflow", 122: "heap-overflow", 190: "integer-overflow", 362: "race-condition",
};

/** CWEs that do not move a finding out of a catch-all category. */
const GENERIC_CWE = new Set([16, 20, 129, 200]);

/** An ordered rule: the first whose pattern matches names the class. */
interface Rule { category: AttackCategory; pattern: RegExp }

// Order matters: a specific class comes before a general one it would also match.
// "Hardcoded" is before "randomness" (a predictable default secret is a hardcoded one); "cookie flags" is before "transport".
const RULES: readonly Rule[] = [
  { category: "ssrf", pattern: /\bssrf\b|server[- ]side request/ },
  { category: "xxe", pattern: /\bxxe\b|xml external|external (xml )?entit|xml entit|entity expansion|\bdtd\b/ },
  { category: "csrf", pattern: /cross-site (logout|requests?)|\bcsrf\b|\bxsrf\b|cross[- ]site request forg|cross-site requests? (can|may|to)|anti-?forgery|\bcors\b.*cookie.*state/ },
  { category: "open-redirect", pattern: /open[- ]?redirect|(external|arbitrary|unrestricted) redirect|redirect endpoint|unvalidated (external )?redirect|redirects? (the )?(user|victim|browser)s? to (an )?(attacker|external|arbitrary|untrusted)/ },
  { category: "mass-assignment", pattern: /mass[- ]assign|over-?posting|(registration|signup|sign-up|sign up|self-regist\w+)[^.]{0,60}(admin|role|privilege)|(admin|role|privilege)[^.]{0,40}(self-assign|attacker-(selected|chosen|supplied)|client-supplied|request body)/ },
  { category: "broken-access-control", pattern: /(unauthenticated|public|anonymous|unprotected)[^.]{0,50}((?<!password[ -])reset|drop|wipe|destroy|delete|initiali[sz]\w*|reseed|recreate|purge)/ },
  { category: "hardcoded-secret", pattern: /hard-?coded|hard coded|embedded (secret|key|credential|password)|(static|default|known|weak|shared|example) (\w+ ){0,2}(signing |session |jwt |encryption )?(secret|signing key|secret key|api key|credentials?|password)s?\b|(seed|seeds|seeded|creates?|provisions?|restores?)[^.]{0,50}(known|default|static|publicly known)[^.]{0,30}(credential|password|account)|(known|default|static) (admin|administrator)|(secret|key|credential|password|token)s? (committed|checked in|in source|in the repository)|jwt[^.]{0,20}(example )?token in/ },
  { category: "insecure-storage", pattern: /(stor\w+|sav(es|ed|ing)|persist\w*|compar\w+|verif\w+|kept|hold\w*|written|logged)\b[^.]{0,60}\b(plain-?text|clear-?text|unencrypted|unhashed|in the clear)|(plain-?text|clear-?text|unhashed) (password|credential|secret|ssn)s?[^.]{0,30}(storage|stored|at rest|in the database)|passwords? (are |is )?not (hashed|encrypted)|without (hashing|encrypt\w+) (the )?(password|ssn)/ },
  { category: "insecure-randomness", pattern: /predictable[^.]{0,40}(token|id\b|identifier|seed|nonce|otp|code|link)|(token|reset (code|link)|otp|nonce)s? (is|are) (predictable|deterministic|guessable|derived|computed|generated)|(token|otp|nonce)[^.]{0,30}(predictable|deterministic|guessable)|(token|reset|otp)[^.]{0,40}\b(md5|sha-?1|derived from|hash of|based on)\b[^.]{0,30}(login|user|email|name|time)|math\.random|insecure(ly)? random|weak (random|prng)|guessable (token|id|reset)|non-?cryptographic (rng|random|prng)|insufficient(ly)? random/ },
  { category: "broken-authentication", pattern: /session (fixation|reuse|id reuse|is not (invalidated|regenerated|rotated))|(rotate|regenerate|renew)s? (the )?(pre-?auth\w* )?session|reuses? the pre-?auth|fixation|weak password|password (policy|complexity|length|strength|requirement)|(one|single|short|1)[- ]?(character|char|letter)s? passwords?|short passwords?|user(name)?s? enumerat|(user|account|login|email|username)s?[ -](name )?enumerat|enumerat\w+ (of )?(valid |registered |existing )?(user|login|account|email)|(reveals?|discloses?|leaks?|confirms?|indicates?|exposes?) (whether|if) (a |an )?(user|login|account|email|username)|account enumeration|distinguish\w* (an? )?(unknown|invalid|valid|existing|non-?existent|registered)[^.]{0,20}(user|login|account|email)|(wrong|incorrect) password|auth(entication)? bypass|bypass(es)? (the )?authentication|alg(orithm)? (none|confusion)|jwt (is )?(not )?(verified|validated)|session (is )?(not )?(expire|timeout)|logout (does not|doesn't|never)/ },
  { category: "missing-rate-limit", pattern: /rate[- ]?limit|brute[- ]?forc|throttl|lockout|unlimited (login|attempt|guess)|no (limit|cap) on (login|attempt|password|guess)/ },
  { category: "broken-access-control", pattern: /\bidor\b|\bbola\b|\bbfla\b|insecure direct object|broken (object|function|access)|access[- ]control|authori[sz]ation|\bauthz\b|ownership|owner check|(read|view|see|list|access|retrieve|fetch|change|modify|edit|update|delete|reset|overwrite|take over|impersonate|download)s?\b[^.]{0,40}\b(other|another|any|different|arbitrary|someone else's) (user|account|customer|member|person|employee)s?['’]?s?\b|(other|another|different) (user|account|customer|member)s?['’]s? (data|record|password|profile|secret|allocation|memo|account|order|benefit)|(lack|lacks|missing|omits?|without|no|skips?|bypass\w*|absent)[^.]{0,20}(an? )?(admin|role|auth\w*|ownership|permission|privilege|access)[^.]{0,15}(check|guard|control|verification|restriction|enforcement|middleware|required)|(does not|doesn't|never|fails to) (check|verify|enforce|validate)[^.]{0,40}(owner|role|admin|permission|privilege|identity|token)|(unauthenticated|public|anonymous|unprotected)[^.]{0,50}((?<!password[ -])reset|drop|wipe|destroy|delete|initiali[sz]\w*|reseed|recreate|purge)|privilege escalation|escalat\w+ (of )?privilege|\bcaller-(selected|supplied|chosen|controlled)|cross-(user|account|tenant)|admin-only|(available|accessible|exposed|open|visible|reachable)[^.]{0,30}(to )?(any|every|all)( \w+)? (authenticated|logged-in)|(submitted|client-supplied|path|request) (user )?(id|username)|trusts? (the )?(submitted|path|client|request)[^.]{0,30}(id|user)|ignores? the (token|session|authenticated) (owner|user)|forced browsing|per-user access|admin(istrative|istrator)? (api|route|endpoint|page|function)s?[^.]{0,40}(any|all|every|non-admin|regular|ordinary)|\bany (logged-in |authenticated |regular |ordinary )?users? (can|to)\b|(let|lets|allow|allows|permit|permits) (any|every|all) (logged-in |authenticated )?users?\b|(exposes?|grants?)[^.]{0,30}admin\w*[^.]{0,40}to (all|any|every) users?|(any|every|all|regular|ordinary|non-admin) (logged-in |authenticated )?users?\b[^.]{0,40}(admin(istrative)?|privileged|other)|non-admins? can/ },
  { category: "regex-dos", pattern: /redos|regex[- ]?dos|catastrophic|backtrack|nested[- ]quantifier|regular expression denial/ },
  { category: "supply-chain", pattern: /mutable (github )?(action|tag|version|reference)|unpinned|not pinned|pinned to (a )?(tag|branch)|(curl|wget)[^.]{0,30}\|\s*(sh|bash)|typosquat|dependency confusion|(workflow|actions?)[^.]{0,40}(secret|token)[^.]{0,30}(untrusted|fork|pull_request_target)/ },
  { category: "known-vulnerable-package", pattern: /vulnerable (version|dependency|dependencies|package|library|component)|outdated (dependency|package|version|library|component)|known (cve|vulnerabilit)|\bcve-\d{4}-\d+/ },
  { category: "sql-injection", pattern: /sql injection|\bsqli\b|(interpolat|concatenat)\w*[^.]{0,40}\bsql\b|raw sql|injectable sql/ },
  { category: "xss", pattern: /\bxss\b|cross[- ]site scripting|html injection|(unescaped|without (html )?escaping|not escaped)[^.]{0,40}(html|template|page)|reflect\w*[^.]{0,40}(into|as) (html|the page)|script injection into (the )?(page|html)/ },
  { category: "command-injection", pattern: /command injection|shell (command )?injection|os command|\bshell=true\b|unquoted[^.]{0,40}(shell|command)/ },
  { category: "path-traversal", pattern: /path traversal|directory traversal|\blfi\b|local file inclusion|arbitrary file (read|write|access)|zip slip/ },
  { category: "unsafe-deserialization", pattern: /deserial|pickle|yaml\.load|unserialize/ },
  { category: "prototype-pollution", pattern: /prototype pollution/ },
  { category: "code-injection", pattern: /code injection|\beval\b|code execution|\brce\b|template injection|\bssti\b|expression (language )?injection/ },
  { category: "cors", pattern: /\bcors\b|cross-origin resource sharing|access-control-allow-origin/ },
  { category: "security-misconfiguration", pattern: /cookies?[^.]{0,60}(secure|httponly|samesite|flag|attribute|https|transport|tls)|(secure|httponly|samesite) (flag|attribute)|runs? as root|running as root|privileged container|debug mode|debug=true|default (config|configuration)|security headers?|x-powered-by/ },
  { category: "insecure-transport", pattern: /(without|no|not|lacks?|missing|does not (enable|use|require|enforce)|doesn't (enable|use|require|enforce)|never (enables?|uses?)) (a )?(tls|https|ssl|transport (encryption|protection|security))|clear-?text (http|transmission|transport|traffic|connection)|plain-?text (http|transport|connection)|unencrypted (connection|transport|channel|http|link)|http (instead|rather)|insecure (http|transport|connection)|(over|via|on) (the )?(plain-?text )?http\b(?!s)|certificate (validation )?(is )?(disabled|not verified)|rejectunauthorized|verify=false|tls (is )?(disabled|not (enabled|enforced))/ },
  { category: "crypto-misuse", pattern: /weak (hash|cipher|crypto\w*|encryption|algorithm|key)|\bmd5\b|\bsha-?1\b|\becb\b|\bdes\b|insecure (hash|cipher|crypto\w*)|unsalted|key size|iv reuse|static iv|nonce reuse/ },
  { category: "denial-of-service", pattern: /denial[- ]of[- ]service|\bdos\b|exhaust|unbounded|without (a |any )?(size |memory |rate )?(limit|bound|cap)|no (size |memory |upper )?(limit|bound|cap)\b|(grow|fill|accumulate|buffered)[^.]{0,50}(without (a )?(bound|limit)|memory|session store|unbounded)|event-loop|block the event|crash(es)? the (service|server|process)|infinite loop/ },
  { category: "information-disclosure", pattern: /stack ?trace|verbose error|error messages?[^.]{0,30}(reveal|expos|leak|disclos)|(expos|disclos|leak|reveal|dump|return|print|log)\w*[^.]{0,60}(password|secret|token|email|credential|pii|hash|sensitive|configuration|private|api key|ssn)|sensitive (data|information)|debug (endpoint|route|page)|source code (is )?(exposed|disclosed)/ },
];

const normalizeLabel = (value: string): string => value.trim().toLowerCase().replace(/[\s_]+/g, "-");

function cweList(value: unknown): number[] {
  const out: number[] = [];
  for (const entry of Array.isArray(value) ? value : [value]) {
    if (typeof entry === "number" && Number.isInteger(entry)) out.push(entry);
    else if (typeof entry === "string") for (const m of entry.matchAll(/cwe[-_/ :]*0*(\d{1,5})\b/gi)) out.push(Number(m[1]));
  }
  return out;
}

const textMatch = (text: string): AttackCategory | undefined => RULES.find(rule => rule.pattern.test(text))?.category;

/** What a category is for: a plain-language lookup of a category from free text only (used by the benchmark and importers). */
export function categoryFromText(text: string): AttackCategory | undefined {
  return textMatch(text.toLowerCase());
}

/**
 * The category a person's words name: one of our ids, an alias, or free text run through the same keyword rules.
 * Undefined when nothing matches. Used for the vectors a repository's SECURITY.md declares in or out of scope.
 */
export function categoryFromLabel(text: string): AttackCategory | undefined {
  const label = normalizeLabel(text);
  if (isAttackCategory(label)) return label;
  const alias = CATEGORY_ALIASES[label];
  if (alias) return alias;
  return textMatch(text.toLowerCase().replace(/[-_]+/g, " "));
}

export interface FindingClassification {
  category: AttackCategory;
  /** The model's label when it was not one of ours. */
  unknownLabel?: string;
  /** The category the model gave when it was one of ours and a title or CWE named a better one. */
  refinedFrom?: AttackCategory;
}

/**
 * The category a finding should carry. Never throws and always returns one of our categories: a label we do not
 * have is mapped to the closest one and keeps the label in `unknownLabel`.
 */
export function classifyFinding(input: { category?: unknown; title?: unknown; description?: unknown; cwe?: unknown }): FindingClassification {
  const raw = typeof input.category === "string" ? input.category.trim() : "";
  const label = raw ? normalizeLabel(raw) : "";
  const title = typeof input.title === "string" ? input.title.toLowerCase() : "";
  const description = typeof input.description === "string" ? input.description.toLowerCase() : "";
  const given: AttackCategory | undefined = isAttackCategory(label) ? label : CATEGORY_ALIASES[label];
  const unknownLabel = raw && !isAttackCategory(label) && !CATEGORY_ALIASES[label] ? raw : undefined;
  const aliasOnly = raw && !isAttackCategory(label) && CATEGORY_ALIASES[label] ? raw : undefined;

  // 1 and 2: a specific category, or an alias for one, stays.
  if (given && !CATCH_ALL.has(given)) return { category: given, ...(aliasOnly ? { unknownLabel: aliasOnly } : {}) };

  // 3: a CWE that names one class.
  const fromCwe = cweList(input.cwe).filter(n => !GENERIC_CWE.has(n)).map(n => CWE_CATEGORY[n]).find(Boolean);
  // 4: the title, then the label's own words. 5: the description, only when the model told us nothing useful.
  const specific = fromCwe ?? textMatch(title) ?? (unknownLabel ? textMatch(label.replace(/-/g, " ")) : undefined) ?? (!given || given === "other" ? textMatch(description) : undefined);
  const category = specific ?? given ?? "other";
  const out: FindingClassification = { category };
  if (unknownLabel) out.unknownLabel = unknownLabel;
  else if (aliasOnly) out.unknownLabel = aliasOnly;
  if (given && given !== category && !aliasOnly) out.refinedFrom = given;
  return out;
}
