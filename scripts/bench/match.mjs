// Pure matching of scan findings against a fixture's answer key. No I/O.
export const LINE_TOLERANCE = 5;
export const DECOY_TOLERANCE = 2;
// Strict oracle (hard benchmark): an item with `oracle` is credited only when the finding sits within `lineSlack` lines
// (default ORACLE_SLACK) of the item or one of its `alsoAt` spots, belongs to one of the item's families, AND its title or
// description matches one of the item's `oracle.mention` patterns (the route, entity or sink the bug is about). Proximity
// alone never credits it, so a finding about the neighbouring route cannot be credited to this one.
export const ORACLE_SLACK = 3;
// Families that count as a claim about access control or business rules in a file known to be correct.
const CLEAN_FAMILIES = ["authz", "authn", "business-logic", "mass-assignment"];

const mentionCache = new Map();
function mentionRegex(source) {
  if (!mentionCache.has(source)) mentionCache.set(source, new RegExp(source, "i"));
  return mentionCache.get(source);
}
/** True when the item has no oracle, or the finding's title/description matches one of its mention patterns. */
export function mentions(item, finding) {
  const list = item.oracle?.mention;
  if (!list?.length) return true;
  const text = `${finding.title ?? ""}\n${finding.description ?? ""}`;
  return list.some((source) => mentionRegex(source).test(text));
}

// Category families: an answer item matches a finding when the finding belongs to the item's family.
// A finding can belong to several (a hardcoded key is both a secret and, often, filed as weak crypto).
const FAMILY_PATTERNS = {
  sqli: /sql[-_ ]?inj|sqli|sql query|nosql|\$where/i,
  "command-injection": /command[-_ ]?inj|code[-_ ]?inj|shell|os command|\bexec\b|\beval\b|remote code|\brce\b/i,
  "path-traversal": /path[-_ ]?trav|directory trav|\blfi\b|arbitrary file (read|access)|file inclusion/i,
  secret: /secret|hard-?coded|credential|api[-_ ]?key|password|token|private key|information[-_ ]?disclosure/i,
  ssrf: /ssrf|server[-_ ]side request/i,
  deserialization: /deserial|pickle|yaml\.load|unsafe[-_ ]?load/i,
  "weak-crypto": /crypto|\bmd5\b|sha-?1\b|\becb\b|\brsa\b|\bkdf\b|weak (hash|cipher|key)|key size|quantum|pkcs|\bdes\b|unsalted/i,
  xss: /\bxss\b|cross[-_ ]site scripting|html injection|template\.html|unescaped|unsanitized html/i,
  "prompt-injection": /prompt[-_ ]?inj|indirect injection|excessive[-_ ]agency|tool[-_ ]misuse|jailbreak|untrusted (content|text|input|ticket).*(model|prompt|tool|command|shell)|model-controlled|shell tool|agent.*(shell|command)/i,
  authz: /authz|(other|another|any|different) users?(['’]s?)?\b|self-assign|without (an? )?(auth|admin|ownership)|no (admin|ownership) (check|guard)|authori[sz]ation|access[-_ ]control|\bidor\b|insecure direct|missing (auth|ownership|permission|admin)|broken (access|object)|privilege|forced browsing|unauthori[sz]ed/i,
  "output-handling":/output[-_ ]?(handling|manipulation)|insecure output|model output|llm output|improper output|(agent|model|llm|assistant)[a-z ]*(reply|response|output).*(html|escap|markup)|unescaped (agent|model|llm|assistant)/i,
  "iac-network": /security[-_ ]group|subnet|route[-_ ]?table|\broute\b|ingress|0\.0\.0\.0|internet gateway|network (exposure|exposed)|publicly (accessible|exposed|reachable)|public (subnet|route|access)|open to the (internet|world)|exposed to the internet/i,
  "iac-iam": /\biam\b|pass-?role|privilege escalation|wildcard (action|resource|permission)|over-?(permissive|broad) (role|polic|permission)|assume-?role/i,
  "iac-privilege": /privileged|host-?path|docker\.sock|docker socket|host-?(network|pid|ipc)|container escape|node (takeover|compromise)|service-?account|security-?context|run(s|ning)? as root/i,
  "iac-supply": /unpinned|not pinned|pipe[sd]? (into|to) (sh|bash|a shell)|curl[^|]*\|\s*(sh|bash)|install script|:latest|latest tag|remote script|download(s|ed)? and (run|execut)/i,
  "ci-injection": /(script|shell)[-_ ]?inj|workflow[-_ ]?inj|expression[-_ ]?inj|pull_request_target|pwn[-_ ]?request|untrusted (checkout|code|pull)|github\.event|(workflow|github actions?|pull[-_ ]request|pr title).*(inject|untrusted)|inject.*(workflow|github actions?|pull[-_ ]request|pr title)/i,
  // Families for the real-application answer keys (web apps documented by their projects).
  xxe: /\bxxe\b|xml external|external entit/i,
  csrf: /\bcsrf\b|cross[-_ ]site request|anti-?csrf/i,
  "open-redirect": /open[-_ ]?redirect|unvalidated redirect|redirect/i,
  redos: /redos|regex[-_ ]?dos|regular expression denial|catastrophic backtrack|nested quantifier|regex.*denial|denial.*regex/i,
  "vuln-dependency": /vulnerable (dependenc|component|librar|package|version)|outdated|known vulnerab|\bcve-\d|dependenc|supply[-_ ]chain/i,
  authn: /session (fixation|management|regenerat|hijack)|fixation|httponly|cookie (flag|attribute|secur)|insecure cookie|session cookies?[^.]*(secure|https|transport|httponly)|cookies? (are |is )?(not )?marked|weak password|password (policy|complexity|strength|requirement)|(user(name)?|account|password) enumeration|user enumeration/i,
  transport: /insecure (http|transport|connection)|cleartext|plain-?text (http|transport)|unencrypted|without (tls|https|ssl)|no (tls|https)|http (instead|rather)|\bhttps\b/i,
  misconfig: /stack ?trace|x-powered-by|verbose error|debug mode|debug=true|misconfig|security header|query logging|logging (of )?(sensitive|queries)/i,
  "rate-limit": /rate[-_ ]?limit|brute[-_ ]?force|resource consumption|throttl|lockout/i,
  "business-logic": /business[-_ ]?logic|missing[-_ ]validation|logic (flaw|bug|error)|state (check|machine|transition)|workflow|maker[-_ ]checker|separation of dut|four[-_ ]eyes|over-?refund|refund|replay|not bound|unbound|binding/i,
  "mass-assignment": /mass[-_ ]assign|over-?posting|admin (flag|field|role).*(register|request|body)/i,
};
export const FAMILIES = Object.keys(FAMILY_PATTERNS);

// What each engine category (packages/engine/src/shared/finding-category.ts) means in family terms. A finding whose
// category is one of these belongs to those families whatever its title says. Keep this in step with the engine list.
export const CATEGORY_FAMILIES = {
  "broken-access-control": ["authz"],
  "broken-authentication": ["authn"],
  "mass-assignment": ["mass-assignment", "authz"],
  csrf: ["csrf"],
  "open-redirect": ["open-redirect"],
  xxe: ["xxe"],
  "hardcoded-secret": ["secret"],
  "insecure-randomness": ["weak-crypto", "authn"],
  "insecure-storage": ["secret", "weak-crypto"],
  "insecure-transport": ["transport"],
  "missing-rate-limit": ["rate-limit"],
  "missing-validation": ["business-logic"],
  "sql-injection": ["sqli"],
  "command-injection": ["command-injection"],
  "code-injection": ["command-injection"],
  "path-traversal": ["path-traversal"],
  ssrf: ["ssrf"],
  "unsafe-deserialization": ["deserialization"],
  xss: ["xss"],
  "regex-dos": ["redos"],
  "known-vulnerable-package": ["vuln-dependency"],
  "supply-chain": ["vuln-dependency", "iac-supply"],
  "information-disclosure": ["secret"],
  "crypto-misuse": ["weak-crypto"],
};

/** The set of families a finding belongs to: category and title first, the description only when those say nothing. */
export function familiesOf(finding) {
  // A saved scan keeps the families it was scored with, so a report can be scored again against a corrected key.
  if (Array.isArray(finding.families)) return new Set(finding.families);
  const head = `${finding.category ?? ""} ${finding.title ?? ""}`;
  const found = new Set(CATEGORY_FAMILIES[finding.category] ?? []);
  for (const family of FAMILIES) if (FAMILY_PATTERNS[family].test(head)) found.add(family);
  if (!found.size) for (const family of FAMILIES) if (FAMILY_PATTERNS[family].test(finding.description ?? "")) found.add(family);
  return found;
}

/** An item names one family or a list of them (a documented class that several scan labels fit). */
export const itemCategories = (item) => (Array.isArray(item.category) ? item.category : [item.category]);

const normPath = (p) => String(p ?? "").replace(/\\/g, "/").replace(/^\.?\//, "");

/** Same file: equal, or one is a path-suffix of the other (a report may be relative to the scan root or absolute). */
export function samePath(a, b) {
  const x = normPath(a);
  const y = normPath(b);
  if (!x || !y) return false;
  return x === y || x.endsWith(`/${y}`) || y.endsWith(`/${x}`);
}

/** Distance in lines between two inclusive ranges; 0 when they overlap. */
export function lineDistance(aStart, aEnd, bStart, bEnd) {
  const as = aStart, ae = aEnd ?? aStart, bs = bStart, be = bEnd ?? bStart;
  if (ae < bs) return bs - ae;
  if (be < as) return as - be;
  return 0;
}

function locate(finding) {
  const loc = finding.location;
  if (!loc || typeof loc.path !== "string" || !Number.isFinite(loc.startLine)) return undefined;
  return { path: loc.path, start: loc.startLine, end: Number.isFinite(loc.endLine) ? loc.endLine : loc.startLine };
}

/**
 * Score one scan's findings against an answer key.
 * - A finding matches an item when path, line (within `tolerance`) and family agree. The closest item wins; one finding
 *   credits one item. An item is found when any finding matches it.
 * - A finding that matches no item but sits on a decoy (within DECOY_TOLERANCE) is a decoy hit: a false positive.
 * - In a clean fixture every finding is a false positive.
 * - Anything else is "unmatched": not a planted bug and not a decoy. It may be a real extra issue or noise, so it is
 *   reported separately and is not counted as a false positive in a fixture that has planted bugs.
 */
export function scoreFindings(answer, findings, { tolerance = LINE_TOLERANCE } = {}) {
  const items = answer.items ?? [];
  const decoys = answer.decoys ?? [];
  const where = findings.map(locate);
  const families = findings.map(familiesOf);
  // Candidate items per finding, closest first. Matching is one-to-one (Kuhn's augmenting paths), so two findings cannot
  // both vouch for one item, and a finding near two items is paired so that the most items are found.
  const candidates = findings.map((_, i) => {
    const w = where[i];
    if (!w) return [];
    // An item may name other places the same flaw shows (`alsoAt`): the sink in a helper file, the route that reaches it.
    const spots = (item) => [item, ...(item.alsoAt ?? [])];
    return items
      .map((item, index) => ({ index, tol: item.oracle ? item.oracle.lineSlack ?? ORACLE_SLACK : tolerance, distance: itemCategories(item).some((c) => families[i].has(c)) && mentions(item, findings[i]) ? Math.min(...spots(item).map((s) => (samePath(w.path, s.path) ? lineDistance(w.start, w.end, s.startLine, s.endLine) : Infinity))) : Infinity }))
      .filter((c) => c.distance <= c.tol)
      .sort((a, b) => a.distance - b.distance)
      .map((c) => c.index);
  });
  const owner = new Array(items.length).fill(-1);
  const tryAssign = (f, seen) => {
    for (const it of candidates[f]) {
      if (seen.has(it)) continue;
      seen.add(it);
      if (owner[it] === -1 || tryAssign(owner[it], seen)) { owner[it] = f; return true; }
    }
    return false;
  };
  for (let f = 0; f < findings.length; f++) tryAssign(f, new Set());
  const credited = new Set(owner.filter((f) => f !== -1));
  const label = (f) => findings[f].id ?? findings[f].title;
  const decoyHits = [];
  const cleanHits = [];
  const unmatched = [];
  const falsePositives = [];
  findings.forEach((finding, f) => {
    // A duplicate of an item another finding already credits is neither noise nor a miss.
    if (credited.has(f) || candidates[f].length) return;
    const w = where[f];
    // A decoy that names `category` is hit only by a finding of that family; one that does not is hit by position alone.
    const decoy = w && decoys.find((d) => samePath(w.path, d.path) && lineDistance(w.start, w.end, d.startLine, d.endLine) <= DECOY_TOLERANCE && (!d.category || itemCategories(d).some((c) => families[f].has(c))));
    // Files verified correct by construction (`cleanPaths`): an authorization-class finding there is a false positive.
    const clean = !decoy && w && (answer.cleanPaths ?? []).some((p) => samePath(w.path, p)) && CLEAN_FAMILIES.some((c) => families[f].has(c));
    if (decoy) decoyHits.push({ finding: label(f), decoy: decoy.id });
    else if (clean) cleanHits.push({ finding: label(f), path: w.path });
    else unmatched.push({ finding: label(f), title: finding.title, located: Boolean(w) });
    if (answer.clean || decoy || clean) falsePositives.push(label(f));
  });
  if (answer.clean) for (let f = 0; f < findings.length; f++) if (credited.has(f) || candidates[f].length) falsePositives.push(label(f));
  // Findings that sit on an item (path and lines agree) but whose label names no family of it. They are not credited;
  // a person reads them, so the report can say how much of the recall gap is wording.
  const nearMisses = [];
  findings.forEach((finding, f) => {
    const w = where[f];
    if (!w || credited.has(f) || candidates[f].length) return;
    items.forEach((item, i) => {
      if (owner[i] !== -1) return;
      const d = Math.min(...[item, ...(item.alsoAt ?? [])].map((s) => (samePath(w.path, s.path) ? lineDistance(w.start, w.end, s.startLine, s.endLine) : Infinity)));
      if (d <= tolerance) nearMisses.push({ finding: label(f), item: item.id, distance: d });
    });
  });
  const foundIds = items.filter((_, i) => owner[i] !== -1).map((i) => i.id);
  return {
    planted: items.length,
    found: foundIds.length,
    foundIds,
    missedIds: items.filter((_, i) => owner[i] === -1).map((i) => i.id),
    recall: items.length ? foundIds.length / items.length : null,
    findings: findings.length,
    falsePositives: falsePositives.length,
    decoyHits,
    cleanHits,
    unmatched,
    nearMisses,
  };
}

export function mean(values) {
  return values.length ? values.reduce((a, b) => a + b, 0) / values.length : null;
}

/** Population spread as [min, max]; with 2 repeats this is the whole range. */
export function spread(values) {
  return values.length ? [Math.min(...values), Math.max(...values)] : null;
}

/** Check an answer key is well-formed. Returns a list of problems (empty when valid). */
export function validateAnswer(answer, { fileLines } = {}) {
  const problems = [];
  if (!answer || typeof answer !== "object") return ["answer is not an object"];
  if (!answer.fixture) problems.push("missing fixture");
  if (!Array.isArray(answer.items)) problems.push("items must be a list");
  if (!Array.isArray(answer.decoys)) problems.push("decoys must be a list");
  if (answer.clean && answer.items?.length) problems.push("a clean fixture has no planted items");
  if (!answer.clean && !answer.items?.length) problems.push("a non-clean fixture needs at least one item");
  const ids = new Set();
  for (const entry of [...(answer.items ?? []), ...(answer.decoys ?? [])]) {
    if (!entry.id || ids.has(entry.id)) problems.push(`duplicate or missing id: ${entry.id}`);
    ids.add(entry.id);
    if (!entry.path) problems.push(`${entry.id}: missing path`);
    if (!Number.isInteger(entry.startLine) || !Number.isInteger(entry.endLine) || entry.endLine < entry.startLine) problems.push(`${entry.id}: bad line range`);
    const lines = fileLines?.[entry.path];
    if (lines !== undefined && entry.endLine > lines) problems.push(`${entry.id}: line ${entry.endLine} is past the end of ${entry.path} (${lines} lines)`);
    if (fileLines && lines === undefined) problems.push(`${entry.id}: file ${entry.path} not found`);
    for (const spot of entry.alsoAt ?? []) {
      const spotLines = fileLines?.[spot.path];
      if (!spot.path || !Number.isInteger(spot.startLine) || !Number.isInteger(spot.endLine) || spot.endLine < spot.startLine) problems.push(`${entry.id}: bad alsoAt entry`);
      else if (fileLines && spotLines === undefined) problems.push(`${entry.id}: alsoAt file ${spot.path} not found`);
      else if (spotLines !== undefined && spot.endLine > spotLines) problems.push(`${entry.id}: alsoAt line ${spot.endLine} is past the end of ${spot.path} (${spotLines} lines)`);
    }
  }
  for (const item of answer.items ?? []) {
    for (const c of itemCategories(item)) if (!FAMILIES.includes(c)) problems.push(`${item.id}: unknown category ${c} (known: ${FAMILIES.join(", ")})`);
    if (!item.description) problems.push(`${item.id}: missing description`);
    for (const source of item.oracle?.mention ?? []) { try { new RegExp(source, "i"); } catch { problems.push(`${item.id}: bad oracle.mention pattern ${source}`); } }
    if (item.oracle && !item.oracle.mention?.length) problems.push(`${item.id}: oracle needs at least one mention pattern`);
  }
  for (const decoy of answer.decoys ?? []) for (const c of decoy.category === undefined ? [] : itemCategories(decoy)) if (!FAMILIES.includes(c)) problems.push(`${decoy.id}: unknown category ${c}`);
  for (const p of answer.cleanPaths ?? []) {
    if (fileLines && fileLines[p] === undefined) problems.push(`cleanPaths: file ${p} not found`);
  }
  return problems;
}
