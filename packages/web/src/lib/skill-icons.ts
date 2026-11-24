/** Icon for a skill tile. Pure: names only, so the component map lives next to the tile and tree-shakes. */
export type SkillIconName =
  | "Terminal" | "Database" | "Braces" | "Binary" | "Eye" | "Bug" | "Timer" | "Route" | "FolderTree" | "Network" | "Waypoints"
  | "Globe" | "Cpu" | "Blocks" | "Lock" | "KeyRound" | "UserCheck" | "Cloud" | "Boxes" | "Package" | "Radar" | "Map"
  | "Bot" | "BotMessageSquare" | "BrainCircuit" | "Sparkles" | "ShieldAlert" | "MessageSquareWarning" | "Plug"
  | "FileText" | "Siren" | "ListChecks" | "Wrench" | "BadgeCheck" | "Workflow" | "GitCompareArrows" | "FileSearch"
  | "ScanSearch" | "Layers" | "Files" | "Hammer" | "BookOpen";

/** What a skill with no match shows. Never used by a family. */
export const DEFAULT_SKILL_ICON: SkillIconName = "BookOpen";

type Family = { icon: SkillIconName; ids: readonly string[]; words: readonly string[] };

/** One icon per family. The `ids` are the built-in skills, the `words` place any other skill. Order matters: first match wins. */
export const SKILL_FAMILIES: readonly Family[] = [
  { icon: "Terminal", ids: ["command-injection"], words: ["command injection", "shell", "rce"] },
  { icon: "Database", ids: ["sqli-advanced", "structural-sqli"], words: ["sql", "sqli", "database", "nosql", "orm"] },
  { icon: "Braces", ids: ["ssti-exploitation"], words: ["ssti", "template", "xss", "script injection"] },
  { icon: "Binary", ids: ["deserialization-chains"], words: ["deserialization", "serialization", "pickle", "gadget"] },
  { icon: "Eye", ids: ["blind-exploitation"], words: ["blind", "out-of-band", "oast"] },
  { icon: "Bug", ids: ["prototype-pollution"], words: ["pollution", "prototype", "bug", "fuzz"] },
  { icon: "Timer", ids: ["race-condition"], words: ["race", "toctou", "concurrency"] },
  { icon: "Route", ids: ["request-smuggling"], words: ["smuggling", "proxy", "desync", "redirect"] },
  { icon: "FolderTree", ids: ["path-traversal"], words: ["traversal", "lfi", "directory", "upload"] },
  { icon: "Network", ids: ["ssrf-bypass"], words: ["ssrf", "network", "dns", "port"] },
  { icon: "Waypoints", ids: ["graphql-introspection", "scope-interview"], words: ["graphql", "scope", "interview", "intake"] },
  { icon: "Globe", ids: ["nextjs-appsec", "python-web-appsec", "supabase-appsec", "wordpress-deep"], words: ["web", "browser", "http", "cors", "csrf", "cookie", "frontend"] },
  { icon: "Cpu", ids: ["native-memory-safety"], words: ["memory", "native", "buffer", "firmware"] },
  { icon: "Blocks", ids: ["cardano-eutxo-validators"], words: ["blockchain", "smart contract", "solidity", "validator", "web3"] },
  { icon: "UserCheck", ids: ["jwt-attacks"], words: ["auth", "jwt", "oauth", "session", "login", "identity", "access control", "permission", "rbac", "idor"] },
  { icon: "KeyRound", ids: ["secrets-hunting"], words: ["secret", "secrets", "credential", "credentials", "token", "api key", "password"] },
  { icon: "Lock", ids: ["crypto-misuse", "crypto-migration"], words: ["crypto", "encryption", "tls", "cipher", "hash", "certificate"] },
  { icon: "Cloud", ids: ["cloud-iac-review"], words: ["cloud", "aws", "gcp", "azure", "kubernetes", "serverless"] },
  { icon: "Boxes", ids: ["iac-review"], words: ["iac", "terraform", "container", "docker", "helm", "infrastructure"] },
  { icon: "Package", ids: ["artifact-scan", "dependency-reachability"], words: ["supply chain", "sbom", "dependency", "dependencies", "package", "artifact", "npm", "pypi", "vendor"] },
  { icon: "Radar", ids: ["attack-surface-diff"], words: ["attack surface", "recon", "reconnaissance", "inventory"] },
  { icon: "Map", ids: ["threat-model"], words: ["threat model", "threat", "stride", "architecture", "data flow"] },
  { icon: "BotMessageSquare", ids: ["llm-prompt-layer-write"], words: ["chatbot", "prompt layer", "system prompt"] },
  { icon: "MessageSquareWarning", ids: ["llm-prompt-injection"], words: ["prompt injection", "jailbreak"] },
  { icon: "BrainCircuit", ids: ["llm-rag-poisoning"], words: ["rag", "embedding", "vector", "poisoning"] },
  { icon: "Sparkles", ids: ["llm-insecure-output-handling"], words: ["output handling", "generative"] },
  { icon: "ShieldAlert", ids: ["llm-excessive-agency"], words: ["excessive agency", "agency"] },
  { icon: "Plug", ids: ["mcp-server-review"], words: ["mcp", "plugin", "connector"] },
  { icon: "Bot", ids: ["llm-app-review"], words: ["llm", "ai", "gpt", "copilot"] },
  { icon: "FileText", ids: ["advisory-disclosure"], words: ["report", "disclosure", "advisory", "evidence", "writeup", "cve"] },
  { icon: "Siren", ids: ["incident-triage"], words: ["incident", "triage", "alert", "oncall", "response"] },
  { icon: "ListChecks", ids: ["policy-check"], words: ["policy", "compliance", "checklist", "standard", "audit"] },
  { icon: "Wrench", ids: ["fix-finding"], words: ["fix", "patch", "remediation", "remediate"] },
  { icon: "BadgeCheck", ids: ["verify-finding"], words: ["verify", "validate", "confirm", "reproduce"] },
  { icon: "Workflow", ids: ["workflow-hardening"], words: ["workflow", "pipeline", "actions", "ci", "cd"] },
  { icon: "GitCompareArrows", ids: ["pr-diff-review"], words: ["diff", "pull request", "pr", "commit", "merge"] },
  { icon: "FileSearch", ids: ["assumption-mining"], words: ["assumption", "invariant", "code review", "review"] },
  { icon: "ScanSearch", ids: ["scan"], words: ["scan", "scanner", "sast", "static analysis"] },
  { icon: "Layers", ids: ["seedless-depth-review"], words: ["depth", "seedless", "layers"] },
  { icon: "Files", ids: ["variant-hunting"], words: ["variant", "similar", "sibling"] },
  { icon: "Hammer", ids: ["develop-this-app"], words: ["develop", "build", "implement", "feature"] },
];

const BY_ID = new Map(SKILL_FAMILIES.flatMap(family => family.ids.map(id => [id, family.icon] as const)));
const escape = (word: string) => word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const RULES = SKILL_FAMILIES.map(family => ({ icon: family.icon, test: new RegExp(`(?:^|[^a-z0-9])(?:${family.words.map(escape).join("|")})(?![a-z0-9])`) }));

type SkillLike = { id: string; name: string; scope: string; category?: string };

/** Icon from keywords in the name, id and category. The summary is ignored: its filler words ("agent", "review") match too much. Undefined when no rule matches. Words match whole words, so "ai" does not match "email". */
export function matchSkillIcon(skill: Pick<SkillLike, "id" | "name" | "category">): SkillIconName | undefined {
  const text = `${skill.name} ${skill.id.replace(/^builtin\//, "")} ${skill.category ?? ""}`.toLowerCase().replace(/[-_/]+/g, " ");
  return RULES.find(rule => rule.test.test(text))?.icon;
}

/** The tile icon of a skill: an explicit pick for a known built-in, else keyword rules, else the neutral default. */
export function skillIconName(skill: SkillLike): SkillIconName {
  if (skill.scope === "builtin") { const known = BY_ID.get(skill.id.replace(/^builtin\//, "")); if (known) return known; }
  return matchSkillIcon(skill) ?? DEFAULT_SKILL_ICON;
}
