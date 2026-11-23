import { describe, expect, it } from "vitest";
import { ATTACK_CATEGORIES, CATEGORY_ALIASES, CWE_CATEGORY, classifyFinding, isAttackCategory } from "./finding-category.js";
import { findingSchema } from "./finding-schemas.js";

// Titles from real scans of three public vulnerable applications. Each row is the category the model gave, the title,
// and the category a person assigned by reading it (the labelling rules are in docs: name the root cause, not the symptom).
// Rows the labeller found ambiguous (a plaintext-password debug route, a cookie flag) are left out.
const LABELLED: Array<[string, string, string]> = [
  ["missing-validation", "Authenticated password update ignores the token owner and trusts the path username", "broken-access-control"],
  ["missing-validation", "User edit trusts the submitted user ID", "broken-access-control"],
  ["missing-validation", "Authenticated non-admins can change any user's benefits start date", "broken-access-control"],
  ["missing-validation", "Admin user listing and API lack role authorization", "broken-access-control"],
  ["missing-validation", "Unauthenticated registration allows self-assigned administrator accounts", "mass-assignment"],
  ["missing-validation", "Password update route lets any authenticated user reset another account", "broken-access-control"],
  ["missing-validation", "Authenticated user can read another user's allocations (BOLA)", "broken-access-control"],
  ["missing-validation", "Authenticated users can read other users' book secrets", "broken-access-control"],
  ["missing-validation", "Unauthenticated signup CSRF can log victims into an attacker-controlled account", "csrf"],
  ["missing-validation", "Allocations endpoint exposes other users' allocation records", "broken-access-control"],
  ["missing-validation", "Benefits routes let any logged-in user view and change users' benefit start dates", "broken-access-control"],
  ["missing-validation", "Authenticated users can read other users' allocations", "broken-access-control"],
  ["missing-validation", "Unauthenticated registration permits attacker-created administrators", "mass-assignment"],
  ["missing-validation", "Authenticated-only guard exposes administrative user API to all users", "broken-access-control"],
  ["missing-validation", "Profile update lacks CSRF verification", "csrf"],
  ["missing-validation", "Signup accepts one-character passwords", "broken-authentication"],
  ["information-disclosure", "Database reset seeds a known administrator credential", "hardcoded-secret"],
  ["information-disclosure", "Memo listing does not enforce per-user access", "broken-access-control"],
  ["information-disclosure", "User passwords stored and compared in plaintext", "insecure-storage"],
  ["information-disclosure", "Public user listing discloses account email addresses", "information-disclosure"],
  ["information-disclosure", "Public user-list endpoint discloses account email addresses", "information-disclosure"],
  ["information-disclosure", "Signup stores user passwords in plaintext", "insecure-storage"],
  ["information-disclosure", "Public debug endpoint discloses users' plaintext passwords", "information-disclosure"],
  ["information-disclosure", "Startup logs dump configuration secrets", "information-disclosure"],
  ["information-disclosure", "Public debug endpoint exposes every user's plaintext password", "information-disclosure"],
  ["security-misconfiguration", "Production uses a hard-coded Express session signing secret", "hardcoded-secret"],
  ["security-misconfiguration", "Hardcoded weak JWT signing key", "hardcoded-secret"],
  ["security-misconfiguration", "Static seeded admin credentials permit account takeover", "hardcoded-secret"],
  ["security-misconfiguration", "Predictable default session signing secret is used in production config", "hardcoded-secret"],
  ["security-misconfiguration", "Hardcoded Flask JWT signing key", "hardcoded-secret"],
  ["security-misconfiguration", "Database initialization creates an administrator with known credentials", "hardcoded-secret"],
  ["security-misconfiguration", "Seeded administrator account has a publicly known password", "hardcoded-secret"],
  ["security-misconfiguration", "Container runs the API as root", "security-misconfiguration"],
  ["security-misconfiguration", "MySQL connection does not enable TLS", "insecure-transport"],
  ["other", "Unauthenticated open redirect via /app/redirect", "open-redirect"],
  ["other", "Authenticated user can reset another account's password", "broken-access-control"],
  ["other", "Successful login reuses the pre-authentication session ID", "broken-authentication"],
  ["other", "Unauthenticated password reset via predictable MD5(login) token", "insecure-randomness"],
  ["other", "Predictable reset token permits password-reset token forgery", "insecure-randomness"],
  ["other", "Authenticated user can change another user's password", "broken-access-control"],
  ["other", "Bulk XML import enables entity expansion on uploaded XML", "xxe"],
  ["other", "Allocation lookup accepts caller-selected user IDs", "broken-access-control"],
  ["other", "Unauthenticated open redirect via query URL", "open-redirect"],
  ["other", "Unauthenticated password reset via predictable MD5 token", "insecure-randomness"],
  ["other", "Unvalidated external redirect in GET /learn", "open-redirect"],
  ["other", "Cross-site requests can invoke authenticated state-changing routes", "csrf"],
  ["other", "Authenticated users can read other users' allocation data by changing the path ID", "broken-access-control"],
  ["sql-injection", "SQL injection in public username lookup", "sql-injection"],
  ["sql-injection", "Unauthenticated username lookup constructs injectable SQL", "sql-injection"],
  ["sql-injection", "SQL injection in public user lookup", "sql-injection"],
  ["sql-injection", "Unauthenticated SQL injection in user lookup", "sql-injection"],
  ["xss", "Research endpoint reflects fetched HTML into authenticated origin", "xss"],
  ["xss", "Benefits page renders user-controlled names without HTML escaping", "xss"],
  ["xss", "Unauthenticated login and signup inputs are reflected as HTML (reflected XSS)", "xss"],
  ["xss", "Login username is reflected into an unescaped HTML attribute", "xss"],
  ["xss", "Profile update reflects attacker-controlled first name into HTML without escaping", "xss"],
  ["xss", "Stored XSS through imported product fields", "xss"],
  ["ssrf", "Research proxy permits server-side requests to attacker-selected URLs and reflects response as HTML", "ssrf"],
  ["ssrf", "Authenticated SSRF via /research url parameter", "ssrf"],
  ["ssrf", "Authenticated research route permits SSRF with response relay", "ssrf"],
  ["code-injection", "Authenticated contributions update executes submitted JavaScript with eval", "code-injection"],
  ["code-injection", "Allocations threshold is interpolated into executable MongoDB $where code", "code-injection"],
  ["code-injection", "Unauthenticated JavaScript evaluation allows remote code execution in contributions update", "code-injection"],
  ["code-injection", "User-controlled mathjs eval reaches vulnerable expression evaluator", "code-injection"],
  ["code-injection", "Arbitrary JavaScript execution in contribution updates", "code-injection"],
  ["regex-dos", "Unbounded nested-quantifier regex causes profile-update ReDoS", "regex-dos"],
  ["regex-dos", "Catastrophic backtracking in profile routing-number validation", "regex-dos"],
  ["regex-dos", "Nested-quantifier bank-routing validation permits event-loop denial of service", "regex-dos"],
  ["command-injection", "Authenticated ping endpoint permits shell command injection", "command-injection"],
  ["command-injection", "Command injection in authenticated ping endpoint", "command-injection"],
  ["command-injection", "Authenticated command injection in /app/ping", "command-injection"],
  ["command-injection", "Shell command injection in authenticated ping endpoint", "command-injection"],
  ["unsafe-deserialization", "Unsafe node-serialize deserialization enables code execution", "unsafe-deserialization"],
  ["unsafe-deserialization", "Unsafe deserialization of uploaded product file permits code execution", "unsafe-deserialization"],
  ["unsafe-deserialization", "Unsafe node-serialize deserialization in legacy product upload", "unsafe-deserialization"],
  ["output-manipulation", "Authenticated open redirect in /learn", "open-redirect"],
  ["output-manipulation", "Authenticated open redirect at /learn", "open-redirect"],
  ["output-manipulation", "Unvalidated external redirect via redirect endpoint", "open-redirect"],
  ["denial-of-service", "Unauthenticated multipart uploads are buffered without size limits", "denial-of-service"],
  ["denial-of-service", "Public login route can grow the default session store without bound", "denial-of-service"],
  ["denial-of-service", "Unbounded multipart upload parsing permits unauthenticated memory exhaustion", "denial-of-service"],
  ["supply-chain", "GitHub Actions workflow uses mutable third-party action tags", "supply-chain"],
  ["supply-chain", "GitHub Actions use mutable major-version tags", "supply-chain"],
  ["supply-chain", "GitHub Actions use mutable tags for secret-bearing release workflow", "supply-chain"],
  ["missing-validation", "Public registration accepts an admin flag and grants administrator privileges", "mass-assignment"],
  ["missing-validation", "Broken object authorization exposes other users' book secrets", "broken-access-control"],
  ["missing-validation", "Authenticated users can change other users' passwords", "broken-access-control"],
  ["missing-validation", "Password-reset token is predictable from the account login", "insecure-randomness"],
  ["missing-validation", "Authenticated users can change another user's password by IDOR", "broken-access-control"],
  ["missing-validation", "Cross-site request forgery on authenticated memo creation", "csrf"],
  ["missing-validation", "Authenticated user can change another user's password by path username", "broken-access-control"],
  ["missing-validation", "Authenticated user can change another account via /useredit", "broken-access-control"],
  ["missing-validation", "Book secret retrieval does not enforce ownership", "broken-access-control"],
  ["missing-validation", "Profile update lacks CSRF protection", "csrf"],
  ["missing-validation", "Any authenticated user can create or modify products", "broken-access-control"],
  ["information-disclosure", "Unauthenticated debug endpoint discloses plaintext passwords", "information-disclosure"],
  ["information-disclosure", "Allocation endpoint exposes other users' records by user ID", "broken-access-control"],
  ["information-disclosure", "Unauthenticated endpoints disclose all users' email addresses", "information-disclosure"],
  ["information-disclosure", "Authenticated users API exposes all password hashes", "information-disclosure"],
  ["information-disclosure", "Login response distinguishes unknown usernames from wrong passwords", "broken-authentication"],
  ["information-disclosure", "Startup config logging can expose database credentials", "information-disclosure"],
  ["information-disclosure", "GET /resetpw leaks whether a login exists", "broken-authentication"],
  ["information-disclosure", "Public debug endpoint discloses every user's plaintext password", "information-disclosure"],
  ["information-disclosure", "User credentials stored and checked in plaintext", "insecure-storage"],
  ["security-misconfiguration", "Hardcoded seeded administrator credentials", "hardcoded-secret"],
  ["security-misconfiguration", "Default session-signing secret is hardcoded and logged at startup", "hardcoded-secret"],
  ["security-misconfiguration", "GET /logout allows cross-site logout requests", "csrf"],
  ["security-misconfiguration", "Hard-coded ZAP API key in development and test configuration", "hardcoded-secret"],
  ["security-misconfiguration", "User passwords are stored and checked in plaintext", "insecure-storage"],
  ["security-misconfiguration", "Seeded administrator uses a hardcoded default password", "hardcoded-secret"],
  ["security-misconfiguration", "Hardcoded express-session signing secret", "hardcoded-secret"],
  ["other", "Arbitrary external redirect via redirect endpoint", "open-redirect"],
  ["other", "User edit lets authenticated users change any account", "broken-access-control"],
  ["other", "User passwords are stored and compared in plaintext", "insecure-storage"],
  ["other", "Unauthenticated requests exhaust the default in-memory session store", "denial-of-service"],
  ["other", "Synchronous bcrypt checks let unauthenticated login traffic block the event loop", "denial-of-service"],
  ["other", "Password reset token is deterministic from the account login", "insecure-randomness"],
  ["other", "Session fixation on password login", "broken-authentication"],
  ["other", "Password reset token is predictable from account name", "insecure-randomness"],
  ["other", "Unauthenticated open redirect at /app/redirect", "open-redirect"],
  ["sql-injection", "SQL injection in authenticated user search", "sql-injection"],
  ["sql-injection", "SQL injection in public user lookup can expose book secrets", "sql-injection"],
  ["xss", "User names are inserted as HTML in the users page, enabling stored XSS", "xss"],
  ["xss", "Reflected XSS in POST /login username field", "xss"],
  ["xss", "Stored profile names are inserted as HTML, enabling authenticated stored XSS", "xss"],
  ["xss", "Stored XSS via unvalidated account names in allocations page", "xss"],
  ["ssrf", "Authenticated research route performs SSRF to caller-controlled URL", "ssrf"],
  ["ssrf", "Authenticated research endpoint permits SSRF and reflects fetched HTML", "ssrf"],
  ["ssrf", "Research endpoint fetches arbitrary URLs and returns the response as HTML", "ssrf"],
  ["code-injection", "Authenticated JavaScript code injection in contribution updates", "code-injection"],
  ["code-injection", "Untrusted calculator expression reaches vulnerable mathjs evaluator", "code-injection"],
  ["code-injection", "Untrusted calculator expression evaluated by vulnerable mathjs version", "code-injection"],
  ["regex-dos", "Catastrophic regex backtracking in profile bank-routing validation", "regex-dos"],
  ["regex-dos", "Profile routing-number validation can be driven into catastrophic backtracking", "regex-dos"],
  ["command-injection", "Unquoted database environment variable permits command injection in production entrypoint", "command-injection"],
  ["command-injection", "POST /app/ping allows authenticated shell command injection", "command-injection"],
  ["command-injection", "Shell command injection in authenticated ping handler", "command-injection"],
  ["unsafe-deserialization", "Bulk legacy import unsafe-deserializes attacker-controlled upload", "unsafe-deserialization"],
  ["unsafe-deserialization", "Bulk-products-legacy deserializes attacker-controlled data with node-serialize", "unsafe-deserialization"],
  ["output-manipulation", "Learning route is an open redirect", "open-redirect"],
  ["output-manipulation", "Authenticated /learn endpoint is an unrestricted open redirect", "open-redirect"],
  ["denial-of-service", "Anonymous requests can permanently accumulate in the default in-memory session store", "denial-of-service"],
  ["denial-of-service", "Unauthenticated requests allocate unbounded in-memory sessions", "denial-of-service"],
  ["supply-chain", "CI workflow runs mutable GitHub Actions tags with registry credentials", "supply-chain"],
  ["supply-chain", "CI workflow uses mutable GitHub Action tags", "supply-chain"],
];

describe("classifyFinding on titles from real scans", () => {
  it("agrees with every unambiguous hand label", () => {
    const wrong = LABELLED.filter(([category, title, want]) => classifyFinding({ category, title }).category !== want);
    expect(wrong.map(([c, t, w]) => `${t} (${c}, want ${w})`)).toEqual([]);
  });
  it("moves the catch-all labels, which is where the models put most of them", () => {
    const catchAll = LABELLED.filter(([c]) => ["missing-validation", "other", "security-misconfiguration", "information-disclosure"].includes(c));
    const moved = catchAll.filter(([c, t]) => classifyFinding({ category: c, title: t }).category !== c);
    expect(moved.length).toBeGreaterThan(catchAll.length / 2);
  });
});

describe("classifyFinding precedence", () => {
  it("keeps a specific category the model chose, even when the title says something else", () => {
    expect(classifyFinding({ category: "xss", title: "Open redirect in the login page" }).category).toBe("xss");
    expect(classifyFinding({ category: "sql-injection", title: "Missing authorization check" })).toEqual({ category: "sql-injection" });
  });
  it("maps an alias to its category and returns the label", () => {
    expect(classifyFinding({ category: "IDOR", title: "x" })).toEqual({ category: "broken-access-control", unknownLabel: "IDOR" });
    expect(classifyFinding({ category: "cross site scripting", title: "x" }).category).toBe("xss");
    expect(classifyFinding({ category: "Cross_Site_Scripting", title: "x" }).category).toBe("xss");
    expect(classifyFinding({ category: "sqli", title: "x" }).category).toBe("sql-injection");
  });
  it("maps an unknown label by its words, then by the title, and keeps the label", () => {
    expect(classifyFinding({ category: "predictable password-reset token", title: "Reset flow" })).toEqual({ category: "insecure-randomness", unknownLabel: "predictable password-reset token" });
    expect(classifyFinding({ category: "business logic", title: "Authenticated users can reset another user's password" })).toEqual({ category: "broken-access-control", unknownLabel: "business logic" });
    expect(classifyFinding({ category: "wat", title: "nothing useful" })).toEqual({ category: "other", unknownLabel: "wat" });
  });
  it("uses a CWE that names one class before the title, and ignores a generic one", () => {
    expect(classifyFinding({ category: "missing-validation", title: "Weird behavior", cwe: "CWE-352" }).category).toBe("csrf");
    expect(classifyFinding({ category: "other", title: "Weird behavior", cwe: ["CWE-639"] }).category).toBe("broken-access-control");
    expect(classifyFinding({ category: "missing-validation", title: "Input is not checked", cwe: "CWE-20" }).category).toBe("missing-validation");
    expect(classifyFinding({ category: "information-disclosure", title: "Weird behavior", cwe: "CWE-200" }).category).toBe("information-disclosure");
    expect(classifyFinding({ category: "sql-injection", title: "x", cwe: "CWE-352" }).category).toBe("sql-injection");
  });
  it("reads the description only for other or an unknown label", () => {
    expect(classifyFinding({ category: "other", title: "Problem in profile", description: "The form has no CSRF token." }).category).toBe("csrf");
    expect(classifyFinding({ category: "missing-validation", title: "Problem in profile", description: "The form has no CSRF token." }).category).toBe("missing-validation");
  });
  it("tells a predictable token from a hardcoded secret, and a stored password from an exposed one", () => {
    expect(classifyFinding({ category: "other", title: "Predictable password-reset token permits account takeover" }).category).toBe("insecure-randomness");
    expect(classifyFinding({ category: "security-misconfiguration", title: "Predictable default session signing secret in production config" }).category).toBe("hardcoded-secret");
    expect(classifyFinding({ category: "information-disclosure", title: "User passwords are stored in plaintext" }).category).toBe("insecure-storage");
    expect(classifyFinding({ category: "information-disclosure", title: "Debug endpoint exposes plaintext passwords" }).category).toBe("information-disclosure");
  });
  it("keeps a password reset route out of the unauthenticated-reset rule", () => {
    expect(classifyFinding({ category: "other", title: "Unauthenticated password reset via predictable MD5 token" }).category).toBe("insecure-randomness");
    expect(classifyFinding({ category: "other", title: "Unauthenticated database reset endpoint destroys data" }).category).toBe("broken-access-control");
  });
  it("never throws and always returns one of our categories", () => {
    for (const input of [{}, { category: 7 }, { category: null, title: 4 }, { category: "  ", title: "" }, { category: "x".repeat(10_000), title: "y".repeat(10_000) }]) {
      expect(isAttackCategory(classifyFinding(input).category)).toBe(true);
    }
  });
});

describe("the category tables", () => {
  it("only point at categories that exist", () => {
    for (const category of [...Object.values(CATEGORY_ALIASES), ...Object.values(CWE_CATEGORY)]) expect(ATTACK_CATEGORIES).toContain(category);
  });
  it("keep every category id that older databases and SARIF files carry", () => {
    for (const id of ["prompt-injection", "jailbreak", "sql-injection", "xss", "ssrf", "cors", "regex-dos", "missing-validation", "crypto-misuse", "policy-violation", "known-vulnerable-package", "supply-chain", "other"]) expect(ATTACK_CATEGORIES).toContain(id);
  });
  it("are accepted by the finding schema", () => {
    for (const category of ATTACK_CATEGORIES) expect(findingSchema.shape.category.safeParse(category).success).toBe(true);
  });
});
