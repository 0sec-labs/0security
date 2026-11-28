//! Java rules for weak cryptographic primitives, predictable randomness and
//! cookie flags.
//!
//! These are syntactic rules. Where an algorithm name is not a literal they
//! resolve it with [`ConstResolver`]: a string literal, a `+` concatenation of
//! constants, or a local/field that is declared once with such a value and
//! never reassigned. Anything else (a parameter, a method result, a value read
//! from configuration such as `props.getProperty("alg", "SHA-256")`, whose
//! literal is only a fallback) is "unknown" and is deliberately not reported.

use std::path::Path;

use tree_sitter::Node;

use crate::rules::common::make_finding;
use crate::rules::Rule;
use crate::{Finding, Language, Severity};

// ─── Shared helpers ──────────────────────────────────────────────────────────

/// Last dotted segment of a type or receiver expression, so that
/// `java.security.MessageDigest` and `MessageDigest` compare equal.
fn simple_name(text: &str) -> &str {
    let text = text.trim();
    let head = text.split('<').next().unwrap_or(text);
    head.rsplit('.').next().unwrap_or(head).trim()
}

/// Pre-order walk that keeps the tree's node lifetime (unlike `walk_tree`).
fn walk<'t>(node: Node<'t>, f: &mut dyn FnMut(Node<'t>)) {
    f(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, f);
    }
}

fn text<'a>(node: Node, src: &'a str) -> &'a str {
    &src[node.byte_range()]
}

fn args_of(call: Node) -> Vec<Node> {
    let mut out = Vec::new();
    if let Some(args) = call.child_by_field_name("arguments") {
        let mut cursor = args.walk();
        for child in args.named_children(&mut cursor) {
            if !matches!(child.kind(), "line_comment" | "block_comment") {
                out.push(child);
            }
        }
    }
    out
}

fn is_scope_kind(kind: &str) -> bool {
    matches!(
        kind,
        "method_declaration"
            | "constructor_declaration"
            | "lambda_expression"
            | "static_initializer"
            | "compact_constructor_declaration"
    )
}

/// Nearest enclosing method-like node, or the whole tree when the code sits in
/// a field initialiser or initialiser block.
fn enclosing_scope(node: Node) -> Node {
    let mut cur = node;
    while let Some(parent) = cur.parent() {
        if is_scope_kind(parent.kind()) && parent.kind() != "lambda_expression" {
            return parent;
        }
        cur = parent;
    }
    cur
}

/// `import a.b.C;` / `import a.b.*;` targets declared at the top of the file.
fn imports(root: Node, src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() == "import_declaration" {
            let t = text(child, src)
                .trim_start_matches("import")
                .trim()
                .trim_end_matches(';')
                .trim();
            if !t.starts_with("static ") {
                out.push(t.split_whitespace().collect::<String>());
            }
        }
    }
    out
}

// ─── Constant resolution ─────────────────────────────────────────────────────

pub(crate) struct ConstResolver<'a> {
    root: Node<'a>,
    src: &'a str,
}

impl<'a> ConstResolver<'a> {
    pub(crate) fn new(root: Node<'a>, src: &'a str) -> Self {
        Self { root, src }
    }

    pub(crate) fn resolve(&self, node: Node<'a>) -> Option<String> {
        self.resolve_depth(node, 0)
    }

    fn resolve_depth(&self, node: Node<'a>, depth: u8) -> Option<String> {
        if depth > 6 {
            return None;
        }
        match node.kind() {
            "string_literal" => {
                let t = text(node, self.src);
                if t.starts_with("\"\"\"") || t.contains('\\') {
                    return None;
                }
                Some(t.trim_matches('"').to_string())
            }
            "parenthesized_expression" => self.resolve_depth(node.named_child(0)?, depth + 1),
            "binary_expression" => {
                let op = node.child_by_field_name("operator")?;
                if text(op, self.src) != "+" {
                    return None;
                }
                let l = self.resolve_depth(node.child_by_field_name("left")?, depth + 1)?;
                let r = self.resolve_depth(node.child_by_field_name("right")?, depth + 1)?;
                Some(l + &r)
            }
            "identifier" => {
                let init = self.find_initializer(text(node, self.src), node)?;
                self.resolve_depth(init, depth + 1)
            }
            "field_access" => {
                let field = node.child_by_field_name("field")?;
                let init = self.find_field_initializer(text(field, self.src))?;
                self.resolve_depth(init, depth + 1)
            }
            _ => None,
        }
    }

    /// The single initialiser of local variable or field `name` visible from
    /// `use_site`, provided nothing else declares or assigns that name.
    fn find_initializer(&self, name: &str, use_site: Node<'a>) -> Option<Node<'a>> {
        let scope = enclosing_scope(use_site);
        if scope.id() != self.root.id() {
            let (decls, assigned) = self.scan_name(scope, name);
            if !decls.is_empty() {
                return match (decls.as_slice(), assigned) {
                    ([Some(init)], false) => Some(*init),
                    _ => None,
                };
            }
        }
        self.find_field_initializer(name)
    }

    fn find_field_initializer(&self, name: &str) -> Option<Node<'a>> {
        let (decls, assigned) = self.scan_name(self.root, name);
        match (decls.as_slice(), assigned) {
            ([Some(init)], false) => Some(*init),
            _ => None,
        }
    }

    /// Every declaration of `name` under `scope` (with its initialiser, if
    /// any) and whether `name` is assigned anywhere under it.
    fn scan_name(&self, scope: Node<'a>, name: &str) -> (Vec<Option<Node<'a>>>, bool) {
        let mut decls: Vec<Option<Node<'a>>> = Vec::new();
        let mut assigned = false;
        let src = self.src;
        walk(scope, &mut |n| match n.kind() {
            "variable_declarator" => {
                if n.child_by_field_name("name")
                    .is_some_and(|id| text(id, src) == name)
                {
                    decls.push(n.child_by_field_name("value"));
                }
            }
            "formal_parameter" | "spread_parameter" | "catch_formal_parameter" => {
                if n.child_by_field_name("name")
                    .is_some_and(|id| text(id, src) == name)
                {
                    decls.push(None);
                }
            }
            "assignment_expression" => {
                if let Some(left) = n.child_by_field_name("left") {
                    let target = match left.kind() {
                        "field_access" => left.child_by_field_name("field"),
                        _ => Some(left),
                    };
                    if target.is_some_and(|t| text(t, src) == name) {
                        assigned = true;
                    }
                }
            }
            _ => {}
        });
        (decls, assigned)
    }
}

// ─── Algorithm tables ────────────────────────────────────────────────────────

fn is_weak_digest(alg: &str) -> bool {
    matches!(
        alg.to_ascii_uppercase().as_str(),
        "MD2" | "MD4" | "MD5" | "SHA" | "SHA1" | "SHA-1"
    )
}

/// Why a cipher transformation is weak, if it is.
fn weak_cipher_reason(transformation: &str, is_cipher: bool) -> Option<String> {
    let upper = transformation.trim().to_ascii_uppercase();
    let mut parts = upper.split('/');
    let alg = parts.next().unwrap_or("");
    let mode = parts.next();

    let weak_alg = match alg {
        "DES" | "DESEDE" | "DESEDEWRAP" | "TRIPLEDES" | "3DES" | "RC2" | "RC4" | "ARCFOUR"
        | "BLOWFISH" | "IDEA" => true,
        _ => {
            // Password-based schemes name the cipher after `AND`:
            // PBEWithMD5AndDES, PBEWithSHA1AndRC4_128, ...
            alg.starts_with("PBEWITH")
                && alg.split("AND").nth(1).is_some_and(|c| {
                    c.starts_with("DES") || c.starts_with("RC2") || c.starts_with("RC4")
                })
        }
    };
    if weak_alg {
        return Some(format!(
            "{} is a weak or obsolete cipher — use AES-GCM or ChaCha20-Poly1305",
            transformation.trim()
        ));
    }
    if !is_cipher {
        return None;
    }
    // ECB is only meaningful as a JCA placeholder for the public-key schemes.
    let asymmetric = matches!(alg, "RSA" | "EC" | "ECIES" | "ELGAMAL");
    if mode == Some("ECB") && !asymmetric {
        return Some(format!(
            "{} uses ECB mode, which leaks plaintext patterns — use GCM or another authenticated mode",
            transformation.trim()
        ));
    }
    // A bare block-cipher name selects the provider default, which is ECB.
    if mode.is_none() && matches!(alg, "AES" | "AES_128" | "AES_192" | "AES_256" | "CAMELLIA") {
        return Some(format!(
            "Cipher.getInstance(\"{}\") with no mode defaults to ECB — name an authenticated mode such as AES/GCM/NoPadding",
            transformation.trim()
        ));
    }
    None
}

/// Resolve the algorithm argument; unknown values yield `None`.
fn algorithm_arg<'a>(resolver: &ConstResolver<'a>, call: Node<'a>, index: usize) -> Option<String> {
    let args = args_of(call);
    resolver.resolve(*args.get(index)?)
}

// ─── java/weak-hash ──────────────────────────────────────────────────────────

pub struct WeakHash;

/// commons-codec `DigestUtils` helpers and Guava `Hashing` factories that
/// hard-wire a broken digest.
const WEAK_DIGEST_HELPERS: &[(&str, &[&str])] = &[
    (
        "DigestUtils",
        &[
            "md2",
            "md2Hex",
            "md5",
            "md5Hex",
            "sha",
            "shaHex",
            "sha1",
            "sha1Hex",
            "getMd2Digest",
            "getMd5Digest",
            "getShaDigest",
            "getSha1Digest",
        ],
    ),
    ("Hashing", &["md5", "sha1"]),
];

impl Rule for WeakHash {
    fn id(&self) -> &str {
        "java/weak-hash"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-328")
    }
    fn description(&self) -> &str {
        "Broken message digest (MD2, MD4, MD5 or SHA-1)"
    }
    fn language(&self) -> Language {
        Language::Java
    }
    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let src = source;
        let resolver = ConstResolver::new(tree.root_node(), source);
        let mut findings = Vec::new();
        walk(tree.root_node(), &mut |node| {
            if node.kind() != "method_invocation" {
                return;
            }
            let (Some(name), Some(obj)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("object"),
            ) else {
                return;
            };
            let method = text(name, src);
            let class = simple_name(text(obj, src));
            if class == "MessageDigest" && method == "getInstance" {
                let Some(alg) = algorithm_arg(&resolver, node, 0) else {
                    return;
                };
                if !is_weak_digest(&alg) {
                    return;
                }
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    &format!(
                        "MessageDigest.getInstance(\"{alg}\") uses a broken digest — use SHA-256 or stronger (SHA-3, BLAKE2), and a password hash such as bcrypt or Argon2 for credentials"
                    ),
                    node,
                    src,
                ));
            } else if WEAK_DIGEST_HELPERS
                .iter()
                .any(|(c, ms)| *c == class && ms.contains(&method))
            {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    &format!(
                        "{class}.{method}() computes a broken digest — use SHA-256 or stronger"
                    ),
                    node,
                    src,
                ));
            }
        });
        findings
    }
}

// ─── java/no-weak-crypto ─────────────────────────────────────────────────────

pub struct WeakCipher;

impl Rule for WeakCipher {
    fn id(&self) -> &str {
        "java/no-weak-crypto"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-327")
    }
    fn description(&self) -> &str {
        "Weak or obsolete cipher, or ECB mode"
    }
    fn language(&self) -> Language {
        Language::Java
    }
    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let src = source;
        let resolver = ConstResolver::new(tree.root_node(), source);
        let mut findings = Vec::new();
        walk(tree.root_node(), &mut |node| {
            if node.kind() != "method_invocation" {
                return;
            }
            let (Some(name), Some(obj)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("object"),
            ) else {
                return;
            };
            if text(name, src) != "getInstance" {
                return;
            }
            let class = simple_name(text(obj, src));
            if !matches!(class, "Cipher" | "KeyGenerator" | "SecretKeyFactory") {
                return;
            }
            let Some(alg) = algorithm_arg(&resolver, node, 0) else {
                return;
            };
            let Some(reason) = weak_cipher_reason(&alg, class == "Cipher") else {
                return;
            };
            findings.push(make_finding(
                self.id(),
                self.severity(),
                self.cwe(),
                &format!("{class}.getInstance: {reason}"),
                node,
                src,
            ));
        });
        findings
    }
}

// ─── hygiene/java-weak-random ────────────────────────────────────────────────

/// Hygiene finding, not a vulnerability claim: `java.util.Random` and
/// `Math.random()` are predictable, which matters only when the value guards
/// something. It lives in its own `hygiene/` namespace so it can be filtered
/// as a group, and it is not reported from test sources.
pub struct WeakRandom;

fn is_test_path(path: &Path) -> bool {
    // The scanner passes paths relative to the scan root; anchor them so that
    // a leading `src/test/` matches like a nested one.
    let s = format!("/{}", path.to_string_lossy().replace('\\', "/"));
    if s.contains("/src/test/") || s.contains("/test/java/") || s.contains("/tests/") {
        return true;
    }
    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
        n.ends_with("Test.java")
            || n.ends_with("Tests.java")
            || n.ends_with("IT.java")
            || n.ends_with("TestCase.java")
    })
}

fn is_java_util_random(type_text: &str, imports: &[String]) -> bool {
    let t = type_text.trim();
    if t.contains('.') {
        return t == "java.util.Random";
    }
    if t != "Random" {
        return false;
    }
    let other_random = imports
        .iter()
        .any(|i| i.ends_with(".Random") && i != "java.util.Random");
    !other_random
        && imports
            .iter()
            .any(|i| i == "java.util.Random" || i == "java.util.*")
}

impl Rule for WeakRandom {
    fn id(&self) -> &str {
        "hygiene/java-weak-random"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-330")
    }
    fn description(&self) -> &str {
        "Hygiene: java.util.Random or Math.random() is predictable; use SecureRandom when the value guards anything"
    }
    fn language(&self) -> Language {
        Language::Java
    }
    fn applies_to_path(&self, path: &Path) -> bool {
        !is_test_path(path)
    }
    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let src = source;
        let imports = imports(tree.root_node(), source);
        let mut findings = Vec::new();
        walk(tree.root_node(), &mut |node| {
            let label = match node.kind() {
                "object_creation_expression" => {
                    let Some(ty) = node.child_by_field_name("type") else {
                        return;
                    };
                    if !is_java_util_random(text(ty, src), &imports) {
                        return;
                    }
                    // A literal seed is a reproducible sequence on purpose
                    // (simulation, shuffling in a fixture), not a secret.
                    let args = args_of(node);
                    if args.first().is_some_and(|a| a.kind().ends_with("_literal")) {
                        return;
                    }
                    "new java.util.Random()"
                }
                "method_invocation" => {
                    let (Some(name), Some(obj)) = (
                        node.child_by_field_name("name"),
                        node.child_by_field_name("object"),
                    ) else {
                        return;
                    };
                    let o = text(obj, src);
                    if text(name, src) != "random" || (o != "Math" && o != "java.lang.Math") {
                        return;
                    }
                    "Math.random()"
                }
                _ => return,
            };
            findings.push(make_finding(
                self.id(),
                self.severity(),
                self.cwe(),
                &format!(
                    "{label} is predictable — fine for simulation or jitter, but use java.security.SecureRandom for tokens, keys, nonces, salts or identifiers"
                ),
                node,
                src,
            ));
        });
        findings
    }
}

// ─── java/cookie-missing-secure ──────────────────────────────────────────────

pub struct CookieMissingSecure;

fn is_servlet_cookie(type_text: &str, imports: &[String]) -> bool {
    let t = type_text.trim();
    if t.contains('.') {
        return t == "javax.servlet.http.Cookie" || t == "jakarta.servlet.http.Cookie";
    }
    if t != "Cookie" {
        return false;
    }
    let servlet = |i: &String| {
        matches!(
            i.as_str(),
            "javax.servlet.http.Cookie"
                | "jakarta.servlet.http.Cookie"
                | "javax.servlet.http.*"
                | "jakarta.servlet.http.*"
        )
    };
    let foreign = imports
        .iter()
        .any(|i| i.ends_with(".Cookie") && !servlet(i));
    !foreign && imports.iter().any(servlet)
}

/// The variable a freshly created cookie is bound to, if any.
fn bound_variable<'a>(creation: Node<'a>, src: &'a str) -> Option<&'a str> {
    let parent = creation.parent()?;
    match parent.kind() {
        "variable_declarator" => parent.child_by_field_name("name").map(|n| text(n, src)),
        "assignment_expression" => parent
            .child_by_field_name("left")
            .filter(|l| l.kind() == "identifier")
            .map(|n| text(n, src)),
        _ => None,
    }
}

impl Rule for CookieMissingSecure {
    fn id(&self) -> &str {
        "java/cookie-missing-secure"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-614")
    }
    fn description(&self) -> &str {
        "Servlet cookie sent without the Secure flag"
    }
    fn language(&self) -> Language {
        Language::Java
    }
    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let src = source;
        let imports = imports(tree.root_node(), source);
        let mut findings = Vec::new();
        walk(tree.root_node(), &mut |node| {
            if node.kind() != "object_creation_expression" {
                return;
            }
            let Some(ty) = node.child_by_field_name("type") else {
                return;
            };
            if !is_servlet_cookie(text(ty, src), &imports) {
                return;
            }

            // A cookie created with an empty value is a logout/clear
            // instruction, not a credential in transit.
            if args_of(node)
                .get(1)
                .is_some_and(|v| matches!(text(*v, src), "\"\"" | "null"))
            {
                return;
            }

            // `response.addCookie(new Cookie(..))`: nothing can set the flag.
            let inline_add = node.parent().is_some_and(|p| {
                p.kind() == "argument_list"
                    && p.parent().is_some_and(|c| {
                        c.kind() == "method_invocation"
                            && c.child_by_field_name("name")
                                .is_some_and(|n| text(n, src) == "addCookie")
                    })
            });
            if inline_add {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "Cookie is added to the response without setSecure(true)",
                    node,
                    src,
                ));
                return;
            }
            let Some(var) = bound_variable(node, src) else {
                return; // returned or stored: the flag may be set elsewhere
            };
            let scope = enclosing_scope(node);
            let usage = CookieUsage::collect(scope, src, var);
            if usage.secure_covers_every_sink() || usage.escapes || usage.expires_now {
                return;
            }
            if let Some(&explicit) = usage.secure_false.first() {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "setSecure(false) sends the cookie over plain HTTP too",
                    explicit,
                    src,
                ));
            } else if usage.added {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    &format!("Cookie `{var}` is added to the response without setSecure(true)"),
                    node,
                    src,
                ));
            }
        });
        findings
    }
}

#[derive(Default)]
struct CookieUsage<'a> {
    /// `setSecure(true)` and `setSecure(<expression>)` (e.g.
    /// `request.isSecure()`) calls. They suppress a finding only when they
    /// dominate every `addCookie` sink; see `dominates`.
    secure_guards: Vec<Node<'a>>,
    sinks: Vec<Node<'a>>,
    secure_false: Vec<Node<'a>>,
    added: bool,
    /// Conditional path of every guard and sink, by node id.
    paths: std::collections::HashMap<usize, Vec<(usize, usize)>>,
    /// The cookie is handed to code we cannot see (helper call, return).
    escapes: bool,
    /// `setMaxAge(0)`: the cookie only asks the browser to drop a cookie.
    expires_now: bool,
}

/// Constructs under which a statement may not run, or may run a different
/// number of times, than its surroundings.
fn is_conditional_construct(n: Node, src: &str) -> bool {
    match n.kind() {
        "if_statement"
        | "for_statement"
        | "enhanced_for_statement"
        | "while_statement"
        | "do_statement"
        | "switch_expression"
        | "switch_block_statement_group"
        | "switch_rule"
        | "ternary_expression"
        | "try_statement"
        | "try_with_resources_statement"
        | "catch_clause"
        | "finally_clause"
        | "lambda_expression"
        | "class_body" => true,
        "binary_expression" => n
            .child_by_field_name("operator")
            .is_some_and(|o| matches!(text(o, src), "&&" | "||")),
        _ => false,
    }
}

/// The conditional constructs around `node` below `scope`, each with the
/// child of it that contains `node` (so two branches of one `if` differ).
fn conditional_path<'a>(node: Node<'a>, scope: Node<'a>, src: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut child = node;
    while let Some(parent) = child.parent() {
        if parent.id() == scope.id() {
            break;
        }
        if is_conditional_construct(parent, src) {
            out.push((parent.id(), child.id()));
        }
        child = parent;
    }
    out
}

impl<'a> CookieUsage<'a> {
    /// True when every `addCookie` sink is preceded by a `setSecure` guard
    /// that runs on every path to it: the guard sits in no conditional
    /// construct the sink is not also in, on the same branch.
    fn secure_covers_every_sink(&self) -> bool {
        if self.sinks.is_empty() {
            return !self.secure_guards.is_empty();
        }
        self.sinks.iter().all(|sink| {
            let sink_path = &self.paths[&sink.id()];
            self.secure_guards.iter().any(|g| {
                g.end_byte() <= sink.start_byte()
                    && self.paths[&g.id()].iter().all(|c| sink_path.contains(c))
            })
        })
    }

    fn collect(scope: Node<'a>, src: &str, var: &str) -> CookieUsage<'a> {
        let mut u = CookieUsage::default();
        walk(scope, &mut |n| match n.kind() {
            "method_invocation" => {
                let name = n.child_by_field_name("name").map(|x| text(x, src));
                let obj = n.child_by_field_name("object").map(|x| text(x, src));
                if name == Some("setSecure") && obj == Some(var) {
                    match args_of(n).first().map(|a| text(*a, src)) {
                        Some("false") => u.secure_false.push(n),
                        _ => u.secure_guards.push(n),
                    }
                }
                if name == Some("setMaxAge")
                    && obj == Some(var)
                    && args_of(n).first().map(|a| text(*a, src)) == Some("0")
                {
                    u.expires_now = true;
                }
                let passes_var = args_of(n)
                    .iter()
                    .any(|a| a.kind() == "identifier" && text(*a, src) == var);
                if passes_var {
                    if name == Some("addCookie") {
                        u.added = true;
                        u.sinks.push(n);
                    } else {
                        u.escapes = true;
                    }
                }
            }
            // `this.cookie = c` hands the cookie to other code.
            "assignment_expression"
                if n.child_by_field_name("right")
                    .is_some_and(|r| r.kind() == "identifier" && text(r, src) == var) =>
            {
                u.escapes = true;
            }
            _ => {}
        });
        for n in u.secure_guards.iter().chain(u.sinks.iter()) {
            u.paths.insert(n.id(), conditional_path(*n, scope, src));
        }
        // `return cookie;`
        walk(scope, &mut |n| {
            if n.kind() == "return_statement"
                && n.named_child(0)
                    .is_some_and(|r| r.kind() == "identifier" && text(r, src) == var)
            {
                u.escapes = true;
            }
        });
        u
    }
}
