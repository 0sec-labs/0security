//! Lightweight flow-sensitive "is this sink argument provably safe?" check
//! for Java.
//!
//! The pattern rules and the flow-insensitive taint engine cannot see that a
//! value was replaced, folded to a constant or fetched back from a collection
//! before it reaches a sink. This module interprets a single method body in
//! source order over a tiny abstract domain:
//!
//! - compile-time constants (ints, chars, strings, booleans) so branch
//!   conditions such as `(7 * 18) + num > 200` fold and only the live branch
//!   contributes (`if`, `?:`, `switch`);
//! - definite assignment: a reassignment replaces the previous value instead of
//!   joining with it, and branches are merged only when both are reachable;
//! - `List` / `Map` locals with constant indices and keys, so `add`/`put`/
//!   `remove` followed by `get` of a safe element stays safe;
//! - calls to uniquely-named helper methods of the same file, interpreted with
//!   the caller's argument values.
//!
//! The analysis is deliberately one-sided: a value is *safe* only when it is
//! proven to be built from constants (or, for HTML output, known encoders).
//! Anything unknown (parameters, fields, unknown calls, unmodelled
//! statements) is *maybe tainted*, so using this check to suppress findings
//! never hides a flow it cannot explain.

use std::collections::HashMap;
use tree_sitter::Node;

/// Output encoders whose result is safe inside an HTML response.
const HTML_ENCODERS: &[&str] = &[
    "encodeForHTML",
    "encodeForHTMLAttribute",
    "encodeForJavaScript",
    "encodeForCSS",
    "encodeForURL",
    "forHtml",
    "forHtmlContent",
    "forHtmlAttribute",
    "forJavaScript",
    "forCssString",
    "escapeHtml",
    "escapeHtml3",
    "escapeHtml4",
    "escapeXml",
    "escapeXml10",
    "escapeXml11",
    "escapeEcmaScript",
    "escapeJavaScript",
    "htmlEscape",
];

/// String methods that return a safe value when the receiver and every
/// argument are safe.
const STRING_PASSTHROUGH: &[&str] = &[
    "toString",
    "trim",
    "strip",
    "toLowerCase",
    "toUpperCase",
    "substring",
    "concat",
    "replace",
    "replaceAll",
    "replaceFirst",
    "intern",
    "toCharArray",
    "getBytes",
    "repeat",
    "length",
    "equals",
    "equalsIgnoreCase",
    "isEmpty",
    "startsWith",
    "endsWith",
    "contains",
    "indexOf",
    "hashCode",
    "charAt",
];

/// Method names that read from the outside world even when every argument is a
/// constant, so their result is never provably free of external input.
const READS_EXTERNAL_INPUT: &[&str] = &[
    "getenv",
    "readLine",
    "read",
    "readAllLines",
    "readAllBytes",
    "readString",
    "nextLine",
    "next",
    "getParameter",
    "getParameterValues",
    "getParameterMap",
    "getHeader",
    "getHeaders",
    "getCookies",
    "getQueryString",
    "getRequestURI",
    "getRequestURL",
    "getInputStream",
    "getReader",
    "getPathInfo",
];

/// Whether `Type.method(safe args)` on a project type that is not declared in
/// the scanned file (so its body cannot be read) is assumed to return a safe
/// value because its arguments are safe.
///
/// `false` (the default) is sound: such a helper is unknown, because it may
/// ignore its arguments and read request, thread or static state. The price is
/// extra false alarms on code that routes constants through helper factories
/// declared in other files; the later verification step is the place to prune
/// them. `true` restores the old assumption (it recovers that precision but can
/// hide a real finding behind e.g. `exec(Helper.currentInput())`). This is a
/// build-time constant, not a user-facing option. See `docs/precision.md`.
const TRUST_UNRESOLVED_PROJECT_HELPERS: bool = false;

/// Accessors of per-request or per-thread state: what they return does not
/// depend on their arguments.
const READS_REQUEST_CONTEXT: &[&str] = &[
    "getAttribute",
    "getAttributes",
    "getSession",
    "getRequest",
    "getRequestAttributes",
    "currentRequestAttributes",
    "getAuthentication",
    "getPrincipal",
    "getUserPrincipal",
    "getRemoteUser",
    "getContext",
];

/// Types whose static methods read request, thread or security context rather
/// than their arguments.
const REQUEST_CONTEXT_TYPES: &[&str] = &[
    "RequestContextHolder",
    "SecurityContextHolder",
    "LocaleContextHolder",
    "TransactionSynchronizationManager",
    "MDC",
    "ThreadContext",
    "ServletActionContext",
    "ActionContext",
    "FacesContext",
    "ExternalContext",
    "ServletRequestAttributes",
    "RequestAttributes",
];

/// Package prefixes of the JDK and widely used libraries.
const LIBRARY_PREFIXES: &[&str] = &[
    "java.",
    "javax.",
    "jakarta.",
    "org.w3c.",
    "org.xml.",
    "org.apache.",
    "com.google.",
    "org.springframework.",
    "org.slf4j.",
    "org.owasp.esapi.",
    "org.owasp.encoder.",
    "org.json.",
    "com.fasterxml.",
];

/// JDK types usable without an import, or commonly brought in by a wildcard.
const JDK_TYPES: &[&str] = &[
    "String",
    "Integer",
    "Long",
    "Double",
    "Float",
    "Short",
    "Byte",
    "Boolean",
    "Character",
    "Math",
    "StrictMath",
    "System",
    "Objects",
    "Arrays",
    "Collections",
    "List",
    "Set",
    "Map",
    "Optional",
    "UUID",
    "Paths",
    "Path",
    "Files",
    "Base64",
    "Pattern",
    "Collectors",
    "Stream",
    "StandardCharsets",
    "Instant",
    "LocalDate",
    "LocalDateTime",
    "Duration",
    "Locale",
    "BigInteger",
    "BigDecimal",
    "Thread",
    "Character",
    "Number",
    "Enum",
];

const MAX_DEPTH: usize = 3;
const STEP_BUDGET: usize = 50_000;

#[derive(Clone, Debug, PartialEq)]
enum Val {
    Int(i64),
    Char(char),
    Bool(bool),
    Str(String),
    Null,
    /// Safe but not a known constant.
    Safe,
    /// Not proven safe.
    Maybe,
    List(Vec<Val>),
    Map(Vec<(String, Val)>),
}

impl Val {
    fn is_safe(&self) -> bool {
        match self {
            Val::Maybe => false,
            Val::List(items) => items.iter().all(Val::is_safe),
            Val::Map(items) => items.iter().all(|(_, v)| v.is_safe()),
            _ => true,
        }
    }

    fn as_int(&self) -> Option<i64> {
        match self {
            Val::Int(i) => Some(*i),
            Val::Char(c) => Some(*c as i64),
            _ => None,
        }
    }

    fn is_const(&self) -> bool {
        matches!(
            self,
            Val::Int(_) | Val::Char(_) | Val::Bool(_) | Val::Str(_) | Val::Null
        )
    }

    fn degrade(&self) -> Val {
        if self.is_safe() {
            Val::Safe
        } else {
            Val::Maybe
        }
    }
}

fn join(a: &Val, b: &Val) -> Val {
    if a == b {
        return a.clone();
    }
    match (a, b) {
        (Val::List(x), Val::List(y)) if x.len() == y.len() => {
            Val::List(x.iter().zip(y).map(|(p, q)| join(p, q)).collect())
        }
        (Val::Map(x), Val::Map(y))
            if x.len() == y.len() && x.iter().zip(y).all(|(p, q)| p.0 == q.0) =>
        {
            Val::Map(
                x.iter()
                    .zip(y)
                    .map(|(p, q)| (p.0.clone(), join(&p.1, &q.1)))
                    .collect(),
            )
        }
        _ => {
            if a.is_safe() && b.is_safe() {
                Val::Safe
            } else {
                Val::Maybe
            }
        }
    }
}

type Env = HashMap<String, Val>;

fn join_env(a: &Env, b: &Env) -> Env {
    let mut out = Env::new();
    for (k, v) in a {
        if let Some(w) = b.get(k) {
            out.insert(k.clone(), join(v, w));
        }
    }
    out
}

#[derive(PartialEq, Clone, Copy)]
enum Flow {
    Next,
    Break,
    Jump,
}

struct Interp<'a> {
    src: &'a str,
    root: Node<'a>,
    html: bool,
    /// `Some(names)`: calls to helpers that receive only safe arguments count
    /// as safe, except calls to a method in `names` (the rule's own sources).
    /// `None`: every call we cannot interpret is not proven safe.
    trusted_helpers: Option<Vec<String>>,
    depth: usize,
    /// Nesting of field initialisers being evaluated for constant lookups.
    const_depth: usize,
    steps: usize,
    aborted: bool,
    /// Sink byte range -> every argument safe on every visit.
    rec: HashMap<(usize, usize), bool>,
    /// Per-argument safety of each recorded call, merged across visits.
    rec_args: HashMap<(usize, usize), Vec<bool>>,
    returns: Vec<Val>,
    /// Environments captured at `break`/`continue`, joined at the enclosing
    /// loop or switch exit so a value assigned just before leaving survives.
    exits: Vec<Env>,
}

/// True when the call or `new` expression `call` sits in a method body and
/// every argument is proven safe on every path that reaches it. With `html`
/// set, known HTML encoders count as sanitisers (use for XSS sinks only).
pub fn sink_args_safe(call: Node<'_>, source: &str, html: bool, only: &[usize]) -> bool {
    sink_args_safe_with(call, source, html, only, Some(Vec::new()))
}

/// Like [`sink_args_safe`], with control over whether helper calls that receive
/// only safe arguments are trusted to return safe values (see
/// `Interp::trusted_helpers`).
pub fn sink_args_safe_with(
    call: Node<'_>,
    source: &str,
    html: bool,
    only: &[usize],
    trusted_helpers: Option<Vec<String>>,
) -> bool {
    let mut method = call;
    loop {
        match method.kind() {
            "method_declaration" | "constructor_declaration" => break,
            _ => match method.parent() {
                Some(p) => method = p,
                None => return false,
            },
        }
    }
    let mut root = method;
    while let Some(p) = root.parent() {
        root = p;
    }
    let Some(body) = method.child_by_field_name("body") else {
        return false;
    };
    let mut it = Interp {
        src: source,
        root,
        html,
        trusted_helpers,
        depth: 0,
        const_depth: 0,
        steps: 0,
        aborted: false,
        rec: HashMap::new(),
        rec_args: HashMap::new(),
        returns: Vec::new(),
        exits: Vec::new(),
    };
    // Parameters are caller-controlled: seed them so they shadow any field.
    let mut env = Env::new();
    if let Some(ps) = method.child_by_field_name("parameters") {
        let mut c = ps.walk();
        for p in ps.named_children(&mut c) {
            let name = p.child_by_field_name("name").or_else(|| {
                let mut c2 = p.walk();
                let found = p
                    .named_children(&mut c2)
                    .find_map(|d| d.child_by_field_name("name"));
                found
            });
            if let Some(n) = name {
                env.insert(it.text(n).to_string(), Val::Maybe);
            }
        }
    }
    it.exec(body, &mut env);
    let key = (call.start_byte(), call.end_byte());
    if it.aborted {
        return false;
    }
    if only.is_empty() {
        return it.rec.get(&key).copied().unwrap_or(false);
    }
    // Only the listed argument positions have to be proven safe.
    match it.rec_args.get(&key) {
        Some(args) => only.iter().all(|i| args.get(*i).copied().unwrap_or(true)),
        None => false,
    }
}

impl<'a> Interp<'a> {
    fn text(&self, n: Node<'_>) -> &'a str {
        &self.src[n.byte_range()]
    }

    fn tick(&mut self) -> bool {
        self.steps += 1;
        if self.steps > STEP_BUDGET {
            self.aborted = true;
        }
        self.aborted
    }

    // ── statements ──────────────────────────────────────────────────────

    fn exec(&mut self, node: Node<'a>, env: &mut Env) -> Flow {
        if self.tick() {
            return Flow::Jump;
        }
        match node.kind() {
            "block" | "constructor_body" | "switch_block_statement_group_body" => {
                let mut c = node.walk();
                for child in node.named_children(&mut c) {
                    let f = self.exec(child, env);
                    if f != Flow::Next {
                        return f;
                    }
                }
                Flow::Next
            }
            "local_variable_declaration" => {
                let mut c = node.walk();
                for d in node.named_children(&mut c) {
                    if d.kind() != "variable_declarator" {
                        continue;
                    }
                    let Some(name) = d.child_by_field_name("name") else {
                        continue;
                    };
                    let v = match d.child_by_field_name("value") {
                        Some(value) => {
                            let v = self.eval(value, env);
                            if matches!(v, Val::List(_) | Val::Map(_)) {
                                // Aliasing a tracked collection: give up on both.
                                self.escape(value, env);
                                if value.kind() == "identifier" {
                                    Val::Maybe
                                } else {
                                    v
                                }
                            } else {
                                v
                            }
                        }
                        None => Val::Safe,
                    };
                    env.insert(self.text(name).to_string(), v);
                }
                Flow::Next
            }
            "expression_statement" => {
                if let Some(e) = node.named_child(0) {
                    self.eval(e, env);
                }
                Flow::Next
            }
            "if_statement" => {
                let cond = node
                    .child_by_field_name("condition")
                    .map(|c| self.eval(c, env))
                    .unwrap_or(Val::Maybe);
                let then = node.child_by_field_name("consequence");
                let alt = node.child_by_field_name("alternative");
                match cond {
                    Val::Bool(true) => then.map_or(Flow::Next, |t| self.exec(t, env)),
                    Val::Bool(false) => alt.map_or(Flow::Next, |a| self.exec(a, env)),
                    _ => {
                        let mut e1 = env.clone();
                        let f1 = then.map_or(Flow::Next, |t| self.exec(t, &mut e1));
                        let mut e2 = env.clone();
                        let f2 = alt.map_or(Flow::Next, |a| self.exec(a, &mut e2));
                        self.merge(env, (e1, f1), (e2, f2))
                    }
                }
            }
            "switch_expression" => self.exec_switch(node, env).1,
            "while_statement" | "for_statement" | "enhanced_for_statement" | "do_statement" => {
                self.exec_loop(node, env)
            }
            "try_statement" | "try_with_resources_statement" => self.exec_try(node, env),
            "return_statement" => {
                let v = node
                    .named_child(0)
                    .map(|e| self.eval(e, env))
                    .unwrap_or(Val::Safe);
                self.returns.push(v);
                Flow::Jump
            }
            "throw_statement" => Flow::Jump,
            "continue_statement" => {
                self.exits.push(env.clone());
                Flow::Jump
            }
            "break_statement" => {
                self.exits.push(env.clone());
                Flow::Break
            }
            "labeled_statement" | "synchronized_statement" => {
                let mut f = Flow::Next;
                let mut c = node.walk();
                for child in node.named_children(&mut c) {
                    if matches!(child.kind(), "block" | "expression_statement")
                        || child.kind().ends_with("_statement")
                    {
                        f = self.exec(child, env);
                    }
                }
                f
            }
            _ => Flow::Next,
        }
    }

    fn merge(&mut self, env: &mut Env, a: (Env, Flow), b: (Env, Flow)) -> Flow {
        match (a.1, b.1) {
            (Flow::Next, Flow::Next) => {
                *env = join_env(&a.0, &b.0);
                Flow::Next
            }
            (Flow::Next, _) => {
                *env = a.0;
                Flow::Next
            }
            (_, Flow::Next) => {
                *env = b.0;
                Flow::Next
            }
            (fa, fb) => {
                *env = join_env(&a.0, &b.0);
                if fa == Flow::Break || fb == Flow::Break {
                    Flow::Break
                } else {
                    Flow::Jump
                }
            }
        }
    }

    fn exec_loop(&mut self, node: Node<'a>, env: &mut Env) -> Flow {
        match node.kind() {
            "for_statement" => {
                let mut c = node.walk();
                let inits: Vec<_> = node.children_by_field_name("init", &mut c).collect();
                for i in inits {
                    if i.kind() == "local_variable_declaration" {
                        self.exec(i, env);
                    } else {
                        self.eval(i, env);
                    }
                }
            }
            "enhanced_for_statement" => {
                let iter = node
                    .child_by_field_name("value")
                    .map(|v| self.eval(v, env))
                    .unwrap_or(Val::Maybe);
                let elem = match &iter {
                    Val::List(items) => items.iter().fold(Val::Safe, |a, b| join(&a, b)),
                    other => other.degrade(),
                };
                if let Some(n) = node.child_by_field_name("name") {
                    env.insert(self.text(n).to_string(), elem);
                }
            }
            _ => {}
        }
        let body = node.child_by_field_name("body");
        let mark = self.exits.len();
        // Two passes so a value carried around the back edge reaches the sinks.
        let entry = env.clone();
        for _ in 0..2 {
            if let Some(cond) = node.child_by_field_name("condition") {
                if self.eval(cond, env) == Val::Bool(false) && node.kind() != "do_statement" {
                    return Flow::Next;
                }
            }
            if let Some(b) = body {
                let mut e = env.clone();
                self.exec(b, &mut e);
                *env = join_env(env, &e);
            }
            let mut c = node.walk();
            let updates: Vec<_> = node.children_by_field_name("update", &mut c).collect();
            for u in updates {
                self.eval(u, env);
            }
        }
        *env = join_env(env, &entry);
        for e in self.exits.split_off(mark) {
            *env = join_env(env, &e);
        }
        Flow::Next
    }

    fn exec_try(&mut self, node: Node<'a>, env: &mut Env) -> Flow {
        let pre = env.clone();
        if let Some(res) = node.child_by_field_name("resources") {
            let mut c = res.walk();
            for r in res.named_children(&mut c) {
                if let (Some(n), Some(v)) = (
                    r.child_by_field_name("name"),
                    r.child_by_field_name("value"),
                ) {
                    let val = self.eval(v, env);
                    env.insert(self.text(n).to_string(), val);
                }
            }
        }
        let mut flow = node
            .child_by_field_name("body")
            .map_or(Flow::Next, |b| self.exec(b, env));
        let after_body = env.clone();
        let mut c = node.walk();
        let children: Vec<_> = node.named_children(&mut c).collect();
        for ch in &children {
            if ch.kind() == "catch_clause" {
                let mut ce = join_env(&pre, &after_body);
                let mut cc = ch.walk();
                for part in ch.named_children(&mut cc) {
                    if part.kind() == "catch_formal_parameter" {
                        if let Some(n) = part.child_by_field_name("name") {
                            ce.insert(self.text(n).to_string(), Val::Maybe);
                        }
                    }
                }
                let cf = ch
                    .child_by_field_name("body")
                    .map_or(Flow::Next, |b| self.exec(b, &mut ce));
                flow = self.merge(env, (env.clone(), flow), (ce, cf));
            }
        }
        for ch in &children {
            if ch.kind() == "finally_clause" {
                let mut cc = ch.walk();
                for b in ch.named_children(&mut cc) {
                    self.exec(b, env);
                }
            }
        }
        flow
    }

    /// Returns (selected value for switch expressions, flow).
    fn exec_switch(&mut self, node: Node<'a>, env: &mut Env) -> (Val, Flow) {
        let sel = node
            .child_by_field_name("condition")
            .map(|c| self.eval(c, env))
            .unwrap_or(Val::Maybe);
        let Some(block) = node.child_by_field_name("body") else {
            return (Val::Maybe, Flow::Next);
        };
        let mut c = block.walk();
        let groups: Vec<Node<'a>> = block.named_children(&mut c).collect();
        // Each group: (labels as Option<Val> where None = default, node).
        let mut labels: Vec<Vec<Option<Val>>> = Vec::new();
        for g in &groups {
            let mut ls = Vec::new();
            let mut gc = g.walk();
            for part in g.named_children(&mut gc) {
                if part.kind() == "switch_label" {
                    let mut lc = part.walk();
                    let exprs: Vec<_> = part.named_children(&mut lc).collect();
                    if exprs.is_empty() {
                        ls.push(None);
                    }
                    for e in exprs {
                        let mut tmp = Env::new();
                        ls.push(Some(self.eval(e, &mut tmp)));
                    }
                }
            }
            labels.push(ls);
        }
        let is_rule = groups.iter().any(|g| g.kind() == "switch_rule");
        let matches_sel = |l: &Option<Val>| match (l, &sel) {
            (Some(lv), s) if lv.is_const() && s.is_const() => match (lv.as_int(), s.as_int()) {
                (Some(a), Some(b)) => a == b,
                _ => lv == s,
            },
            _ => false,
        };
        let all_const = sel.is_const()
            && labels
                .iter()
                .flatten()
                .all(|l| l.as_ref().is_none_or(Val::is_const));
        let start_indices: Vec<usize> = if all_const {
            let hit = labels.iter().position(|ls| ls.iter().any(&matches_sel));
            let def = labels.iter().position(|ls| ls.iter().any(Option::is_none));
            hit.or(def).into_iter().collect()
        } else {
            (0..groups.len()).collect()
        };
        if start_indices.is_empty() {
            return (Val::Safe, Flow::Next);
        }
        let mut result: Option<(Env, Val)> = None;
        let mark = self.exits.len();
        for &start in &start_indices {
            let mut e = env.clone();
            let mut value = Val::Safe;
            if is_rule {
                value = self.exec_rule_body(groups[start], &mut e);
            } else {
                // Run groups from `start`, falling through until a break.
                for g in &groups[start..] {
                    let mut f = Flow::Next;
                    let mut gc = g.walk();
                    for stmt in g.named_children(&mut gc) {
                        if stmt.kind() == "switch_label" {
                            continue;
                        }
                        f = self.exec(stmt, &mut e);
                        if f != Flow::Next {
                            break;
                        }
                    }
                    if f != Flow::Next {
                        break;
                    }
                }
            }
            result = Some(match result {
                None => (e, value),
                Some((pe, pv)) => (join_env(&pe, &e), join(&pv, &value)),
            });
        }
        let (mut new_env, value) = result.unwrap();
        for ex in self.exits.split_off(mark) {
            new_env = join_env(&new_env, &ex);
        }
        if !all_const {
            // Without a default, control may skip every case.
            let has_default = labels.iter().flatten().any(Option::is_none);
            if !has_default {
                new_env = join_env(&new_env, env);
            }
        }
        *env = new_env;
        (value, Flow::Next)
    }

    fn exec_rule_body(&mut self, rule: Node<'a>, env: &mut Env) -> Val {
        let mut c = rule.walk();
        let mut v = Val::Safe;
        for part in rule.named_children(&mut c) {
            match part.kind() {
                "switch_label" => {}
                "block" => {
                    self.exec(part, env);
                }
                "expression_statement" | "throw_statement" => {
                    if let Some(e) = part.named_child(0) {
                        v = self.eval(e, env);
                    }
                }
                _ => v = self.eval(part, env),
            }
        }
        v
    }

    // ── expressions ─────────────────────────────────────────────────────

    fn eval(&mut self, node: Node<'a>, env: &mut Env) -> Val {
        if self.tick() {
            return Val::Maybe;
        }
        match node.kind() {
            "decimal_integer_literal" => {
                let t = self.text(node).replace('_', "");
                let t = t.trim_end_matches(['l', 'L']);
                t.parse().map(Val::Int).unwrap_or(Val::Safe)
            }
            "hex_integer_literal"
            | "octal_integer_literal"
            | "binary_integer_literal"
            | "decimal_floating_point_literal"
            | "hex_floating_point_literal" => Val::Safe,
            "string_literal" => {
                let t = self.text(node);
                if t.starts_with("\"\"\"") || t.contains('\\') {
                    Val::Safe
                } else {
                    Val::Str(t[1..t.len().saturating_sub(1)].to_string())
                }
            }
            "character_literal" => {
                let t = self.text(node);
                let inner = &t[1..t.len().saturating_sub(1)];
                let mut it = inner.chars();
                match (it.next(), it.next()) {
                    (Some(c), None) if c != '\\' => Val::Char(c),
                    _ => Val::Safe,
                }
            }
            "true" => Val::Bool(true),
            "false" => Val::Bool(false),
            "null_literal" => Val::Null,
            "identifier" => match env.get(self.text(node)) {
                Some(v) => v.clone(),
                // A name that is not a local or parameter is only a constant
                // when it resolves to a `static final` field (or an enum
                // constant or static import); spelling alone proves nothing.
                None => self.resolve_constant(node),
            },
            "parenthesized_expression" => node
                .named_child(0)
                .map_or(Val::Maybe, |n| self.eval(n, env)),
            "cast_expression" => node
                .child_by_field_name("value")
                .map_or(Val::Maybe, |n| self.eval(n, env)),
            "unary_expression" => {
                let op = node
                    .child_by_field_name("operator")
                    .map(|o| self.text(o))
                    .unwrap_or("");
                let v = node
                    .child_by_field_name("operand")
                    .map_or(Val::Maybe, |n| self.eval(n, env));
                match (op, &v) {
                    ("!", Val::Bool(b)) => Val::Bool(!b),
                    ("-", Val::Int(i)) => Val::Int(-i),
                    _ => v.degrade(),
                }
            }
            "binary_expression" => self.eval_binary(node, env),
            "ternary_expression" => {
                let cond = node
                    .child_by_field_name("condition")
                    .map_or(Val::Maybe, |n| self.eval(n, env));
                let (Some(t), Some(f)) = (
                    node.child_by_field_name("consequence"),
                    node.child_by_field_name("alternative"),
                ) else {
                    return Val::Maybe;
                };
                match cond {
                    Val::Bool(true) => self.eval(t, env),
                    Val::Bool(false) => self.eval(f, env),
                    _ => {
                        let a = self.eval(t, env);
                        let b = self.eval(f, env);
                        join(&a, &b)
                    }
                }
            }
            "assignment_expression" => self.eval_assign(node, env),
            "array_initializer" => {
                let mut c = node.walk();
                let items: Vec<Node<'a>> = node.named_children(&mut c).collect();
                Val::List(items.into_iter().map(|i| self.eval(i, env)).collect())
            }
            "array_creation_expression" => match node.child_by_field_name("value") {
                Some(init) => self.eval(init, env),
                None => Val::Safe,
            },
            "array_access" => {
                let arr = node
                    .child_by_field_name("array")
                    .map_or(Val::Maybe, |n| self.eval(n, env));
                let idx = node
                    .child_by_field_name("index")
                    .map_or(Val::Maybe, |n| self.eval(n, env));
                match (&arr, idx.as_int()) {
                    (Val::List(items), Some(i)) if i >= 0 && (i as usize) < items.len() => {
                        items[i as usize].clone()
                    }
                    _ => arr.degrade(),
                }
            }
            "field_access" => {
                let obj = node.child_by_field_name("object");
                let field = node.child_by_field_name("field").map(|f| self.text(f));
                if let (Some(o), Some("length")) = (obj, field) {
                    if self.eval(o, env).is_safe() {
                        return Val::Safe;
                    }
                }
                if let (Some(o), Some(f)) = (obj, field) {
                    if is_constant_name(f) {
                        match o.kind() {
                            // `this.NAME` is whatever the enclosing class declares.
                            "this" => {
                                return self.resolve_field(node, f, None).unwrap_or(Val::Maybe)
                            }
                            // `local.NAME` reads a field off a value.
                            "identifier" if env.contains_key(self.text(o)) => return Val::Maybe,
                            // A class of this file declares what `Type.NAME` is.
                            "identifier" => {
                                let ty = self.text(o);
                                if self.class_declared_in_file(ty) {
                                    if let Some(v) = self.resolve_field(node, f, Some(ty)) {
                                        return v;
                                    }
                                }
                                return Val::Safe;
                            }
                            // `pkg.Type.NAME`: a constant by convention.
                            "field_access" | "scoped_identifier" => return Val::Safe,
                            _ => {}
                        }
                    }
                }
                Val::Maybe
            }
            "method_invocation" => self.eval_call(node, env),
            "object_creation_expression" => self.eval_new(node, env),
            _ => Val::Maybe,
        }
    }

    fn eval_binary(&mut self, node: Node<'a>, env: &mut Env) -> Val {
        let op = node
            .child_by_field_name("operator")
            .map(|o| self.text(o))
            .unwrap_or("");
        let (Some(ln), Some(rn)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return Val::Maybe;
        };
        let l = self.eval(ln, env);
        // Short-circuit folding keeps the dead operand's effects out.
        match (op, &l) {
            ("&&", Val::Bool(false)) => return Val::Bool(false),
            ("||", Val::Bool(true)) => return Val::Bool(true),
            _ => {}
        }
        let r = self.eval(rn, env);
        if let (Some(a), Some(b)) = (l.as_int(), r.as_int()) {
            let both_int = matches!(l, Val::Int(_)) || matches!(r, Val::Int(_));
            let folded = match op {
                "+" => a.checked_add(b).map(Val::Int),
                "-" => a.checked_sub(b).map(Val::Int),
                "*" => a.checked_mul(b).map(Val::Int),
                "/" if b != 0 => a.checked_div(b).map(Val::Int),
                "%" if b != 0 => a.checked_rem(b).map(Val::Int),
                ">" => Some(Val::Bool(a > b)),
                "<" => Some(Val::Bool(a < b)),
                ">=" => Some(Val::Bool(a >= b)),
                "<=" => Some(Val::Bool(a <= b)),
                "==" => Some(Val::Bool(a == b)),
                "!=" => Some(Val::Bool(a != b)),
                _ => None,
            };
            if let Some(v) = folded {
                // `'a' + 1` style char arithmetic stays an int.
                let _ = both_int;
                return v;
            }
        }
        match (op, &l, &r) {
            ("&&", Val::Bool(a), Val::Bool(b)) => return Val::Bool(*a && *b),
            ("||", Val::Bool(a), Val::Bool(b)) => return Val::Bool(*a || *b),
            ("==", a, b) if a.is_const() && b.is_const() => return Val::Bool(a == b),
            ("!=", a, b) if a.is_const() && b.is_const() => return Val::Bool(a != b),
            ("+", Val::Str(a), b) | ("+", b, Val::Str(a)) if b.is_const() => {
                let other = match b {
                    Val::Str(s) => s.clone(),
                    Val::Int(i) => i.to_string(),
                    Val::Char(c) => c.to_string(),
                    Val::Bool(x) => x.to_string(),
                    _ => "null".to_string(),
                };
                // Operand order matters for the folded text only; safety does not.
                return Val::Str(if matches!(&l, Val::Str(_)) {
                    format!("{a}{other}")
                } else {
                    format!("{other}{a}")
                });
            }
            _ => {}
        }
        if l.is_safe() && r.is_safe() {
            Val::Safe
        } else if matches!(
            op,
            "==" | "!=" | "<" | ">" | "<=" | ">=" | "&&" | "||" | "instanceof"
        ) {
            // A comparison yields a boolean, never the tainted operand.
            Val::Safe
        } else {
            Val::Maybe
        }
    }

    fn eval_assign(&mut self, node: Node<'a>, env: &mut Env) -> Val {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return Val::Maybe;
        };
        let op = node
            .child_by_field_name("operator")
            .map(|o| self.text(o))
            .unwrap_or("=");
        let mut rv = self.eval(right, env);
        if matches!(rv, Val::List(_) | Val::Map(_)) && right.kind() == "identifier" {
            self.escape(right, env);
            rv = Val::Maybe;
        }
        if left.kind() != "identifier" {
            return rv;
        }
        let name = self.text(left).to_string();
        let nv = if op == "=" {
            rv
        } else {
            let old = env.get(&name).cloned().unwrap_or(Val::Maybe);
            if old.is_safe() && rv.is_safe() {
                Val::Safe
            } else {
                Val::Maybe
            }
        };
        env.insert(name, nv.clone());
        nv
    }

    fn eval_args(&mut self, node: Node<'a>, env: &mut Env) -> Vec<Val> {
        let Some(args) = node.child_by_field_name("arguments") else {
            return Vec::new();
        };
        let mut c = args.walk();
        let nodes: Vec<Node<'a>> = args.named_children(&mut c).collect();
        let vals: Vec<Val> = nodes.iter().map(|a| self.eval(*a, env)).collect();
        // A collection handed to another call may be mutated there (or
        // aliased), so it is no longer tracked precisely afterwards.
        for a in nodes {
            self.escape(a, env);
        }
        vals
    }

    /// Stop tracking a collection variable whose identity escapes.
    fn escape(&mut self, node: Node<'a>, env: &mut Env) {
        if node.kind() == "identifier" {
            let name = self.text(node);
            if matches!(env.get(name), Some(Val::List(_) | Val::Map(_))) {
                env.insert(name.to_string(), Val::Maybe);
            }
        }
    }

    fn record(&mut self, node: Node<'a>, args: &[Val]) {
        if self.depth != 0 {
            return;
        }
        // A sink without arguments has nothing to prove safe.
        let safe = !args.is_empty() && args.iter().all(Val::is_safe);
        let e = self
            .rec
            .entry((node.start_byte(), node.end_byte()))
            .or_insert(true);
        *e = *e && safe;
        let per_arg = self
            .rec_args
            .entry((node.start_byte(), node.end_byte()))
            .or_insert_with(|| vec![true; args.len()]);
        if per_arg.len() < args.len() {
            per_arg.resize(args.len(), true);
        }
        for (slot, v) in per_arg.iter_mut().zip(args) {
            *slot = *slot && v.is_safe();
        }
    }

    fn eval_new(&mut self, node: Node<'a>, env: &mut Env) -> Val {
        let ty = node
            .child_by_field_name("type")
            .map(|t| self.text(t))
            .unwrap_or("");
        let base = ty.split('<').next().unwrap_or(ty);
        let base = base.rsplit('.').next().unwrap_or(base);
        let args = self.eval_args(node, env);
        self.record(node, &args);
        match base {
            "ArrayList" | "LinkedList" | "Vector" if args.is_empty() => Val::List(Vec::new()),
            "HashMap" | "LinkedHashMap" | "TreeMap" | "Hashtable" if args.is_empty() => {
                Val::Map(Vec::new())
            }
            _ => {
                if node.child_by_field_name("body").is_none()
                    && args.iter().all(Val::is_safe)
                    && is_value_type(base)
                {
                    Val::Safe
                } else {
                    Val::Maybe
                }
            }
        }
    }

    fn eval_call(&mut self, node: Node<'a>, env: &mut Env) -> Val {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.text(n))
            .unwrap_or("");
        let obj_node = node.child_by_field_name("object");
        // Collection receivers are updated in place.
        if let Some(o) = obj_node {
            if o.kind() == "identifier" {
                let var = self.text(o).to_string();
                if matches!(env.get(&var), Some(Val::List(_) | Val::Map(_))) {
                    let args = self.eval_args(node, env);
                    self.record(node, &args);
                    return self.collection_call(&var, name, args, env);
                }
            }
        }
        let recv = obj_node.map(|o| self.eval(o, env));
        let args = self.eval_args(node, env);
        self.record(node, &args);
        let all_safe = args.iter().all(Val::is_safe);

        if self.html && HTML_ENCODERS.contains(&name) {
            return Val::Safe;
        }

        // StringBuilder-style mutation on a plain local: unsafe input taints
        // the builder itself, not just the returned value.
        if let Some(o) = obj_node {
            if o.kind() == "identifier"
                && !all_safe
                && matches!(
                    name,
                    "append" | "insert" | "replace" | "setCharAt" | "setLength"
                )
            {
                env.insert(self.text(o).to_string(), Val::Maybe);
                return Val::Maybe;
            }
        }

        match (&recv, obj_node) {
            // String/value methods on a proven-safe receiver.
            (Some(r), Some(_)) if r.is_safe() && STRING_PASSTHROUGH.contains(&name) => {
                if all_safe {
                    return fold_string_method(r, name, &args);
                }
                return Val::Maybe;
            }
            (Some(_), Some(o)) if is_static_value_call(self.text(o), name) && all_safe => {
                return Val::Safe;
            }
            // A call to a library or project helper that receives only constants
            // (or values derived from constants) cannot hand back request data:
            // nothing request-derived goes in. Calls that read from the outside
            // world are excluded by name.
            (Some(_), Some(o))
                if all_safe
                    && self.helper_is_trusted(name)
                    && self.is_static_type_ref(o, env)
                    && self.static_call_trusted(o) =>
            {
                return Val::Safe;
            }
            (Some(r), Some(o))
                if all_safe
                    && self.helper_is_trusted(name)
                    && r.is_safe()
                    && self.receiver_call_trusted(o) =>
            {
                return Val::Safe;
            }
            _ => {}
        }

        // Same-file helper (unqualified, `this.` or `new LocalClass().`).
        let local_receiver = match obj_node {
            None => true,
            Some(o) if o.kind() == "this" => true,
            Some(o) if o.kind() == "object_creation_expression" => o
                .child_by_field_name("type")
                .is_some_and(|t| self.class_declared_in_file(self.text(t))),
            _ => false,
        };
        if local_receiver && self.depth < MAX_DEPTH {
            if let Some(m) = self.unique_method(name, args.len()) {
                return self.call_helper(m, args);
            }
        }
        // `Helper.method(..)` where `Helper` is declared in this file: read its
        // body instead of guessing.
        if let Some(o) = obj_node {
            if self.depth < MAX_DEPTH
                && self.is_static_type_ref(o, env)
                && self.class_declared_in_file(self.text(o))
            {
                if let Some(m) = self.unique_method_in(self.text(o), name, args.len()) {
                    return self.call_helper(m, args);
                }
            }
        }
        Val::Maybe
    }

    /// Value of an identifier that is not in the environment. Locals,
    /// parameters, lambda, catch and loop variables all shadow fields, so a
    /// name declared anywhere in the enclosing method is never a constant.
    /// Otherwise the name must resolve to a field declared by an enclosing
    /// class, or be statically imported by name; anything else is unknown.
    fn resolve_constant(&mut self, node: Node<'a>) -> Val {
        let name = self.text(node);
        if !is_constant_name(name) || self.declared_in_method(node, name) {
            return Val::Maybe;
        }
        if let Some(v) = self.resolve_field(node, name, None) {
            return v;
        }
        if self.statically_imported(name) {
            return Val::Safe;
        }
        Val::Maybe
    }

    fn declared_in_method(&self, node: Node<'a>, name: &str) -> bool {
        let mut cur = node;
        let method = loop {
            match cur.kind() {
                "method_declaration" | "constructor_declaration" => break cur,
                _ => match cur.parent() {
                    Some(p) => cur = p,
                    None => return false,
                },
            }
        };
        let mut found = false;
        walk(method, &mut |n| {
            if found {
                return;
            }
            if let Some(p) = n.parent() {
                if n.kind() == "identifier"
                    && self.text(n) == name
                    && (p.child_by_field_name("name") == Some(n)
                        || matches!(
                            p.kind(),
                            "lambda_expression" | "inferred_parameters" | "spread_parameter"
                        ))
                {
                    found = true;
                }
            }
        });
        found
    }

    /// Look `name` up in the field declarations of `class` (by name) or, with
    /// `None`, of the classes enclosing `at`, innermost first. `Some(Safe)` for
    /// a `static final` field with a safe initialiser, an interface field or an
    /// enum constant; `Some(Maybe)` for any other declaration; `None` when no
    /// such class declares it.
    fn resolve_field(&mut self, at: Node<'a>, name: &str, class: Option<&str>) -> Option<Val> {
        let mut scopes = Vec::new();
        match class {
            Some(ty) => walk(self.root, &mut |n| {
                if n.kind() == "class_declaration"
                    && n.child_by_field_name("name")
                        .is_some_and(|x| self.text(x) == ty)
                {
                    scopes.push(n);
                }
            }),
            None => {
                let mut cur = at.parent();
                while let Some(n) = cur {
                    if matches!(
                        n.kind(),
                        "class_declaration"
                            | "interface_declaration"
                            | "enum_declaration"
                            | "record_declaration"
                            | "object_creation_expression"
                    ) {
                        scopes.push(n);
                    }
                    cur = n.parent();
                }
            }
        }
        for scope in scopes {
            let interface = scope.kind() == "interface_declaration";
            let Some(body) = scope
                .child_by_field_name("body")
                .or_else(|| find_child(scope, "class_body"))
            else {
                continue;
            };
            let mut members = Vec::new();
            let mut c = body.walk();
            for m in body.named_children(&mut c) {
                if m.kind() == "enum_body_declarations" {
                    let mut c2 = m.walk();
                    members.extend(m.named_children(&mut c2));
                } else {
                    members.push(m);
                }
            }
            for m in members {
                if m.kind() == "enum_constant"
                    && m.child_by_field_name("name")
                        .is_some_and(|x| self.text(x) == name)
                {
                    return Some(Val::Safe);
                }
                if !matches!(m.kind(), "field_declaration" | "constant_declaration") {
                    continue;
                }
                let modifiers = find_child(m, "modifiers").map_or("", |x| self.text(x));
                let words: Vec<&str> = modifiers.split_whitespace().collect();
                let constant = interface || (words.contains(&"static") && words.contains(&"final"));
                let mut c3 = m.walk();
                for d in m.children_by_field_name("declarator", &mut c3) {
                    if d.child_by_field_name("name")
                        .is_none_or(|x| self.text(x) != name)
                    {
                        continue;
                    }
                    if !constant || self.const_depth >= 4 {
                        return Some(Val::Maybe);
                    }
                    let Some(init) = d.child_by_field_name("value") else {
                        return Some(Val::Maybe);
                    };
                    self.const_depth += 1;
                    let v = self.eval(init, &mut Env::new());
                    self.const_depth -= 1;
                    return Some(v.degrade());
                }
            }
        }
        None
    }

    fn statically_imported(&self, name: &str) -> bool {
        let mut found = false;
        let mut c = self.root.walk();
        for n in self.root.named_children(&mut c) {
            if n.kind() == "import_declaration" {
                let t = self.text(n);
                if t.contains("static")
                    && t.trim_end_matches(';').trim().rsplit('.').next() == Some(name)
                {
                    found = true;
                }
            }
        }
        found
    }

    /// May a `Type.method(safe args)` call be assumed to return a safe value?
    ///
    /// Never for request, thread or security context holders, whose result does
    /// not depend on the arguments. Never for a class declared in this file: its
    /// body is interpreted instead (a helper that reads context then comes back
    /// unknown). A type whose body is not available is trusted only if it is a
    /// JDK or well-known library type, unless
    /// [`TRUST_UNRESOLVED_PROJECT_HELPERS`] is set.
    fn static_call_trusted(&self, receiver: Node<'a>) -> bool {
        let text = self.text(receiver);
        let head = text.split('.').next().unwrap_or("");
        let last = text.rsplit('.').next().unwrap_or("");
        if REQUEST_CONTEXT_TYPES.contains(&last) || self.class_declared_in_file(last) {
            return false;
        }
        if TRUST_UNRESOLVED_PROJECT_HELPERS {
            return true;
        }
        if head.starts_with(|c: char| c.is_ascii_lowercase()) {
            return LIBRARY_PREFIXES.iter().any(|p| text.starts_with(p));
        }
        let mut c = self.root.walk();
        for n in self.root.named_children(&mut c) {
            if n.kind() != "import_declaration" {
                continue;
            }
            let t = self.text(n);
            if t.contains("static") {
                continue;
            }
            let path = t
                .trim_start_matches("import")
                .trim()
                .trim_end_matches(';')
                .trim();
            if path.rsplit('.').next() == Some(head) {
                return LIBRARY_PREFIXES.iter().any(|p| path.starts_with(p));
            }
        }
        JDK_TYPES.contains(&head)
    }

    /// Same question for `value.method(safe args)` on a receiver already proven
    /// safe: never when the chain starts at a request-context holder.
    fn receiver_call_trusted(&self, receiver: Node<'a>) -> bool {
        let mut cur = receiver;
        loop {
            match cur.kind() {
                "method_invocation" => match cur.child_by_field_name("object") {
                    Some(o) => cur = o,
                    None => return true,
                },
                "field_access" | "scoped_identifier" => {
                    let last = self.text(cur).rsplit('.').next().unwrap_or("");
                    return !REQUEST_CONTEXT_TYPES.contains(&last);
                }
                _ => return !REQUEST_CONTEXT_TYPES.contains(&self.text(cur)),
            }
        }
    }

    fn helper_is_trusted(&self, name: &str) -> bool {
        !READS_EXTERNAL_INPUT.contains(&name)
            && !READS_REQUEST_CONTEXT.contains(&name)
            && self
                .trusted_helpers
                .as_ref()
                .is_some_and(|sources| !sources.iter().any(|s| s == name))
    }

    /// `Type.method(..)` / `pkg.Type.method(..)`: the receiver names a class, not
    /// a variable in scope.
    fn is_static_type_ref(&self, node: Node<'a>, env: &Env) -> bool {
        if !matches!(
            node.kind(),
            "identifier" | "field_access" | "scoped_identifier"
        ) {
            return false;
        }
        let text = self.text(node);
        let mut parts = text.split('.');
        let first = parts.next().unwrap_or("");
        let last = text.rsplit('.').next().unwrap_or("");
        env.get(first).is_none()
            && !is_constant_name(last)
            && last.starts_with(|c: char| c.is_ascii_uppercase())
            && text
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
    }

    fn collection_call(&mut self, var: &str, name: &str, args: Vec<Val>, env: &mut Env) -> Val {
        let cur = env.get(var).cloned().unwrap_or(Val::Maybe);
        let (new, ret) = match (cur, name, args.as_slice()) {
            (Val::List(mut v), "add", [x]) => {
                v.push(x.clone());
                (Val::List(v), Val::Safe)
            }
            (Val::List(mut v), "add", [i, x]) if idx_ok(i, v.len() + 1) => {
                v.insert(i.as_int().unwrap() as usize, x.clone());
                (Val::List(v), Val::Safe)
            }
            (Val::List(mut v), "remove", [i @ Val::Int(_)]) if idx_ok(i, v.len()) => {
                let old = v.remove(i.as_int().unwrap() as usize);
                (Val::List(v), old)
            }
            (Val::List(v), "get", [i]) if idx_ok(i, v.len()) => {
                let e = v[i.as_int().unwrap() as usize].clone();
                (Val::List(v), e)
            }
            (Val::List(mut v), "set", [i, x]) if idx_ok(i, v.len()) => {
                let old = std::mem::replace(&mut v[i.as_int().unwrap() as usize], x.clone());
                (Val::List(v), old)
            }
            (Val::List(v), "size" | "isEmpty" | "contains" | "indexOf", _) => {
                (Val::List(v), Val::Safe)
            }
            (Val::Map(mut m), "put", [Val::Str(k), x]) => {
                let old = match m.iter_mut().find(|(key, _)| key == k) {
                    Some(slot) => std::mem::replace(&mut slot.1, x.clone()),
                    None => {
                        m.push((k.clone(), x.clone()));
                        Val::Null
                    }
                };
                (Val::Map(m), old)
            }
            (Val::Map(m), "get", [Val::Str(k)]) => {
                let e = m
                    .iter()
                    .find(|(key, _)| key == k)
                    .map_or(Val::Null, |(_, v)| v.clone());
                (Val::Map(m), e)
            }
            (Val::Map(mut m), "remove", [Val::Str(k)]) => {
                let old = match m.iter().position(|(key, _)| key == k) {
                    Some(p) => m.remove(p).1,
                    None => Val::Null,
                };
                (Val::Map(m), old)
            }
            (Val::Map(m), "containsKey" | "size" | "isEmpty" | "containsValue", _) => {
                (Val::Map(m), Val::Safe)
            }
            // Anything unmodelled: keep only what is still provably safe.
            (cur, _, a) => {
                let v = if cur.is_safe() && a.iter().all(Val::is_safe) {
                    Val::Safe
                } else {
                    Val::Maybe
                };
                (v.clone(), v)
            }
        };
        env.insert(var.to_string(), new);
        ret
    }

    fn class_declared_in_file(&self, ty: &str) -> bool {
        let base = ty.split('<').next().unwrap_or(ty).trim();
        let mut found = false;
        walk(self.root, &mut |n| {
            if n.kind() == "class_declaration" {
                if let Some(name) = n.child_by_field_name("name") {
                    if self.text(name) == base {
                        found = true;
                    }
                }
            }
        });
        found
    }

    fn unique_method_in(&self, class: &str, name: &str, arity: usize) -> Option<Node<'a>> {
        let mut hits = Vec::new();
        walk(self.root, &mut |n| {
            if n.kind() == "class_declaration"
                && n.child_by_field_name("name")
                    .is_some_and(|x| self.text(x) == class)
            {
                walk(n, &mut |m| {
                    if m.kind() == "method_declaration" {
                        if let (Some(nm), Some(ps)) = (
                            m.child_by_field_name("name"),
                            m.child_by_field_name("parameters"),
                        ) {
                            if self.text(nm) == name && ps.named_child_count() == arity {
                                hits.push(m);
                            }
                        }
                    }
                });
            }
        });
        if hits.len() == 1 {
            hits.pop()
        } else {
            None
        }
    }

    fn unique_method(&self, name: &str, arity: usize) -> Option<Node<'a>> {
        let mut hits = Vec::new();
        walk(self.root, &mut |n| {
            if n.kind() == "method_declaration" {
                if let (Some(nm), Some(ps)) = (
                    n.child_by_field_name("name"),
                    n.child_by_field_name("parameters"),
                ) {
                    if self.text(nm) == name && ps.named_child_count() == arity {
                        hits.push(n);
                    }
                }
            }
        });
        if hits.len() == 1 {
            hits.pop()
        } else {
            None
        }
    }

    fn call_helper(&mut self, method: Node<'a>, args: Vec<Val>) -> Val {
        let Some(body) = method.child_by_field_name("body") else {
            return Val::Maybe;
        };
        let mut callee = Env::new();
        if let Some(ps) = method.child_by_field_name("parameters") {
            let mut c = ps.walk();
            for (p, a) in ps.named_children(&mut c).zip(args) {
                if let Some(n) = p.child_by_field_name("name") {
                    callee.insert(self.text(n).to_string(), a);
                }
            }
        }
        let saved = std::mem::take(&mut self.returns);
        self.depth += 1;
        let flow = self.exec(body, &mut callee);
        self.depth -= 1;
        let rets = std::mem::replace(&mut self.returns, saved);
        if rets.is_empty() {
            // Falling off the end of a non-void method cannot happen; a void
            // helper returns nothing a sink could use.
            return if flow == Flow::Next {
                Val::Safe
            } else {
                Val::Maybe
            };
        }
        rets.iter()
            .skip(1)
            .fold(rets[0].clone(), |a, b| join(&a, b))
    }
}

fn find_child<'t>(node: Node<'t>, kind: &str) -> Option<Node<'t>> {
    let mut c = node.walk();
    let found = node.named_children(&mut c).find(|n| n.kind() == kind);
    found
}

fn is_constant_name(name: &str) -> bool {
    name.len() > 1
        && name.starts_with(|c: char| c.is_ascii_uppercase())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn idx_ok(i: &Val, len: usize) -> bool {
    matches!(i, Val::Int(n) if *n >= 0 && (*n as usize) < len)
}

fn is_value_type(base: &str) -> bool {
    matches!(
        base,
        "String"
            | "StringBuilder"
            | "StringBuffer"
            | "Integer"
            | "Long"
            | "Object"
            | "File"
            | "URI"
            | "URL"
    )
}

fn is_static_value_call(receiver: &str, name: &str) -> bool {
    matches!(
        (receiver, name),
        ("String", "valueOf" | "format" | "join")
            | ("Integer", "toString" | "valueOf" | "parseInt")
            | ("Long", "toString" | "valueOf" | "parseLong")
            | ("Math", _)
    )
}

fn fold_string_method(recv: &Val, name: &str, args: &[Val]) -> Val {
    match (recv, name, args) {
        (Val::Str(s), "charAt", [i]) => match i.as_int() {
            Some(n) if n >= 0 => s.chars().nth(n as usize).map_or(Val::Safe, Val::Char),
            _ => Val::Safe,
        },
        (Val::Str(s), "length", []) => Val::Int(s.chars().count() as i64),
        _ => Val::Safe,
    }
}

fn walk<'t>(node: Node<'t>, f: &mut impl FnMut(Node<'t>)) {
    f(node);
    let mut c = node.walk();
    for child in node.named_children(&mut c) {
        walk(child, f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    /// Parse `body` as a class and report whether the `sink(...)` call is safe.
    fn safe(src: &str, html: bool) -> bool {
        let mut p = Parser::new();
        p.set_language(&tree_sitter_java::LANGUAGE.into()).unwrap();
        let tree = p.parse(src, None).unwrap();
        let mut found = None;
        walk(tree.root_node(), &mut |n| {
            if n.kind() == "method_invocation"
                && n.child_by_field_name("name")
                    .is_some_and(|x| &src[x.byte_range()] == "sink")
            {
                found = Some(n);
            }
        });
        sink_args_safe(found.expect("sink call"), src, html, &[])
    }

    fn method(body: &str) -> String {
        format!("class T {{ void m(HttpServletRequest req) {{ String param = req.getParameter(\"x\"); {body} }} }}")
    }

    #[test]
    fn static_helper_with_constant_arguments_is_safe_but_input_readers_are_not() {
        // JDK and library helpers depend only on their arguments. (The old
        // expectation also trusted `Helpers.name("k")` for an unknown project
        // class; that assumption is gone, see the next test.)
        assert!(safe(
            &method("String v = java.util.Objects.toString(\"k\"); sink(v);"),
            false
        ));
        assert!(safe(
            &method("String v = java.util.Arrays.asList(\"k\").get(0); sink(v);"),
            false
        ));
        assert!(!safe(
            &method("String v = Helpers.name(param); sink(v);"),
            false
        ));
        assert!(!safe(
            &method("String v = System.getenv(\"HOME\"); sink(v);"),
            false
        ));
    }

    #[test]
    fn upper_snake_names_are_constants_and_any_unsafe_argument_blocks_the_veto() {
        let src = "class T { static final String BASE_DIR = \"/srv\"; void m() { sink(BASE_DIR + \"x\"); } }";
        assert!(safe(src, false));
        let src = "class T { void m(HttpServletRequest req) { String p = req.getParameter(\"x\"); sink(\"fixed\", p); } }";
        assert!(!safe(src, false));
    }

    #[test]
    fn constant_condition_ternary() {
        let tp = method(
            "int num = 106; String bar = (7 * 18) + num > 200 ? param : \"safe\"; sink(bar);",
        );
        let ok = method(
            "int num = 106; String bar = (7 * 18) + num > 200 ? \"safe\" : param; sink(bar);",
        );
        assert!(!safe(&tp, false));
        assert!(safe(&ok, false));
    }

    #[test]
    fn constant_condition_if() {
        let tp = method("int n = 86; String bar; if ((7 * 42) - n > 200) bar = param; else bar = \"x\"; sink(bar);");
        let ok = method("int n = 86; String bar; if ((7 * 42) - n > 200) bar = \"x\"; else bar = param; sink(bar);");
        assert!(!safe(&tp, false));
        assert!(safe(&ok, false));
    }

    #[test]
    fn unknown_condition_joins_branches() {
        let src = method("String bar = \"a\"; if (param.length() > 3) { bar = param; } sink(bar);");
        assert!(!safe(&src, false));
    }

    #[test]
    fn reassignment_and_sanitiser() {
        let tp = method("String bar = \"ok\"; bar = param; sink(bar);");
        let ok = method("String bar = param; bar = \"ok\"; sink(bar);");
        assert!(!safe(&tp, false));
        assert!(safe(&ok, false));
        let enc = method("String bar = Encode.forHtml(param); sink(bar);");
        assert!(safe(&enc, true));
        assert!(!safe(&enc, false));
    }

    #[test]
    fn list_element_selection() {
        let tp = method("java.util.List<String> l = new java.util.ArrayList<String>(); l.add(\"safe\"); l.add(param); l.add(\"more\"); l.remove(0); String bar = l.get(0); sink(bar);");
        let ok = method("java.util.List<String> l = new java.util.ArrayList<String>(); l.add(\"safe\"); l.add(param); l.add(\"more\"); l.remove(0); String bar = l.get(1); sink(bar);");
        assert!(!safe(&tp, false));
        assert!(safe(&ok, false));
    }

    #[test]
    fn map_element_selection() {
        let tp = method("java.util.HashMap<String, Object> m = new java.util.HashMap<String, Object>(); m.put(\"a\", \"x\"); m.put(\"b\", param); String bar = (String) m.get(\"b\"); sink(bar);");
        let ok = method("java.util.HashMap<String, Object> m = new java.util.HashMap<String, Object>(); m.put(\"a\", \"x\"); m.put(\"b\", param); String bar = (String) m.get(\"a\"); sink(bar);");
        let removed = method("java.util.HashMap<String, Object> m = new java.util.HashMap<String, Object>(); m.put(\"b\", param); m.remove(\"b\"); String bar = (String) m.get(\"b\"); sink(bar);");
        assert!(!safe(&tp, false));
        assert!(safe(&ok, false));
        assert!(safe(&removed, false));
    }

    #[test]
    fn switch_selects_constant() {
        let head = "String guess = \"ABC\"; char t = guess.charAt(1); String bar;";
        let tp = method(&format!("{head} switch (t) {{ case 'A': bar = \"a\"; break; case 'B': bar = param; break; default: bar = \"d\"; }} sink(bar);"));
        let ok = method(&format!("{head} switch (t) {{ case 'A': bar = param; break; case 'B': bar = \"b\"; break; default: bar = param; }} sink(bar);"));
        let unknown = method("String bar; switch (param) { case \"A\": bar = \"a\"; break; default: bar = param; } sink(bar);");
        assert!(!safe(&tp, false));
        assert!(safe(&ok, false));
        assert!(!safe(&unknown, false));
    }

    #[test]
    fn same_file_helper_is_interpreted() {
        let tp = "class T { void m(HttpServletRequest req) { String param = req.getParameter(\"x\"); String bar = new Test().f(param); sink(bar); } private class Test { public String f(String p) { String b = \"x\"; b = p; return b; } } }";
        let ok = "class T { void m(HttpServletRequest req) { String param = req.getParameter(\"x\"); String bar = new Test().f(param); sink(bar); } private class Test { public String f(String p) { String b = p; b = \"x\"; return b; } } }";
        assert!(!safe(tp, false));
        assert!(safe(ok, false));
    }

    #[test]
    fn unknown_values_are_not_safe() {
        assert!(!safe("class T { void m() { sink(field); } }", false));
        assert!(!safe("class T { void m() { sink(other()); } }", false));
    }

    #[test]
    fn upper_snake_parameters_and_other_declared_names_are_never_constants() {
        for src in [
            "class T { void m(@RequestParam String USER_INPUT) { sink(USER_INPUT); } }",
            "class T { void m(HttpServletRequest req, String USER_INPUT) { sink(USER_INPUT); } }",
            "class T { void m(String... ARGS) { sink(ARGS); } }",
            "class T { void m() { items.forEach(ITEM -> sink(ITEM)); } }",
            "class T { void m() { items.forEach((String ITEM) -> sink(ITEM)); } }",
            "class T { void m(java.util.List<String> xs) { for (String ITEM : xs) { sink(ITEM); } } }",
            "class T { void m() { try { run(); } catch (Exception ERR) { sink(ERR); } } }",
            "class T { void m(HttpServletRequest req) { String RAW; RAW = req.getParameter(\"x\"); sink(RAW); } }",
            // A parameter shadows a constant field of the same name.
            "class T { static final String CMD = \"ls\"; void m(String CMD) { sink(CMD); } }",
            // A plain or merely static field is not a constant.
            "class T { static String MODE = \"a\"; void m() { sink(MODE); } }",
            "class T { final String MODE = \"a\"; void m() { sink(MODE); } }",
            "class T { static final String HOME = System.getenv(\"HOME\"); void m() { sink(HOME); } }",
            // Nothing declares it: unknown, not a constant.
            "class T { void m() { sink(UNDECLARED_NAME); } }",
            "class T { void m() { sink(this.UNDECLARED_NAME); } }",
        ] {
            assert!(!safe(src, false), "{src}");
        }
    }

    #[test]
    fn upper_snake_names_that_resolve_to_constants_are_safe() {
        for src in [
            "class T { static final String BASE = \"ls\"; void m() { sink(BASE); } }",
            "class T { private static final String BASE = \"ls\"; static final String FULL = BASE + \" -l\"; void m() { sink(FULL); } }",
            "class T { static final String BASE = \"ls\"; void m() { sink(T.BASE); } }",
            "class T { static final String BASE = \"ls\"; void m() { sink(this.BASE); } }",
            "interface K { String BASE = \"ls\"; default void m() { sink(BASE); } }",
            "enum E { FIRST, SECOND; void m() { sink(FIRST); } }",
            "import static a.b.Config.BASE; class T { void m() { sink(BASE); } }",
            "class T { static class N { static final String BASE = \"ls\"; void m() { sink(BASE); } } }",
        ] {
            assert!(safe(src, false), "{src}");
        }
    }

    #[test]
    fn helpers_that_read_request_context_are_not_safe() {
        for src in [
            // Body is in the file and reads thread state.
            "class T { static final ThreadLocal<String> CURRENT = new ThreadLocal<>(); void m() { sink(Helper.currentInput()); } } class Helper { static final ThreadLocal<String> CURRENT = new ThreadLocal<>(); static String currentInput() { return CURRENT.get(); } }",
            // Body is in the file and returns a static field set from a request.
            "class T { void m() { sink(Helper.last()); } } class Helper { static String last; static void set(HttpServletRequest r) { last = r.getParameter(\"x\"); } static String last() { return last; } }",
            // Body is in the file and calls a source.
            "class T { void m() { sink(Helper.fromRequest()); } } class Helper { static String fromRequest() { return ((javax.servlet.http.HttpServletRequest) RequestContextHolder.getRequestAttributes()).getParameter(\"x\"); } }",
            // Context holders are never trusted, in the file or not.
            "class T { void m() { sink(RequestContextHolder.currentRequestAttributes()); } }",
            "class T { void m() { sink(RequestContextHolder.currentRequestAttributes().getAttribute(\"user\", 0)); } }",
            "class T { void m() { sink(SecurityContextHolder.getContext().getAuthentication().getName()); } }",
            "class T { void m() { sink(MDC.get(\"user\")); } }",
            // An overloaded or recursive helper cannot be resolved.
            "class T { void m() { sink(Helper.a(\"k\")); } } class Helper { static String a(String k) { return CURRENT.get(); } static String a(int k) { return \"x\"; } }",
        ] {
            assert!(!safe(src, false), "{src}");
        }
    }

    #[test]
    fn helpers_whose_body_is_in_the_file_are_judged_by_the_body() {
        for src in [
            "class T { void m() { sink(Helper.name(\"k\")); } } class Helper { static String name(String k) { return k + \"x\"; } }",
            "class T { void m() { sink(Helper.fixed()); } } class Helper { static final String BASE = \"a\"; static String fixed() { return BASE; } }",
        ] {
            assert!(safe(src, false), "{src}");
        }
        // The body returns its (request-derived) argument.
        let src = "class T { void m(HttpServletRequest req) { sink(Helper.id(req.getParameter(\"x\"))); } } class Helper { static String id(String k) { return k; } }";
        assert!(!safe(src, false));
    }

    #[test]
    fn project_helper_declared_elsewhere_is_unknown_even_with_safe_arguments() {
        // The body is not available: it may ignore its arguments and read
        // request, thread or static state, so nothing is proven.
        for body in [
            "sink(Elsewhere.make(\"k\"));",
            "sink(Elsewhere.currentInput());",
            "sink(pkg.Elsewhere.make(\"k\"));",
            "String v = pkg.Helpers.make().name(\"k\"); sink(v);",
            "sink(Elsewhere.make(param));",
        ] {
            assert!(!safe(&method(body), false), "{body}");
        }
        // JDK and well-known library calls are still a function of their arguments.
        assert!(safe(&method("sink(String.valueOf(\"k\"));"), false));
        assert!(safe(
            &method("sink(java.nio.file.Paths.get(\"/srv\", \"k\"));"),
            false
        ));
    }
}
