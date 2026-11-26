//! Code graph export: symbols, call edges, HTTP routes and sink calls as versioned JSON.
//!
//! `foxguard graph <path>` walks a folder, parses JavaScript/TypeScript, Python, Java and Kotlin
//! with the same tree-sitter grammars the scanner uses, and prints one JSON document (schema
//! version 1). A call edge carries the callee name as written; for Java and Kotlin it also carries
//! the receiver's declared type, resolved through chains, fields, generics, interface dispatch and
//! Spring wiring (`types`, `resolve`). It is not a data-flow proof; the taint engines remain the
//! source of truth for findings. Other languages are counted under `unsupported`.
//!
//! Security configuration outside annotations (Spring Security URL rules, `web.xml`, filters) is
//! mapped onto routes by `security`.
//!
//! The `taintSummaries` array holds the per-method summaries of the Java taint engine, keyed by
//! class and symbol, when `--taint-summaries` is given, and is empty otherwise.

mod java;
mod kotlin;
mod resolve;
mod security;
mod types;

#[cfg(test)]
mod security_tests;

#[cfg(test)]
mod resolve_tests;

#[cfg(test)]
mod taint_tests;

#[cfg(test)]
mod kotlin_tests;

use crate::engine::parser::parse_path;
use crate::engine::scanner::detect_language;
use crate::Language;
use ignore::WalkBuilder;
use rayon::prelude::*;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;
use tree_sitter::Node;

pub const GRAPH_SCHEMA_VERSION: u32 = 1;
const MAX_FILES: usize = 200_000;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_TAINT_BYTES: usize = 300 * 1024;
/// A Java method name defined more often than this is not followed by name (see `resolve`).
const MAX_JAVA_NAME_DEFS: usize = resolve::MAX_NAME_DEFS;
/// Calls kept in the output; the consumer's validator accepts two million.
const MAX_CALLS: usize = 1_000_000;

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GraphSymbol {
    pub id: String,
    pub name: String,
    pub qualified: String,
    pub kind: &'static str,
    pub file: String,
    pub line: usize,
    pub end_line: usize,
    pub language: &'static str,
}

#[derive(Debug, Serialize, Clone)]
pub struct SinkTag {
    pub category: &'static str,
    pub text: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct GraphCall {
    pub from: String,
    pub name: String,
    pub text: String,
    pub file: String,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink: Option<SinkTag>,
    /// Declared type (simple name) of the receiver, when a variable, field or class name gives one.
    /// Java only. A consumer joining the call to symbols prefers methods of that class.
    #[serde(rename = "receiverType", skip_serializing_if = "Option::is_none")]
    pub receiver_type: Option<String>,
    /// The call looks like an authentication, authorization or ownership check (by name only).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub auth: bool,
    /// The receiver as a path from a known type, for the resolver (Java and Kotlin); not serialized.
    #[serde(skip)]
    pub recv: Option<types::RecvPath>,
    /// Symbol indices the call can reach after resolution; not serialized.
    #[serde(skip)]
    pub cand: Option<Box<[u32]>>,
}

/// Where an auth signal on a route came from: a URL rule, a deployment descriptor or a filter.
#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct AuthSource {
    pub signal: String,
    /// `file:line` and the rule as written.
    pub source: String,
    /// `public`, `authenticated`, `role`, `denied`, `filter` or `annotation`.
    pub access: &'static str,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GraphRoute {
    pub method: String,
    pub path: String,
    pub file: String,
    pub line: usize,
    /// A symbol id, or `ref:<name>` when the handler is named but defined elsewhere.
    pub handler: String,
    pub middleware: Vec<String>,
    pub framework: &'static str,
    /// Guard annotations or auth-like middleware on the route itself (Java annotations, JS/Python middleware).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub auth_signals: Vec<String>,
    /// The rule behind each signal outside the handler itself (URL rules, `web.xml`, filters), and the
    /// `permitAll` rules that make the route public.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub auth_sources: Vec<AuthSource>,
    /// An explicit `permitAll`, `@PermitAll` or unrestricted `web.xml` constraint covers the route and
    /// no auth signal does: the route is open on purpose.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub public: bool,
    /// Set by `--missing-guard`: sink categories the handler reaches within four call hops.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sinks_reachable: Vec<&'static str>,
    /// Set by `--missing-guard`: the handler reaches a data sink and no auth signal was found on the
    /// route or on any call within four hops.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_guard: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeGraph {
    pub version: u32,
    pub producer: &'static str,
    pub root: String,
    pub files: usize,
    pub symbols: Vec<GraphSymbol>,
    pub calls: Vec<GraphCall>,
    pub routes: Vec<GraphRoute>,
    pub taint_summaries: Vec<TaintSummaryOut>,
    pub unsupported: BTreeMap<String, usize>,
    pub truncated: bool,
    /// Java and Kotlin calls left out because their name is defined too often to follow, even after
    /// ranking the candidates by receiver type, imports and package. Calls to methods defined nowhere
    /// in the tree (library calls) are not counted; they are in `callStats.external`.
    pub dropped_calls: usize,
    /// How the Java and Kotlin calls resolved (additive; absent when there were none).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_stats: Option<resolve::CallStats>,
    /// Caveats the consumer should show next to the answer (for example URL-pattern security rules).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// Classes of the tree, for the resolver; not serialized.
    #[serde(skip)]
    pub types: types::TypeTable,
}

/// One entry of `taintSummaries`: how a method's parameters reach sinks and its return value,
/// from the Java taint engine's cross-file summaries (name-keyed, same as the scanner uses).
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TaintSummaryOut {
    pub file: String,
    pub function: String,
    /// `Class.method`: the same key as the matching symbol's `qualified`, so same-named methods of
    /// different classes stay apart.
    pub qualified: String,
    /// Id of the matching symbol (`file#qualified@line`), the exact join key for the consumer.
    pub symbol: String,
    /// Number of parameters; `paramIndex` values index them, and overloads differ in it.
    pub arity: usize,
    pub language: &'static str,
    pub params_to_return: Vec<usize>,
    pub params_to_sink: Vec<ParamSinkOut>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ParamSinkOut {
    pub param_index: usize,
    pub rule_id: String,
    pub description: String,
}

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static regex"))
}

/// Category of a sink for a dotted callee text, by name only.
pub fn classify_sink(text: &str) -> Option<&'static str> {
    static CMD: OnceLock<Regex> = OnceLock::new();
    static EVAL: OnceLock<Regex> = OnceLock::new();
    static SQL: OnceLock<Regex> = OnceLock::new();
    static FILE: OnceLock<Regex> = OnceLock::new();
    static NET: OnceLock<Regex> = OnceLock::new();
    static DESER: OnceLock<Regex> = OnceLock::new();
    static TPL: OnceLock<Regex> = OnceLock::new();
    static REDIR: OnceLock<Regex> = OnceLock::new();
    let t = text;
    let table: [(&str, &'static OnceLock<Regex>, &str); 8] = [
        (
            "command",
            &CMD,
            r"(^|\.)(exec|execSync|execFile|execFileSync|spawn|spawnSync)$|^os\.(system|popen)$|^subprocess\.\w+$",
        ),
        (
            "code-eval",
            &EVAL,
            r"^(eval|Function|exec|compile)$|^vm\.(runIn\w+|Script)$",
        ),
        (
            "sql",
            &SQL,
            r"(^|\.)(query|raw|queryRaw|\$queryRaw|\$executeRaw|execute|executemany|executescript)$",
        ),
        (
            "file",
            &FILE,
            r"(^|\.)(readFile|readFileSync|writeFile|writeFileSync|createReadStream|sendFile|unlink|unlinkSync|rmSync|send_file|send_from_directory)$|^open$|^shutil\.\w+$|^os\.(remove|unlink|rename)$",
        ),
        (
            "network",
            &NET,
            r"^(fetch|axios|got)$|(^|\.)(request|urlopen)$|^axios\.\w+$|^requests\.\w+$|^httpx\.\w+$",
        ),
        (
            "deserialize",
            &DESER,
            r"^pickle\.loads?$|^yaml\.(load|unsafe_load)$|^marshal\.loads?$|(^|\.)(unserialize|deserialize)$",
        ),
        (
            "template",
            &TPL,
            r"^render_template_string$|^(ejs|pug|handlebars)\.render$",
        ),
        ("redirect", &REDIR, r"(^|\.)redirect$"),
    ];
    table
        .iter()
        .find(|(_, cell, pattern)| re(cell, pattern).is_match(t))
        .map(|(category, _, _)| *category)
}

fn auth_like(name: &str) -> bool {
    static AUTH: OnceLock<Regex> = OnceLock::new();
    re(
        &AUTH,
        r"(?i)auth|permission|owner|can[A-Z_]|may[A-Z_]|guard|require|login|session|verify|jwt|token|acl|policy|role|admin|belongs|is_?allowed|csrf|protect",
    )
    .is_match(name)
}

#[derive(Default)]
struct FileGraph {
    symbols: Vec<GraphSymbol>,
    calls: Vec<GraphCall>,
    routes: Vec<GraphRoute>,
    notes: Vec<String>,
    taint: Vec<TaintSummaryOut>,
    security: security::FileSecurity,
    classes: Vec<types::ClassDef>,
    scope: types::FileScope,
}

struct Ctx<'a> {
    file: &'a str,
    src: &'a [u8],
    lang: &'static str,
    out: FileGraph,
    /// Function nodes pre-named by their parent (variable declarator, route call, pair).
    names: HashMap<usize, (String, &'static str)>,
    router_mw: HashMap<String, Vec<String>>,
}

impl<'a> Ctx<'a> {
    fn text(&self, n: Node) -> String {
        n.utf8_text(self.src).unwrap_or("").to_string()
    }

    fn add_symbol(&mut self, name: &str, qualified: &str, kind: &'static str, n: Node) -> String {
        let line = n.start_position().row + 1;
        let id = format!("{}#{}@{}", self.file, qualified, line);
        self.out.symbols.push(GraphSymbol {
            id: id.clone(),
            name: name.to_string(),
            qualified: qualified.to_string(),
            kind,
            file: self.file.to_string(),
            line,
            end_line: n.end_position().row + 1,
            language: self.lang,
        });
        id
    }

    fn add_call(&mut self, from: &str, callee: Node) {
        let text: String = self
            .text(callee)
            .split_whitespace()
            .collect::<String>()
            .replace("?.", ".");
        let name = text.rsplit('.').next().unwrap_or("").to_string();
        if name.is_empty() {
            return;
        }
        let sink = classify_sink(&text).map(|category| SinkTag {
            category,
            text: text.clone(),
        });
        let auth = auth_like(&name);
        self.out.calls.push(GraphCall {
            from: from.to_string(),
            name,
            text,
            file: self.file.to_string(),
            line: callee.start_position().row + 1,
            sink,
            auth,
            receiver_type: None,
            recv: None,
            cand: None,
        });
    }
}

const HTTP_VERBS: [&str; 8] = [
    "get", "post", "put", "patch", "delete", "all", "options", "head",
];

fn unquote(s: &str) -> Option<String> {
    let t = s.trim();
    let q = t.chars().next()?;
    if (q == '"' || q == '\'' || q == '`') && t.len() >= 2 && t.ends_with(q) {
        Some(t[1..t.len() - 1].to_string())
    } else {
        None
    }
}

fn last_ident(text: &str) -> String {
    let head: String = text
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$' || *c == '.')
        .collect();
    head.rsplit('.').next().unwrap_or("").to_string()
}

fn args_of(call: Node) -> Vec<Node> {
    let Some(args) = call.child_by_field_name("arguments") else {
        return vec![];
    };
    let mut cursor = args.walk();
    let v: Vec<Node> = args.named_children(&mut cursor).collect();
    v
}

fn is_function_node(kind: &str) -> bool {
    matches!(
        kind,
        "arrow_function" | "function_expression" | "function" | "generator_function"
    )
}

fn walk_js(ctx: &mut Ctx, node: Node, current: &str, class: Option<&str>) {
    let kind = node.kind();
    let mut next_current = current.to_string();
    let mut next_class = class.map(|s| s.to_string());
    match kind {
        "class_declaration" | "class" => {
            if let Some(n) = node.child_by_field_name("name") {
                next_class = Some(ctx.text(n));
            }
        }
        "function_declaration" | "generator_function_declaration" => {
            if let Some(n) = node.child_by_field_name("name") {
                let name = ctx.text(n);
                next_current = ctx.add_symbol(&name, &name, "function", node);
            }
        }
        "method_definition" => {
            if let Some(n) = node.child_by_field_name("name") {
                let name = ctx.text(n);
                let q = class
                    .map(|c| format!("{}.{}", c, name))
                    .unwrap_or_else(|| name.clone());
                next_current = ctx.add_symbol(&name, &q, "method", node);
            }
        }
        "variable_declarator" | "pair" | "public_field_definition" => {
            let name_node = node
                .child_by_field_name("name")
                .or_else(|| node.child_by_field_name("key"));
            if let (Some(n), Some(v)) = (name_node, node.child_by_field_name("value")) {
                if is_function_node(v.kind()) {
                    ctx.names.insert(v.id(), (ctx.text(n), "function"));
                }
            }
        }
        "assignment_expression" => {
            if let (Some(l), Some(r)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                if is_function_node(r.kind()) {
                    ctx.names
                        .insert(r.id(), (last_ident(&ctx.text(l)), "function"));
                }
            }
        }
        k if is_function_node(k) => {
            if let Some((name, kind)) = ctx.names.get(&node.id()).cloned() {
                next_current = ctx.add_symbol(&name, &name, kind, node);
            }
        }
        "call_expression" => {
            if let Some(f) = node.child_by_field_name("function") {
                js_route(ctx, node, f, current);
                ctx.add_call(current, f);
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    let children: Vec<Node> = node.children(&mut cursor).collect();
    for c in children {
        walk_js(ctx, c, &next_current, next_class.as_deref());
    }
}

fn js_route(ctx: &mut Ctx, call: Node, callee: Node, _current: &str) {
    if callee.kind() != "member_expression" {
        return;
    }
    let (Some(obj), Some(prop)) = (
        callee.child_by_field_name("object"),
        callee.child_by_field_name("property"),
    ) else {
        return;
    };
    let verb = ctx.text(prop);
    let receiver = ctx.text(obj);
    let args = args_of(call);
    if verb == "use" {
        let names: Vec<String> = args
            .iter()
            .filter(|a| !matches!(a.kind(), "string" | "template_string"))
            .map(|a| last_ident(&ctx.text(*a)))
            .filter(|n| !n.is_empty())
            .collect();
        if !names.is_empty() {
            ctx.router_mw.entry(receiver).or_default().extend(names);
        }
        return;
    }
    if !HTTP_VERBS.contains(&verb.as_str()) || args.len() < 2 {
        return;
    }
    let Some(path) = unquote(&ctx.text(args[0])) else {
        return;
    };
    if !(path.starts_with('/') || path == "*") {
        return;
    }
    let mut middleware: Vec<String> = ctx.router_mw.get(&receiver).cloned().unwrap_or_default();
    for a in &args[1..args.len() - 1] {
        let n = last_ident(&ctx.text(*a));
        middleware.push(if n.is_empty() {
            "<inline>".to_string()
        } else {
            n
        });
    }
    let last = args[args.len() - 1];
    let method = verb.to_uppercase();
    let handler = if is_function_node(last.kind()) {
        let name = format!("<{} {}>", method, path);
        ctx.names.insert(last.id(), (name.clone(), "route-handler"));
        // The symbol is created when the walker reaches the function node; its id is deterministic.
        format!("{}#{}@{}", ctx.file, name, last.start_position().row + 1)
    } else {
        format!("ref:{}", last_ident(&ctx.text(last)))
    };
    ctx.out.routes.push(GraphRoute {
        method,
        path,
        file: ctx.file.to_string(),
        line: call.start_position().row + 1,
        handler,
        middleware,
        framework: "express-like",
        auth_signals: vec![],
        auth_sources: vec![],
        public: false,
        sinks_reachable: vec![],
        missing_guard: None,
    });
}

fn decorator_names<'t>(ctx: &Ctx, deco: Node<'t>) -> (String, Option<Node<'t>>) {
    // `@a.b(...)` or `@a`: the expression is the first named child.
    let mut cursor = deco.walk();
    let expr = deco.named_children(&mut cursor).next();
    match expr {
        Some(e) if e.kind() == "call" => {
            let f = e.child_by_field_name("function");
            (f.map(|f| ctx.text(f)).unwrap_or_default(), Some(e))
        }
        Some(e) => (ctx.text(e), None),
        None => (String::new(), None),
    }
}

fn walk_py(ctx: &mut Ctx, node: Node, current: &str, class: Option<&str>) {
    let mut next_current = current.to_string();
    let mut next_class = class.map(|s| s.to_string());
    match node.kind() {
        "class_definition" => {
            if let Some(n) = node.child_by_field_name("name") {
                next_class = Some(ctx.text(n));
            }
        }
        "function_definition" => {
            if let Some(n) = node.child_by_field_name("name") {
                let name = ctx.text(n);
                let q = class
                    .map(|c| format!("{}.{}", c, name))
                    .unwrap_or_else(|| name.clone());
                let id = ctx.add_symbol(
                    &name,
                    &q,
                    if class.is_some() {
                        "method"
                    } else {
                        "function"
                    },
                    node,
                );
                if let Some(parent) = node.parent().filter(|p| p.kind() == "decorated_definition") {
                    py_routes(ctx, node, parent, &id);
                }
                next_current = id;
                next_class = None;
            }
        }
        "call" => {
            if let Some(f) = node.child_by_field_name("function") {
                ctx.add_call(current, f);
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    let children: Vec<Node> = node.children(&mut cursor).collect();
    for c in children {
        walk_py(ctx, c, &next_current, next_class.as_deref());
    }
}

fn depends_names(ctx: &Ctx, n: Node, out: &mut Vec<String>) {
    if n.kind() == "call" {
        if let Some(f) = n.child_by_field_name("function") {
            if ctx.text(f) == "Depends" {
                if let Some(a) = args_of(n).first() {
                    let name = last_ident(&ctx.text(*a));
                    if !name.is_empty() {
                        out.push(name);
                    }
                }
            }
        }
    }
    let mut cursor = n.walk();
    let kids: Vec<Node> = n.children(&mut cursor).collect();
    for k in kids {
        depends_names(ctx, k, out);
    }
}

fn py_routes(ctx: &mut Ctx, func: Node, decorated: Node, id: &str) {
    let mut cursor = decorated.walk();
    let decos: Vec<Node> = decorated
        .children(&mut cursor)
        .filter(|c| c.kind() == "decorator")
        .collect();
    let parsed: Vec<(String, Option<Node>)> =
        decos.iter().map(|d| decorator_names(ctx, *d)).collect();
    let mut depends = Vec::new();
    if let Some(params) = func.child_by_field_name("parameters") {
        depends_names(ctx, params, &mut depends);
    }
    for (i, (text, call)) in parsed.iter().enumerate() {
        let verb = text.rsplit('.').next().unwrap_or("");
        if !text.contains('.')
            || ![
                "route", "get", "post", "put", "patch", "delete", "head", "options",
            ]
            .contains(&verb)
        {
            continue;
        }
        let Some(call) = call else { continue };
        let args = args_of(*call);
        let Some(path) = args.first().and_then(|a| unquote(&ctx.text(*a))) else {
            continue;
        };
        let call_text = ctx.text(*call);
        let mut methods = vec![verb.to_uppercase()];
        if verb == "route" {
            static METHODS: OnceLock<Regex> = OnceLock::new();
            static ITEM: OnceLock<Regex> = OnceLock::new();
            let list = re(&METHODS, r"methods\s*=\s*[\[(]([^\])]*)[\])]")
                .captures(&call_text)
                .map(|c| c[1].to_string());
            methods = match list {
                Some(l) => re(&ITEM, r#"['"](\w+)['"]"#)
                    .captures_iter(&l)
                    .map(|c| c[1].to_uppercase())
                    .collect(),
                None => vec!["GET".to_string()],
            };
            if methods.is_empty() {
                methods = vec!["GET".to_string()];
            }
        }
        let mut middleware: Vec<String> = parsed
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, (t, _))| t.rsplit('.').next().unwrap_or("").to_string())
            .collect();
        depends_names(ctx, *call, &mut middleware);
        middleware.extend(depends.clone());
        for method in methods {
            ctx.out.routes.push(GraphRoute {
                method,
                path: path.clone(),
                file: ctx.file.to_string(),
                line: decos[i].start_position().row + 1,
                handler: id.to_string(),
                middleware: middleware.clone(),
                framework: "flask-fastapi",
                auth_signals: vec![],
                auth_sources: vec![],
                public: false,
                sinks_reachable: vec![],
                missing_guard: None,
            });
        }
    }
}

/// Options for [`build_graph_with`].
#[derive(Debug, Clone, Default)]
pub struct GraphOptions {
    /// Fill `taintSummaries` from the Java taint engine (slower: one analysis per parameter and rule).
    pub taint_summaries: bool,
    /// Resolve calls by name and declared receiver type only, as the first version did. For
    /// comparing the resolver against its predecessor.
    pub legacy_resolution: bool,
}

enum FileOutcome {
    Graph(Box<FileGraph>),
    TimedOut,
    Skipped,
}

fn java_summaries(rel: &str, source: &str, root: Node) -> Vec<TaintSummaryOut> {
    use crate::rules::java_taint::{extract_method_summaries, java_taint_rule_specs};
    let specs = java_taint_rule_specs();
    extract_method_summaries(root, source, &specs)
        .into_iter()
        .map(|m| {
            let qualified = if m.class.is_empty() {
                m.summary.name.clone()
            } else {
                format!("{}.{}", m.class, m.summary.name)
            };
            TaintSummaryOut {
                file: rel.to_string(),
                symbol: format!("{}#{}@{}", rel, qualified, m.line),
                qualified,
                arity: m.arity,
                function: m.summary.name,
                language: "java",
                params_to_return: m.summary.params_to_return,
                params_to_sink: m
                    .summary
                    .params_to_sink
                    .into_iter()
                    .map(|f| ParamSinkOut {
                        param_index: f.param_index,
                        rule_id: f.sink_rule_id,
                        description: f.sink_description,
                    })
                    .collect(),
            }
        })
        .collect()
}

fn graph_file(
    rel: &str,
    source: &str,
    lang: Language,
    path: &Path,
    opts: &GraphOptions,
) -> FileOutcome {
    let Some(tree) = parse_path(source, lang, path) else {
        return if crate::engine::budget::expired() {
            FileOutcome::TimedOut
        } else {
            FileOutcome::Skipped
        };
    };
    if lang == Language::Java {
        let mut fg = java::extract(rel, source, tree.root_node());
        if opts.taint_summaries
            && source.len() <= MAX_TAINT_BYTES
            && !crate::engine::budget::expired()
        {
            fg.taint = java_summaries(rel, source, tree.root_node());
        }
        return FileOutcome::Graph(Box::new(fg));
    }
    if lang == Language::Kotlin {
        return FileOutcome::Graph(Box::new(kotlin::extract(rel, source, tree.root_node())));
    }
    let (lang_name, is_js) = match lang {
        Language::JavaScript => ("javascript", true),
        Language::Python => ("python", false),
        _ => return FileOutcome::Skipped,
    };
    let mut ctx = Ctx {
        file: rel,
        src: source.as_bytes(),
        lang: lang_name,
        out: FileGraph::default(),
        names: HashMap::new(),
        router_mw: HashMap::new(),
    };
    let root = tree.root_node();
    let module = ctx.add_symbol("<module>", "<module>", "module", root);
    if is_js {
        walk_js(&mut ctx, root, &module, None);
    } else {
        walk_py(&mut ctx, root, &module, None);
    }
    FileOutcome::Graph(Box::new(ctx.out))
}

/// Resolve `ref:<name>` handlers against the symbols of the whole graph (same file first).
fn resolve_refs(g: &mut CodeGraph) {
    let mut by_name: HashMap<&str, Vec<&GraphSymbol>> = HashMap::new();
    for s in &g.symbols {
        if s.kind == "function" || s.kind == "method" {
            by_name.entry(s.name.as_str()).or_default().push(s);
        }
    }
    let resolved: Vec<String> = g
        .routes
        .iter()
        .map(|r| match r.handler.strip_prefix("ref:") {
            Some(name) => {
                let c = by_name.get(name).cloned().unwrap_or_default();
                c.iter()
                    .find(|s| s.file == r.file)
                    .or(c.first())
                    .map(|s| s.id.clone())
                    .unwrap_or_else(|| format!("unresolved:{}", name))
            }
            None => r.handler.clone(),
        })
        .collect();
    for (r, h) in g.routes.iter_mut().zip(resolved) {
        r.handler = h;
    }
}

/// Sink categories that count as a data sink for `missingGuard`.
const DATA_SINKS: [&str; 5] = ["command", "code-eval", "sql", "file", "deserialize"];
/// Call hops followed from a handler.
const GUARD_HOPS: usize = 4;
/// A name defined this many times is too generic to follow by name.
const MAX_NAME_FANOUT: usize = 12;
/// Symbols visited per route.
const GUARD_NODE_BUDGET: usize = 3000;

/// The class a method symbol belongs to: `A.B.m` gives `B`.
fn class_of(qualified: &str) -> &str {
    let mut parts = qualified.rsplit('.');
    parts.next();
    parts.next().unwrap_or("")
}

/// Symbols of one name, also grouped by the class they belong to.
#[derive(Default)]
struct NameEntry<'a> {
    all: Vec<&'a GraphSymbol>,
    by_class: HashMap<&'a str, Vec<&'a GraphSymbol>>,
}

type ByName<'a> = HashMap<&'a str, NameEntry<'a>>;

fn index_by_name<'a>(symbols: impl Iterator<Item = &'a GraphSymbol>) -> ByName<'a> {
    let mut by_name: ByName = HashMap::new();
    for s in symbols {
        let e = by_name.entry(s.name.as_str()).or_default();
        e.all.push(s);
        e.by_class
            .entry(class_of(&s.qualified))
            .or_default()
            .push(s);
    }
    by_name
}

/// The symbols a call can reach: every symbol of that name, narrowed to the receiver's declared type
/// when it is known. An exact class match wins; otherwise a class whose name starts or ends with the
/// type (`UserService` and `UserServiceImpl`); otherwise all of them.
fn narrow<'a>(entry: &NameEntry<'a>, receiver: Option<&str>) -> Vec<&'a GraphSymbol> {
    let Some(t) = receiver else {
        return entry.all.clone();
    };
    if let Some(exact) = entry.by_class.get(t) {
        return exact.clone();
    }
    if t.len() >= 4 {
        let fuzzy: Vec<&GraphSymbol> = entry
            .by_class
            .iter()
            .filter(|(c, _)| c.starts_with(t) || c.ends_with(t))
            .flat_map(|(_, v)| v.iter().copied())
            .collect();
        if !fuzzy.is_empty() {
            return fuzzy;
        }
    }
    entry.all.clone()
}

/// Memo of [`narrow`] by (callee name, receiver type): a tree has far fewer distinct pairs than calls.
#[derive(Default)]
struct NarrowCache<'a> {
    memo: HashMap<(&'a str, &'a str), Vec<&'a GraphSymbol>>,
}

impl<'a> NarrowCache<'a> {
    fn fill(&mut self, by_name: &ByName<'a>, c: &'a GraphCall) {
        let key = (c.name.as_str(), c.receiver_type.as_deref().unwrap_or(""));
        if self.memo.contains_key(&key) {
            return;
        }
        if let Some(cands) = by_name.get(key.0) {
            let t = (!key.1.is_empty()).then_some(key.1);
            self.memo.insert(key, narrow(cands, t));
        }
    }

    fn get(&self, c: &'a GraphCall) -> Option<&Vec<&'a GraphSymbol>> {
        self.memo
            .get(&(c.name.as_str(), c.receiver_type.as_deref().unwrap_or("")))
    }
}

/// For every route: the sink categories its handler reaches and whether it is unguarded.
///
/// A route is `missingGuard` when its handler reaches a data sink within four call hops (by name) and
/// neither the route (middleware, guard annotations) nor any call on the way looks like an auth,
/// permission or ownership check. A handler that reaches no data sink is not flagged.
pub fn mark_missing_guards(g: &mut CodeGraph) {
    let by_name = index_by_name(
        g.symbols
            .iter()
            .filter(|s| s.kind == "function" || s.kind == "method"),
    );
    let mut from: HashMap<&str, Vec<&GraphCall>> = HashMap::new();
    let mut cache = NarrowCache::default();
    for c in &g.calls {
        from.entry(c.from.as_str()).or_default().push(c);
        if c.cand.is_none() {
            cache.fill(&by_name, c);
        }
    }
    let marks: Vec<(bool, Vec<&'static str>)> = g
        .routes
        .par_iter()
        .map(|r| {
            let mut guarded = !r.auth_signals.is_empty();
            let mut sinks: Vec<&'static str> = Vec::new();
            let mut seen: HashSet<&str> = HashSet::new();
            let mut frontier = vec![r.handler.as_str()];
            'hops: for _ in 0..GUARD_HOPS {
                let mut next = vec![];
                for id in frontier {
                    if !seen.insert(id) {
                        continue;
                    }
                    if seen.len() > GUARD_NODE_BUDGET {
                        break 'hops;
                    }
                    for c in from.get(id).into_iter().flatten() {
                        guarded |= c.auth;
                        if let Some(s) = &c.sink {
                            if !sinks.contains(&s.category) {
                                sinks.push(s.category);
                            }
                        }
                        if let Some(cand) = &c.cand {
                            if cand.len() <= MAX_NAME_FANOUT {
                                next.extend(
                                    cand.iter().map(|&i| g.symbols[i as usize].id.as_str()),
                                );
                            }
                        } else if let Some(targets) = cache.get(c) {
                            if targets.len() <= MAX_NAME_FANOUT {
                                next.extend(targets.iter().map(|s| s.id.as_str()));
                            }
                        }
                    }
                }
                frontier = next;
            }
            let missing = !guarded && sinks.iter().any(|s| DATA_SINKS.contains(s));
            (missing, sinks)
        })
        .collect();
    for (r, (missing, sinks)) in g.routes.iter_mut().zip(marks) {
        r.missing_guard = Some(missing);
        r.sinks_reachable = sinks;
    }
}

fn is_ignored_dir(name: &str) -> bool {
    matches!(name, "node_modules" | ".gradle" | ".git")
}

/// Build the graph of every supported file under `root`.
pub fn build_graph(root: &Path) -> CodeGraph {
    build_graph_with(root, &GraphOptions::default())
}

/// Build the graph with explicit options. Files are parsed in parallel on a pool with a large stack
/// (generated Java and JavaScript can nest deeply); each file runs under the per-file time budget and
/// a file over it is skipped and reported through `truncated`.
pub fn build_graph_with(root: &Path, opts: &GraphOptions) -> CodeGraph {
    let mut g = CodeGraph {
        version: GRAPH_SCHEMA_VERSION,
        producer: "foxguard",
        root: root.to_string_lossy().to_string(),
        files: 0,
        symbols: vec![],
        calls: vec![],
        routes: vec![],
        taint_summaries: vec![],
        unsupported: BTreeMap::new(),
        truncated: false,
        dropped_calls: 0,
        call_stats: None,
        notes: vec![],
        types: types::TypeTable::default(),
    };
    let mut web_paths: Vec<std::path::PathBuf> = Vec::new();
    let mut paths: Vec<_> = WalkBuilder::new(root)
        .hidden(true)
        .filter_entry(|e| {
            !(e.file_type().map(|t| t.is_dir()).unwrap_or(false)
                && is_ignored_dir(&e.file_name().to_string_lossy()))
        })
        .build()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.into_path())
        .collect();
    paths.sort();
    let mut jobs: Vec<(std::path::PathBuf, Language)> = Vec::new();
    for path in paths {
        if path.file_name().and_then(|n| n.to_str()) == Some("web.xml") {
            web_paths.push(path);
            continue;
        }
        let Some(lang) = detect_language(&path) else {
            continue;
        };
        let supported = matches!(
            lang,
            Language::JavaScript | Language::Python | Language::Java | Language::Kotlin
        );
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.ends_with(".d.ts") || name.contains(".min.") {
            continue;
        }
        if !supported {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                *g.unsupported.entry(ext.to_string()).or_default() += 1;
            }
            continue;
        }
        if jobs.len() >= MAX_FILES {
            g.truncated = true;
            break;
        }
        jobs.push((path, lang));
    }

    let budget = crate::engine::budget::file_timeout();
    let work = |(path, lang): &(std::path::PathBuf, Language)| -> FileOutcome {
        let too_big = std::fs::metadata(path)
            .map(|m| m.len() > MAX_FILE_BYTES)
            .unwrap_or(true);
        if too_big {
            return FileOutcome::TimedOut;
        }
        let Ok(bytes) = std::fs::read(path) else {
            return FileOutcome::Skipped;
        };
        let source = String::from_utf8_lossy(&bytes);
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let _budget = crate::engine::budget::FileBudgetGuard::start(budget);
        graph_file(&rel, &source, *lang, path, opts)
    };
    let results: Vec<FileOutcome> = match rayon::ThreadPoolBuilder::new()
        .stack_size(64 * 1024 * 1024)
        .build()
    {
        Ok(pool) => pool.install(|| jobs.par_iter().map(work).collect()),
        Err(_) => jobs.iter().map(work).collect(),
    };

    let mut secs: Vec<security::FileSecurity> = Vec::new();
    let mut classes: Vec<types::ClassDef> = Vec::new();
    let mut scopes: HashMap<String, types::FileScope> = HashMap::new();
    let mut webs: Vec<security::WebXml> = Vec::new();
    let web_xmls: Vec<security::WebXml> = web_paths
        .iter()
        .filter_map(|p| {
            let meta = std::fs::metadata(p).ok()?;
            if meta.len() > MAX_FILE_BYTES {
                return None;
            }
            let text = String::from_utf8_lossy(&std::fs::read(p).ok()?).into_owned();
            let rel = p
                .strip_prefix(root)
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/");
            Some(security::parse_web_xml(&rel, &text))
        })
        .collect();
    for outcome in results {
        match outcome {
            FileOutcome::Graph(fg) => {
                g.files += 1;
                let fg = *fg;
                if !fg.security.is_empty() {
                    secs.push(fg.security);
                }
                classes.extend(fg.classes);
                if let Some(first) = fg.symbols.first() {
                    scopes.insert(first.file.clone(), fg.scope);
                }
                g.symbols.extend(fg.symbols);
                g.calls.extend(fg.calls);
                g.routes.extend(fg.routes);
                g.taint_summaries.extend(fg.taint);
                for n in fg.notes {
                    if !g.notes.contains(&n) {
                        g.notes.push(n);
                    }
                }
            }
            FileOutcome::TimedOut => g.truncated = true,
            FileOutcome::Skipped => {}
        }
    }

    // Security rules outside annotations are joined to the routes of the whole tree.
    for w in web_xmls {
        webs.push(w);
    }
    security::apply(&mut g, secs, webs);
    g.types = types::TypeTable::build(classes, scopes);

    // Java and Kotlin calls to names defined nowhere in the tree (JDK and library methods) would
    // dominate the output, and so would calls to names defined in dozens of places (`get`, `add`,
    // `toString`) that neither the receiver's type nor the file's imports and package can tell apart.
    if opts.legacy_resolution {
        legacy_prune(&mut g);
    } else {
        resolve_jvm_calls(&mut g);
    }
    if g.calls.len() > MAX_CALLS {
        g.calls.truncate(MAX_CALLS);
        g.truncated = true;
    }
    for r in &mut g.routes {
        if r.auth_signals.is_empty() && r.framework != "spring" {
            r.auth_signals = r
                .middleware
                .iter()
                .filter(|m| auth_like(m))
                .cloned()
                .collect();
        }
    }
    resolve_refs(&mut g);
    g
}

/// Resolve every Java and Kotlin call against the types of the tree and keep the ones that join a
/// bounded number of symbols (or are sinks or auth signals); count what is given up.
fn resolve_jvm_calls(g: &mut CodeGraph) {
    let index = resolve::SymIndex::new(&g.symbols, true);
    if index.is_empty() {
        return;
    }
    let verdicts: Vec<resolve::Verdict> = {
        let resolver = resolve::Resolver {
            symbols: &g.symbols,
            index: &index,
            table: &g.types,
            rank_cache: Default::default(),
        };
        g.calls.par_iter().map(|c| resolver.decide(c)).collect()
    };
    let mut stats = resolve::CallStats::default();
    let mut dropped = 0usize;
    let mut it = verdicts.into_iter();
    g.calls.retain_mut(|c| {
        let Some(v) = it.next() else { return true };
        use resolve::Kind;
        match v.kind {
            Kind::NotJvm => return true,
            Kind::External => stats.external += 1,
            Kind::Resolved => stats.resolved += 1,
            Kind::Ambiguous => stats.ambiguous += 1,
            Kind::Ranked => stats.ranked += 1,
            Kind::Dropped => {}
        }
        stats.jvm_calls += 1;
        if !v.keep {
            if v.kind == Kind::Dropped {
                dropped += 1;
            }
            return false;
        }
        if v.receiver_type.is_some() {
            c.receiver_type = v.receiver_type;
        }
        c.cand = v.cand;
        true
    });
    g.dropped_calls = dropped;
    if stats.jvm_calls > 0 {
        g.call_stats = Some(stats);
    }
}

/// The name-only resolution of the first version of the graph (no type table, no ranking), kept
/// behind a hidden flag so the improvement can be measured on any tree.
fn legacy_prune(g: &mut CodeGraph) {
    let java_by_name = index_by_name(g.symbols.iter().filter(|s| s.language == "java"));
    if java_by_name.is_empty() {
        return;
    }
    let mut cache = NarrowCache::default();
    for c in &g.calls {
        cache.fill(&java_by_name, c);
    }
    let mut stats = resolve::CallStats::default();
    let mut dropped = 0usize;
    let keep: Vec<bool> = g
        .calls
        .iter()
        .map(|c| {
            if !c.file.ends_with(".java") {
                return true;
            }
            stats.jvm_calls += 1;
            let n = cache.get(c).map(|v| v.len()).unwrap_or(0);
            match n {
                0 => stats.external += 1,
                1 => stats.resolved += 1,
                2..=MAX_JAVA_NAME_DEFS => stats.ambiguous += 1,
                _ => {}
            }
            let keep = c.sink.is_some() || c.auth || (1..=MAX_JAVA_NAME_DEFS).contains(&n);
            if !keep && n > MAX_JAVA_NAME_DEFS {
                dropped += 1;
            }
            keep
        })
        .collect();
    let mut keep = keep.into_iter();
    g.calls.retain(|_| keep.next().unwrap_or(true));
    g.dropped_calls = dropped;
    if stats.jvm_calls > 0 {
        g.call_stats = Some(stats);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph_of(files: &[(&str, &str)]) -> CodeGraph {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "fg-graph-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        for (name, text) in files {
            let p = dir.join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        let g = build_graph(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        g
    }

    #[test]
    fn express_routes_and_missing_guard() {
        let mut g = graph_of(&[
            ("auth.ts", "export function requireAuth(a, b, c) {}\nexport function assertOwner(u, n) {}\n"),
            ("notes.ts", "export function loadNote(id) { return db.query('SELECT ' + id); }\n"),
            ("handlers.ts", "export function exportHandler(req, res) { res.send(loadNote(req.params.id)); }\n"),
            (
                "routes.ts",
                "const router = express.Router();\n\
                 router.get('/notes/:id', requireAuth, async (req, res) => { const n = loadNote(req.params.id); assertOwner(req.user, n); res.json(n); });\n\
                 router.put('/notes/:id', requireAuth, (req, res) => { assertOwner(req.user, loadNote(1)); });\n\
                 router.get('/notes/:id/export', exportHandler);\n",
            ),
        ]);
        assert_eq!(g.routes.len(), 3);
        mark_missing_guards(&mut g);
        let unguarded: Vec<_> = g
            .routes
            .iter()
            .filter(|r| r.missing_guard == Some(true))
            .collect();
        assert_eq!(unguarded.len(), 1);
        assert_eq!(unguarded[0].path, "/notes/:id/export");
        assert!(unguarded[0].handler.contains("exportHandler"));
        assert!(g
            .calls
            .iter()
            .any(|c| c.text == "db.query" && c.sink.as_ref().map(|s| s.category) == Some("sql")));
    }

    #[test]
    fn flask_routes_and_unsupported_languages() {
        let g = graph_of(&[
            (
                "app.py",
                "@app.route('/files/<n>', methods=['DELETE'])\n@login_required\ndef rm(n):\n    os.remove(n)\n\n@app.get('/ping')\ndef ping():\n    os.system('ping')\n",
            ),
            ("main.go", "package main\nfunc main() {}\n"),
        ]);
        assert_eq!(g.routes.len(), 2);
        assert_eq!(g.routes[0].method, "DELETE");
        assert!(g.routes[0]
            .middleware
            .contains(&"login_required".to_string()));
        assert_eq!(g.unsupported.get("go"), Some(&1));
        assert!(g
            .calls
            .iter()
            .any(|c| c.text == "os.system" && c.sink.is_some()));
    }

    fn route<'a>(g: &'a CodeGraph, method: &str, path: &str) -> &'a GraphRoute {
        g.routes
            .iter()
            .find(|r| r.method == method && r.path == path)
            .unwrap_or_else(|| {
                panic!(
                    "no route {method} {path}; have {:?}",
                    g.routes
                        .iter()
                        .map(|r| format!("{} {}", r.method, r.path))
                        .collect::<Vec<_>>()
                )
            })
    }

    #[test]
    fn java_spring_routes_prefixes_methods_and_guards() {
        let mut g = graph_of(&[
            (
                "UserApi.java",
                r#"package a;
@RestController
@RequestMapping(path = {"/v1", "/v2"})
@PreAuthorize("hasRole('USER')")
public class UserApi {
    @Autowired UserRepository userRepository;
    @GetMapping("/users/{id}")
    public User one(@PathVariable Long id) { return userRepository.findById(id).orElseThrow(); }
    @RequestMapping(value = "/users", method = {RequestMethod.POST, RequestMethod.PUT})
    public void write(@RequestBody User u) { userRepository.save(u); }
    @DeleteMapping
    @PermitAll
    public void wipe() { userRepository.deleteAll(); }
    @GetMapping("/ping")
    public String ping() { return "pong"; }
}
"#,
            ),
            (
                "Client.java",
                "@FeignClient(name = \"x\")\npublic interface Client { @GetMapping(\"/remote\") String remote(); }\n",
            ),
        ]);
        mark_missing_guards(&mut g);
        assert_eq!(g.routes.len(), 2 + 4 + 2 + 2, "{:?}", g.routes);
        let r = route(&g, "GET", "/v2/users/{id}");
        assert_eq!(r.framework, "spring");
        assert!(r.auth_signals.contains(&"PreAuthorize".to_string()));
        assert_eq!(r.missing_guard, Some(false));
        assert_eq!(r.sinks_reachable, vec!["sql"]);
        route(&g, "POST", "/v1/users");
        route(&g, "PUT", "/v2/users");
        assert_eq!(route(&g, "DELETE", "/v1").middleware[1], "PermitAll");
        assert!(g.routes.iter().all(|r| r.path != "/remote"));
    }

    #[test]
    fn java_unguarded_sink_routes_are_flagged_and_pure_routes_are_not() {
        let mut g = graph_of(&[(
            "A.java",
            r#"@RestController
class A {
    @GetMapping("/open") String open(String q) { return em.createNativeQuery("select " + q).getSingleResult().toString(); }
    @GetMapping("/health") String health() { return "ok"; }
    @GetMapping("/exec") void run(String c) { Runtime.getRuntime().exec(c); }
    @GetMapping("/ctx") void ctx(String q) {
        if (SecurityContextHolder.getContext().getAuthentication() == null) throw new RuntimeException();
        jdbc.execute("x" + q);
    }
    @GetMapping("/scan") void scan(String q) { scanner.scanFiles(q); new FileInputStream(q); }
}
"#,
        )]);
        mark_missing_guards(&mut g);
        assert_eq!(route(&g, "GET", "/open").missing_guard, Some(true));
        assert_eq!(route(&g, "GET", "/health").missing_guard, Some(false));
        assert_eq!(route(&g, "GET", "/exec").sinks_reachable, vec!["command"]);
        assert_eq!(route(&g, "GET", "/exec").missing_guard, Some(true));
        let ctx = route(&g, "GET", "/ctx");
        assert_eq!(
            ctx.missing_guard,
            Some(false),
            "SecurityContext is a signal"
        );
        assert_eq!(ctx.sinks_reachable, vec!["sql"]);
        // `scan` contains "can" but is not an auth name; a file constructor is a file sink.
        assert_eq!(route(&g, "GET", "/scan").missing_guard, Some(true));
        assert!(g.calls.iter().any(|c| c.text == "new FileInputStream"
            && c.sink.as_ref().map(|s| s.category) == Some("file")));
    }

    #[test]
    fn java_jaxrs_and_servlet_entry_points() {
        let mut g = graph_of(&[
            (
                "Res.java",
                r#"@Path("/files")
public class Res {
    @GET @Path("/{name}") @RolesAllowed("admin")
    public String read(@PathParam("name") String n) { return Files.readString(Path.of(n)); }
    @DELETE @Path("{name}")
    public void del(@PathParam("name") String n) { Files.delete(Path.of(n)); }
}
"#,
            ),
            (
                "Hello.java",
                r#"@WebServlet("/hello")
public class Hello extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse res) { res.sendRedirect(req.getParameter("to")); }
    protected void helper() {}
}
class Other extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse res) { new ProcessBuilder(req.getParameter("c")).start(); }
}
"#,
            ),
        ]);
        mark_missing_guards(&mut g);
        let read = route(&g, "GET", "/files/{name}");
        assert_eq!(read.framework, "jax-rs");
        assert_eq!(read.auth_signals, vec!["RolesAllowed"]);
        assert_eq!(read.missing_guard, Some(false));
        let del = route(&g, "DELETE", "/files/{name}");
        assert_eq!(del.missing_guard, Some(true));
        assert_eq!(route(&g, "GET", "/hello").framework, "servlet");
        assert_eq!(
            g.routes.iter().filter(|r| r.framework == "servlet").count(),
            2
        );
        assert!(g
            .routes
            .iter()
            .any(|r| r.path == "/{servlet:Other}" && r.method == "POST"));
        assert!(g
            .calls
            .iter()
            .any(|c| c.name == "sendRedirect" && c.sink.is_some()));
    }

    #[test]
    fn java_symbols_calls_and_pruning() {
        let g = graph_of(&[(
            "S.java",
            r#"package p;
public class S {
    static class Inner { void deep() { helper(); } }
    S() { init(); }
    void helper() { list.add(x); this.init(); }
    void init() {}
    abstract void nobody();
}
"#,
        )]);
        let names: Vec<&str> = g.symbols.iter().map(|s| s.qualified.as_str()).collect();
        assert!(
            names.contains(&"S.Inner.deep")
                && names.contains(&"S.helper")
                && names.contains(&"S.S")
        );
        assert!(
            !names.contains(&"S.nobody"),
            "bodiless methods are not symbols"
        );
        // `list.add` is not defined in the tree and is dropped; calls that join a symbol stay.
        assert!(!g.calls.iter().any(|c| c.name == "add"));
        assert_eq!(g.calls.iter().filter(|c| c.name == "init").count(), 2);
        assert!(g.symbols.iter().all(|s| s.language == "java"));
    }

    #[test]
    fn java_taint_summaries_are_opt_in() {
        let dir = std::env::temp_dir().join(format!("fg-graph-taint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("Q.java"),
            "class Q { String run(String cmd) throws Exception { Runtime.getRuntime().exec(cmd); return cmd; } }\n",
        )
        .unwrap();
        let off = build_graph(&dir);
        assert!(off.taint_summaries.is_empty());
        let on = build_graph_with(
            &dir,
            &GraphOptions {
                taint_summaries: true,
                ..Default::default()
            },
        );
        let _ = std::fs::remove_dir_all(&dir);
        let run = on
            .taint_summaries
            .iter()
            .find(|s| s.function == "run")
            .expect("summary for run");
        assert_eq!(run.params_to_return, vec![0]);
        assert!(run
            .params_to_sink
            .iter()
            .any(|f| f.param_index == 0 && f.rule_id == "java/taint-command-injection"));
    }
}
