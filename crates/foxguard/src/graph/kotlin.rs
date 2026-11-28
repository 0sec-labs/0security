//! Kotlin extractor for `foxguard graph`: functions and methods, call edges with declared receiver
//! types, Spring MVC and JAX-RS annotations, Ktor routing, sink calls, auth signals and Spring
//! Security URL rules (Java-style chains and the Kotlin DSL), on the same terms as the Java extractor.
//!
//! The Kotlin grammar attaches annotations unreliably (annotations on a class can parse as sibling
//! expressions), so annotations are read from the source text of the modifiers and of the gap before
//! a declaration instead of from the tree.

use super::java::{
    auth_signal, guard_annotation, is_method_security_annotation, join_path, sink_category,
    MATCHER_CALLS, PUBLIC_ANNOTATIONS, STEREOTYPES,
};
use super::security::{auth_filter_name, Access, FilterDef, PArg, Pm, UrlRule};
use super::types::{parse_type, ClassDef, FieldDef, FileScope, RecvPath, Step, TypeRef};
use super::{AuthSource, FileGraph, GraphCall, GraphRoute, GraphSymbol, SinkTag};
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;
use tree_sitter::Node;

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static regex"))
}

fn kids<'t>(n: Node<'t>) -> Vec<Node<'t>> {
    let mut c = n.walk();
    n.named_children(&mut c).collect()
}

fn first_kind<'t>(n: Node<'t>, kind: &str) -> Option<Node<'t>> {
    kids(n).into_iter().find(|k| k.kind() == kind)
}

fn is_type_node(kind: &str) -> bool {
    matches!(
        kind,
        "user_type"
            | "nullable_type"
            | "not_nullable_type"
            | "parenthesized_type"
            | "receiver_type"
    )
}

// ---- annotations read from text -------------------------------------------------------------

struct KAnn {
    name: String,
    args: String,
    line: usize,
}

fn strip_comments(text: &str) -> String {
    static C: OnceLock<Regex> = OnceLock::new();
    re(&C, r"(?s)/\*.*?\*/|//[^\n]*")
        .replace_all(text, |c: &regex::Captures| {
            "\n".repeat(c[0].matches('\n').count())
        })
        .into_owned()
}

fn parse_annotations(text: &str, first_line: usize) -> Vec<KAnn> {
    let text = strip_comments(text);
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let mut line = first_line;
    while i < chars.len() {
        match chars[i] {
            '\n' => line += 1,
            '"' => {
                // Skip a string literal.
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' {
                        i += 1;
                    }
                    if i < chars.len() && chars[i] == '\n' {
                        line += 1;
                    }
                    i += 1;
                }
            }
            '@' => {
                let start_line = line;
                let mut j = i + 1;
                let mut name = String::new();
                while j < chars.len()
                    && (chars[j].is_alphanumeric() || matches!(chars[j], '_' | '.' | ':'))
                {
                    name.push(chars[j]);
                    j += 1;
                }
                let name = name
                    .rsplit(':')
                    .next()
                    .unwrap_or("")
                    .rsplit('.')
                    .next()
                    .unwrap_or("")
                    .to_string();
                let mut args = String::new();
                if j < chars.len() && chars[j] == '(' {
                    let mut depth = 0;
                    let mut in_str = false;
                    let begin = j + 1;
                    while j < chars.len() {
                        let c = chars[j];
                        if in_str {
                            if c == '\\' {
                                j += 1;
                            } else if c == '"' {
                                in_str = false;
                            }
                        } else if c == '"' {
                            in_str = true;
                        } else if c == '(' {
                            depth += 1;
                        } else if c == ')' {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        } else if c == '\n' {
                            line += 1;
                        }
                        j += 1;
                    }
                    args = chars[begin..j.min(chars.len())].iter().collect();
                }
                if !name.is_empty() {
                    out.push(KAnn {
                        name,
                        args,
                        line: start_line,
                    });
                }
                i = j;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// Split annotation arguments at top-level commas.
fn split_args(args: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let (mut depth, mut in_str) = (0i32, false);
    let mut prev = ' ';
    for c in args.chars() {
        if in_str {
            cur.push(c);
            if c == '"' && prev != '\\' {
                in_str = false;
            }
        } else {
            match c {
                '"' => {
                    in_str = true;
                    cur.push(c);
                }
                '(' | '[' | '{' => {
                    depth += 1;
                    cur.push(c);
                }
                ')' | ']' | '}' => {
                    depth -= 1;
                    cur.push(c);
                }
                ',' if depth == 0 => {
                    parts.push(std::mem::take(&mut cur));
                }
                _ => cur.push(c),
            }
        }
        prev = c;
    }
    if !cur.trim().is_empty() {
        parts.push(cur);
    }
    parts
}

fn string_literals(s: &str) -> Vec<String> {
    static S: OnceLock<Regex> = OnceLock::new();
    re(&S, r#""((?:[^"\\]|\\.)*)""#)
        .captures_iter(s)
        .map(|c| c[1].to_string())
        .collect()
}

/// Values of the annotation argument(s) named one of `keys` (a bare first argument counts as
/// `value`): strings, or `{NAME}` for a constant.
fn ann_values(args: &str, keys: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for (idx, part) in split_args(args).iter().enumerate() {
        let (key, value) = match part.split_once('=') {
            Some((k, v)) if !k.contains('"') && !k.contains('(') && !v.starts_with('=') => {
                (k.trim().to_string(), v.trim().to_string())
            }
            _ if idx == 0 => ("value".to_string(), part.trim().to_string()),
            _ => continue,
        };
        if !keys.contains(&key.as_str()) {
            continue;
        }
        let lits = string_literals(&value);
        if lits.is_empty() {
            let name: String = value.chars().filter(|c| !c.is_whitespace()).collect();
            if !name.is_empty() {
                out.push(format!("{{{name}}}"));
            }
        } else {
            out.extend(lits);
        }
    }
    out
}

fn ann_paths(args: &str, keys: &[&str]) -> Vec<String> {
    let v = ann_values(args, keys);
    if v.is_empty() {
        vec![String::new()]
    } else {
        v
    }
}

// ---- the walker -------------------------------------------------------------------------------

struct KClass {
    simple: String,
    qualified: String,
    def: usize,
    fields: HashMap<String, FieldDef>,
    tparams: Vec<String>,
    prefixes: Vec<String>,
    guards: Vec<String>,
    public: Vec<String>,
}

#[derive(Clone)]
enum Local {
    Ty(TypeRef),
    Path(RecvPath),
}

/// Ktor routing context: whether the walk is inside a `routing { }` block, the path prefix and the
/// `authenticate { }` wrappers around the current call.
#[derive(Clone, Default)]
struct Ktor {
    active: bool,
    prefix: String,
    guards: Vec<(String, usize)>,
}

struct Walker<'a> {
    file: &'a str,
    src: &'a [u8],
    out: &'a mut FileGraph,
    locals: HashMap<String, Local>,
    chain_key: usize,
}

const KTOR_VERBS: [&str; 7] = ["get", "post", "put", "delete", "patch", "head", "options"];
/// Calls that return their receiver, so a chain keeps the receiver's type through them.
const IDENTITY_CALLS: [&str; 6] = [
    "also",
    "apply",
    "takeIf",
    "takeUnless",
    "onEach",
    "requireNotNull",
];

fn is_upper(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_uppercase())
}

impl<'a> Walker<'a> {
    fn text(&self, n: Node) -> String {
        n.utf8_text(self.src).unwrap_or("").to_string()
    }

    fn line_of(&self, n: Node) -> usize {
        n.start_position().row + 1
    }

    fn symbol(&mut self, name: &str, qualified: &str, kind: &'static str, n: Node) -> String {
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
            language: "kotlin",
        });
        id
    }

    fn type_of_decl(&self, n: Node) -> Option<TypeRef> {
        kids(n)
            .into_iter()
            .find(|k| is_type_node(k.kind()))
            .map(|t| parse_type(&self.text(t)))
            .filter(|t| !t.name.is_empty())
    }

    fn is_tparam(&self, name: &str, class: Option<&KClass>, fn_tparams: &[String]) -> bool {
        fn_tparams.iter().any(|p| p == name)
            || class.is_some_and(|c| c.tparams.iter().any(|p| p == name))
    }

    fn tparams(&self, decl: Node) -> Vec<String> {
        let Some(tp) = first_kind(decl, "type_parameters") else {
            return vec![];
        };
        kids(tp)
            .into_iter()
            .filter(|k| k.kind() == "type_parameter")
            .filter_map(|p| first_kind(p, "type_identifier").map(|i| self.text(i)))
            .collect()
    }

    /// Text of the modifiers of a declaration plus the annotations that the grammar left as
    /// sibling expressions in front of it.
    fn annotations_of(&self, decl: Node) -> Vec<KAnn> {
        let mut out = Vec::new();
        let mut gap_start = None;
        let mut prev = decl.prev_named_sibling();
        while let Some(p) = prev {
            if matches!(p.kind(), "prefix_expression" | "annotation") {
                gap_start = Some(p.start_byte());
                prev = p.prev_named_sibling();
            } else {
                break;
            }
        }
        if let Some(start) = gap_start {
            let end = decl.start_byte();
            if let Ok(t) = std::str::from_utf8(&self.src[start..end]) {
                let first_line = self.src[..start].iter().filter(|&&b| b == b'\n').count() + 1;
                out.extend(parse_annotations(t, first_line));
            }
        }
        if let Some(m) = first_kind(decl, "modifiers") {
            out.extend(parse_annotations(&self.text(m), self.line_of(m)));
        }
        out
    }

    fn qualifier_in(&self, anns: &[KAnn]) -> Option<String> {
        anns.iter()
            .filter(|a| matches!(a.name.as_str(), "Qualifier" | "Resource" | "Named"))
            .find_map(|a| ann_values(&a.args, &["value", "name"]).into_iter().next())
    }

    // ---- declarations ----

    fn scope(&mut self, root: Node) {
        let mut scope = FileScope::default();
        for k in kids(root) {
            match k.kind() {
                "package_header" => {
                    scope.package = self
                        .text(k)
                        .trim_start_matches("package")
                        .trim()
                        .trim_end_matches(';')
                        .trim()
                        .to_string();
                }
                "import_list" => {
                    for h in kids(k) {
                        let t = self.text(h);
                        let t = t
                            .trim_start_matches("import")
                            .trim()
                            .trim_end_matches(';')
                            .trim();
                        let t = t.split(" as ").next().unwrap_or(t).trim().to_string();
                        scope.imports.push(t);
                    }
                }
                _ => {}
            }
        }
        self.out.scope = scope;
    }

    fn supertypes(&self, decl: Node) -> Vec<TypeRef> {
        kids(decl)
            .into_iter()
            .filter(|k| k.kind() == "delegation_specifier")
            .filter_map(|d| {
                let inner = kids(d).into_iter().next()?;
                let t = if inner.kind() == "constructor_invocation" {
                    first_kind(inner, "user_type")?
                } else if inner.kind() == "user_type" {
                    inner
                } else {
                    return None;
                };
                Some(parse_type(&self.text(t)))
            })
            .collect()
    }

    fn class_info(&mut self, decl: Node, parent: Option<&KClass>) -> KClass {
        let name = first_kind(decl, "type_identifier")
            .map(|n| self.text(n))
            .unwrap_or_else(|| "<object>".to_string());
        let qualified = match parent {
            Some(p) => format!("{}.{}", p.qualified, name),
            None => name.clone(),
        };
        let anns = self.annotations_of(decl);
        let mut own: HashMap<String, FieldDef> = HashMap::new();
        // Primary constructor properties.
        if let Some(pc) = first_kind(decl, "primary_constructor") {
            for p in kids(pc)
                .into_iter()
                .filter(|k| k.kind() == "class_parameter")
            {
                if first_kind(p, "binding_pattern_kind").is_none() {
                    continue;
                }
                let (Some(n), Some(t)) = (first_kind(p, "simple_identifier"), self.type_of_decl(p))
                else {
                    continue;
                };
                let pa = first_kind(p, "modifiers")
                    .map(|m| parse_annotations(&self.text(m), self.line_of(m)))
                    .unwrap_or_default();
                own.insert(
                    self.text(n),
                    FieldDef {
                        ty: t,
                        qualifier: self.qualifier_in(&pa),
                    },
                );
            }
        }
        // Properties of the body.
        let mut consts: Vec<(String, Vec<String>)> = Vec::new();
        if let Some(body) = first_kind(decl, "class_body") {
            self.collect_properties(body, &mut own, &mut consts);
            for c in kids(body)
                .into_iter()
                .filter(|k| k.kind() == "companion_object")
            {
                if let Some(cb) = first_kind(c, "class_body") {
                    self.collect_properties(cb, &mut own, &mut consts);
                }
            }
        }
        for (n, v) in consts {
            self.out
                .security
                .consts
                .entry(format!("{name}.{n}"))
                .or_insert_with(|| v.clone());
            self.out.security.consts.entry(n).or_insert(v);
        }
        let own_tparams = self.tparams(decl);
        let mut tparams = parent.map(|p| p.tparams.clone()).unwrap_or_default();
        tparams.extend(own_tparams.clone());
        let mut fields = parent.map(|p| p.fields.clone()).unwrap_or_default();
        fields.extend(own.clone());
        let supers = self.supertypes(decl);
        let interface = {
            let mut c = decl.walk();
            let found = decl
                .children(&mut c)
                .any(|k| !k.is_named() && k.kind() == "interface");
            found
        };
        let is_abstract = first_kind(decl, "modifiers")
            .is_some_and(|m| self.text(m).split_whitespace().any(|w| w == "abstract"));
        let mut def = ClassDef {
            name: name.clone(),
            qualified: qualified.clone(),
            package: self.out.scope.package.clone(),
            file: self.file.to_string(),
            interface,
            is_abstract,
            supers: supers.clone(),
            type_params: own_tparams,
            fields: own,
            ..Default::default()
        };
        let mut info = KClass {
            simple: name.clone(),
            qualified,
            def: 0,
            fields,
            tparams,
            prefixes: vec![String::new()],
            guards: vec![],
            public: vec![],
        };
        let mut web_filter: Option<Vec<String>> = None;
        for a in &anns {
            match a.name.as_str() {
                "RequestMapping" => info.prefixes = ann_paths(&a.args, &["value", "path"]),
                "Path" => info.prefixes = ann_paths(&a.args, &["value"]),
                "WebFilter" => {
                    web_filter = Some(
                        ann_values(&a.args, &["value", "urlPatterns"])
                            .into_iter()
                            .filter(|p| !p.is_empty())
                            .collect(),
                    )
                }
                "EnableMethodSecurity" | "EnableGlobalMethodSecurity" => {
                    self.out.security.method_security = true
                }
                "Primary" => def.primary = true,
                "Qualifier" => def.bean_name = self.qualifier_in(std::slice::from_ref(a)),
                n if STEREOTYPES.contains(&n) => {
                    def.component = true;
                    if def.bean_name.is_none() {
                        def.bean_name = ann_values(&a.args, &["value"])
                            .into_iter()
                            .next()
                            .filter(|s| !s.is_empty());
                    }
                }
                n if guard_annotation(n) => {
                    if is_method_security_annotation(n) {
                        self.out.security.method_guards = true;
                    }
                    info.guards.push(n.to_string());
                }
                n if PUBLIC_ANNOTATIONS.contains(&n) => info.public.push(n.to_string()),
                _ => {}
            }
        }
        if web_filter.is_some() || supers.iter().any(|s| s.name.ends_with("Filter")) {
            static BODY: OnceLock<Regex> = OnceLock::new();
            let body = re(
                &BODY,
                r"(?i)SC_UNAUTHORIZED|SC_FORBIDDEN|HttpStatus\.(UNAUTHORIZED|FORBIDDEN)|sendError\(\s*40[13]|userPrincipal|remoteUser|isUserInRole|SecurityContext|AuthenticationException|\bBearer\b|jwt",
            );
            let auth = auth_filter_name(&name) || body.is_match(&self.text(decl));
            self.out.security.filters.push(FilterDef {
                name: name.clone(),
                patterns: web_filter.unwrap_or_default(),
                auth,
                source: format!("{}:{} filter class {}", self.file, self.line_of(decl), name),
            });
        }
        self.out.classes.push(def);
        info.def = self.out.classes.len() - 1;
        info
    }

    fn collect_properties(
        &self,
        body: Node,
        own: &mut HashMap<String, FieldDef>,
        consts: &mut Vec<(String, Vec<String>)>,
    ) {
        for p in kids(body)
            .into_iter()
            .filter(|k| k.kind() == "property_declaration")
        {
            let Some(vd) = first_kind(p, "variable_declaration") else {
                continue;
            };
            let Some(n) = first_kind(vd, "simple_identifier") else {
                continue;
            };
            let name = self.text(n);
            let anns = first_kind(p, "modifiers")
                .map(|m| parse_annotations(&self.text(m), self.line_of(m)))
                .unwrap_or_default();
            let init = kids(p).into_iter().find(|k| {
                !matches!(
                    k.kind(),
                    "modifiers"
                        | "binding_pattern_kind"
                        | "variable_declaration"
                        | "property_delegate"
                        | "type_constraints"
                        | "type_parameters"
                        | "getter"
                        | "setter"
                )
            });
            if let Some(i) = init {
                if let Some(lits) = self.literal_strings(i) {
                    consts.push((name.clone(), lits));
                }
            }
            let ty = self.type_of_decl(vd).or_else(|| {
                init.filter(|i| i.kind() == "call_expression")
                    .and_then(|i| kids(i).into_iter().next())
                    .filter(|c| c.kind() == "simple_identifier" && is_upper(&self.text(*c)))
                    .map(|c| TypeRef::named(&self.text(c)))
            });
            if let Some(ty) = ty {
                own.insert(
                    name,
                    FieldDef {
                        ty,
                        qualifier: self.qualifier_in(&anns),
                    },
                );
            }
        }
    }

    /// `"a"`, `arrayOf("a", "b")`, `listOf(..)`, `[..]`: the string literals of a constant.
    fn literal_strings(&self, n: Node) -> Option<Vec<String>> {
        match n.kind() {
            "string_literal" => Some(vec![self.text(n).trim_matches('"').to_string()]),
            "collection_literal" => {
                let mut out = Vec::new();
                for k in kids(n) {
                    out.extend(self.literal_strings(k)?);
                }
                Some(out)
            }
            "call_expression" => {
                let ks = kids(n);
                let callee = ks.first()?;
                if callee.kind() != "simple_identifier"
                    || !matches!(
                        self.text(*callee).as_str(),
                        "arrayOf" | "listOf" | "setOf" | "mutableListOf" | "persistentListOf"
                    )
                {
                    return None;
                }
                let mut out = Vec::new();
                let suffix = first_kind(n, "call_suffix")?;
                let args = first_kind(suffix, "value_arguments")?;
                for a in kids(args) {
                    out.extend(self.literal_strings(kids(a).into_iter().next()?)?);
                }
                Some(out)
            }
            _ => None,
        }
    }

    fn register_function(
        &mut self,
        decl: Node,
        class: Option<&KClass>,
    ) -> (String, Option<String>) {
        let mut name = String::new();
        let mut receiver: Option<String> = None;
        let mut ret: Option<TypeRef> = None;
        let mut seen_name = false;
        let mut seen_params = false;
        let tp = self.tparams(decl);
        for k in kids(decl) {
            match k.kind() {
                "simple_identifier" if !seen_name => {
                    name = self.text(k);
                    seen_name = true;
                }
                "function_value_parameters" => seen_params = true,
                kind if is_type_node(kind) => {
                    let t = parse_type(&self.text(k));
                    if !seen_name {
                        receiver = Some(t.name);
                    } else if seen_params {
                        ret = Some(t);
                    }
                }
                _ => {}
            }
        }
        if let (Some(c), true) = (class, !name.is_empty()) {
            let has_body = first_kind(decl, "function_body").is_some();
            let def = &mut self.out.classes[c.def];
            if let Some(r) = ret {
                let r = if tp.contains(&r.name) {
                    TypeRef::default()
                } else {
                    r
                };
                def.methods.entry(name.clone()).or_default().push(r);
            }
            if has_body {
                def.bodied.insert(name.clone());
            }
        }
        (name, receiver)
    }

    #[allow(clippy::type_complexity)]
    fn collect_locals<'t>(
        &self,
        func: Node<'t>,
        class: Option<&KClass>,
        tp: &[String],
    ) -> (HashMap<String, Local>, Vec<(usize, String, Node<'t>)>) {
        let mut map = HashMap::new();
        let mut pending = Vec::new();
        let mut stack = vec![func];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "parameter" => {
                    if let (Some(name), Some(t)) =
                        (first_kind(n, "simple_identifier"), self.type_of_decl(n))
                    {
                        if !self.is_tparam(&t.name, class, tp) {
                            map.insert(self.text(name), Local::Ty(t));
                        }
                    }
                }
                "property_declaration" => {
                    if let Some(vd) = first_kind(n, "variable_declaration") {
                        if let Some(name) = first_kind(vd, "simple_identifier") {
                            let name = self.text(name);
                            if let Some(t) = self.type_of_decl(vd) {
                                if !self.is_tparam(&t.name, class, tp) {
                                    map.insert(name, Local::Ty(t));
                                }
                            } else if let Some(init) = kids(n).into_iter().find(|k| {
                                !matches!(
                                    k.kind(),
                                    "modifiers"
                                        | "binding_pattern_kind"
                                        | "variable_declaration"
                                        | "property_delegate"
                                )
                            }) {
                                pending.push((init.start_byte(), name, init));
                            }
                        }
                    }
                }
                _ => {}
            }
            stack.extend(kids(n));
        }
        pending.sort_by_key(|p| p.0);
        (map, pending)
    }

    // ---- receiver paths ----

    fn recv_path(&self, n: Node, class: Option<&KClass>, depth: usize) -> Option<RecvPath> {
        if depth > 8 {
            return None;
        }
        let this_path = || {
            class.map(|c| RecvPath {
                base: TypeRef::named(&c.simple),
                steps: vec![],
                hint: None,
            })
        };
        let typed = |ty: TypeRef, hint: Option<(String, Option<String>)>| {
            (!ty.name.is_empty()).then_some(RecvPath {
                base: ty,
                steps: vec![],
                hint,
            })
        };
        match n.kind() {
            "this_expression" => this_path(),
            "simple_identifier" => {
                let name = self.text(n);
                if let Some(l) = self.locals.get(&name) {
                    return match l {
                        Local::Ty(t) => typed(t.clone(), None),
                        Local::Path(p) => Some(p.clone()),
                    };
                }
                if let Some(f) = class.and_then(|c| c.fields.get(&name)) {
                    return typed(f.ty.clone(), Some((name, f.qualifier.clone())));
                }
                is_upper(&name)
                    .then(|| typed(TypeRef::named(&name), None))
                    .flatten()
            }
            "navigation_expression" => {
                let ks = kids(n);
                let recv = *ks.first()?;
                let suffix = ks.iter().rev().find(|k| k.kind() == "navigation_suffix")?;
                let name = self.text(first_kind(*suffix, "simple_identifier")?);
                let mut p = self.recv_path(recv, class, depth + 1)?;
                p.steps.push(Step::Field(name));
                p.hint = None;
                Some(p)
            }
            "call_expression" => {
                let ks = kids(n);
                let callee = *ks.first()?;
                match callee.kind() {
                    "simple_identifier" => {
                        let name = self.text(callee);
                        if is_upper(&name) {
                            return typed(TypeRef::named(&name), None);
                        }
                        let mut p = this_path()?;
                        p.steps.push(Step::Call(name));
                        Some(p)
                    }
                    "navigation_expression" => {
                        let nk = kids(callee);
                        let recv = *nk.first()?;
                        let suffix = nk.iter().rev().find(|k| k.kind() == "navigation_suffix")?;
                        let name = self.text(first_kind(*suffix, "simple_identifier")?);
                        let mut p = self.recv_path(recv, class, depth + 1)?;
                        p.hint = None;
                        if !IDENTITY_CALLS.contains(&name.as_str()) {
                            p.steps.push(Step::Call(name));
                        }
                        Some(p)
                    }
                    _ => None,
                }
            }
            "parenthesized_expression" | "postfix_expression" => {
                self.recv_path(*kids(n).first()?, class, depth + 1)
            }
            "as_expression" => {
                let t = kids(n).into_iter().find(|k| is_type_node(k.kind()))?;
                typed(parse_type(&self.text(t)), None)
            }
            "indexing_expression" => {
                let mut p = self.recv_path(*kids(n).first()?, class, depth + 1)?;
                p.steps.push(Step::Call("get".to_string()));
                p.hint = None;
                Some(p)
            }
            _ => None,
        }
    }

    fn render(&self, n: Node, depth: usize) -> String {
        let t = match n.kind() {
            "simple_identifier" | "this_expression" => self.text(n),
            "navigation_expression" if depth < 6 => {
                let ks = kids(n);
                let suffix = ks
                    .iter()
                    .rev()
                    .find(|k| k.kind() == "navigation_suffix")
                    .and_then(|s| first_kind(*s, "simple_identifier"))
                    .map(|s| self.text(s))
                    .unwrap_or_default();
                match ks.first() {
                    Some(r) => format!("{}.{}", self.render(*r, depth + 1), suffix),
                    None => suffix,
                }
            }
            "call_expression" if depth < 6 => match kids(n).first() {
                Some(c) => format!("{}()", self.render(*c, depth + 1)),
                None => "<expr>".to_string(),
            },
            "parenthesized_expression" | "postfix_expression" => match kids(n).first() {
                Some(c) => self.render(*c, depth + 1),
                None => "<expr>".to_string(),
            },
            _ => "<expr>".to_string(),
        };
        let t: String = t.split_whitespace().collect();
        t.chars().take(160).collect()
    }

    // ---- calls and routes ----

    fn add_call(
        &mut self,
        from: &str,
        name: String,
        text: String,
        line: usize,
        recv: Option<RecvPath>,
    ) {
        if name.is_empty() {
            return;
        }
        let sink = sink_category(&text, &name).map(|category| SinkTag {
            category,
            text: text.clone(),
        });
        let auth = auth_signal(&name, &text);
        let receiver_type = recv
            .as_ref()
            .filter(|p| p.steps.is_empty())
            .map(|p| p.base.name.clone());
        let recv = recv.filter(|p| !p.steps.is_empty() || p.hint.is_some());
        self.out.calls.push(GraphCall {
            from: from.to_string(),
            name,
            text,
            file: self.file.to_string(),
            line,
            sink,
            auth,
            receiver_type,
            recv,
            cand: None,
        });
    }

    fn walk_children(&mut self, node: Node, cur: &str, class: Option<&KClass>, ktor: &Ktor) {
        for k in kids(node) {
            self.walk(k, cur, class, ktor);
        }
    }

    fn walk(&mut self, node: Node, cur: &str, class: Option<&KClass>, ktor: &Ktor) {
        match node.kind() {
            "class_declaration" | "object_declaration" => {
                let info = self.class_info(node, class);
                self.walk_children(node, cur, Some(&info), ktor);
                return;
            }
            "companion_object" => {
                self.walk_children(node, cur, class, ktor);
                return;
            }
            "function_declaration" => {
                let (name, receiver) = self.register_function(node, class);
                if name.is_empty() || first_kind(node, "function_body").is_none() {
                    return;
                }
                let tp = self.tparams(node);
                let qualified = match (class, &receiver) {
                    (Some(c), _) => format!("{}.{}", c.qualified, name),
                    (None, Some(r)) => format!("{r}.{name}"),
                    (None, None) => name.clone(),
                };
                let id = self.symbol(&name, &qualified, "method", node);
                if let Some(c) = class {
                    self.spring_routes(node, c, &id);
                }
                let (locals, pending) = self.collect_locals(node, class, &tp);
                let outer = std::mem::replace(&mut self.locals, locals);
                let outer_key = std::mem::replace(&mut self.chain_key, node.id());
                for (_, n, value) in pending {
                    if let Some(p) = self.recv_path(value, class, 0) {
                        self.locals.insert(n, Local::Path(p));
                    }
                }
                let mut k = ktor.clone();
                if matches!(receiver.as_deref(), Some("Route") | Some("Routing")) {
                    k.active = true;
                }
                self.walk_children(node, &id, class, &k);
                self.locals = outer;
                self.chain_key = outer_key;
                return;
            }
            "call_expression" if self.call(node, cur, class, ktor) => {
                return;
            }
            _ => {}
        }
        self.walk_children(node, cur, class, ktor);
    }

    /// Handle a call. Returns true when its children were walked here.
    fn call(&mut self, node: Node, cur: &str, class: Option<&KClass>, ktor: &Ktor) -> bool {
        let ks = kids(node);
        let Some(callee) = ks.first().copied() else {
            return false;
        };
        let suffix = first_kind(node, "call_suffix");
        let (name, text, recv_node) = match callee.kind() {
            "simple_identifier" => {
                let n = self.text(callee);
                if is_upper(&n) {
                    (n.clone(), format!("new {n}"), None)
                } else {
                    (n.clone(), n, None)
                }
            }
            "navigation_expression" => {
                let nk = kids(callee);
                let Some(sfx) = nk.iter().rev().find(|k| k.kind() == "navigation_suffix") else {
                    return false;
                };
                let Some(id) = first_kind(*sfx, "simple_identifier") else {
                    return false;
                };
                let name = self.text(id);
                let mut text = self.render(callee, 0);
                // `java.io.File(path)`: a constructor behind a package name, like Java's `new File`.
                let package_like = text
                    .rsplit_once('.')
                    .is_some_and(|(p, _)| p.chars().all(|c| c.is_ascii_lowercase() || c == '.'));
                if is_upper(&name) && package_like {
                    text = format!("new {name}");
                }
                (name, text, nk.first().copied())
            }
            _ => return false,
        };
        // Ktor routing blocks.
        if callee.kind() == "simple_identifier" {
            if let Some(sfx) = suffix {
                if self.ktor_call(node, &name, sfx, cur, class, ktor) {
                    return true;
                }
            }
            self.dsl_rule(node, &name, suffix);
        } else {
            self.chain_rule(node, callee, &name);
        }
        self.security_misc(node, &name, suffix);
        let recv = match callee.kind() {
            "simple_identifier" if !is_upper(&name) => class.map(|c| RecvPath {
                base: TypeRef::named(&c.simple),
                steps: vec![],
                hint: None,
            }),
            "navigation_expression" => recv_node.and_then(|r| self.recv_path(r, class, 0)),
            _ => None,
        };
        let line = self.line_of(callee);
        self.add_call(cur, name, text, line, recv);
        false
    }

    // ---- Spring MVC / JAX-RS ----

    fn spring_routes(&mut self, node: Node, class: &KClass, id: &str) {
        let anns = self.annotations_of(node);
        let mut middleware: Vec<String> = class.guards.clone();
        middleware.extend(class.public.iter().cloned());
        let mut guards = class.guards.clone();
        let mut public_names = class.public.clone();
        for a in &anns {
            if guard_annotation(&a.name) {
                if is_method_security_annotation(&a.name) {
                    self.out.security.method_guards = true;
                }
                guards.push(a.name.clone());
                middleware.push(a.name.clone());
            } else if PUBLIC_ANNOTATIONS.contains(&a.name.as_str()) {
                public_names.push(a.name.clone());
                middleware.push(a.name.clone());
            }
        }
        let own_path = anns.iter().find(|a| a.name == "Path");
        let mut found: Vec<(String, String, usize, &'static str)> = Vec::new();
        for a in &anns {
            let verb = match a.name.as_str() {
                "GetMapping" => Some("GET"),
                "PostMapping" => Some("POST"),
                "PutMapping" => Some("PUT"),
                "DeleteMapping" => Some("DELETE"),
                "PatchMapping" => Some("PATCH"),
                _ => None,
            };
            if verb.is_some() || a.name == "RequestMapping" {
                let methods: Vec<String> = match verb {
                    Some(v) => vec![v.to_string()],
                    None => {
                        static M: OnceLock<Regex> = OnceLock::new();
                        let mut ms: Vec<String> = Vec::new();
                        for part in split_args(&a.args) {
                            if part.trim_start().starts_with("method") {
                                for c in
                                    re(&M, r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\b")
                                        .captures_iter(&part)
                                {
                                    ms.push(c[1].to_string());
                                }
                            }
                        }
                        if ms.is_empty() {
                            ms.push("ANY".to_string());
                        }
                        ms
                    }
                };
                let sub = ann_paths(&a.args, &["value", "path"]);
                for m in methods {
                    for p in &class.prefixes {
                        for s in &sub {
                            found.push((m.clone(), join_path(p, s), a.line, "spring"));
                        }
                    }
                }
                continue;
            }
            if matches!(
                a.name.as_str(),
                "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS"
            ) {
                let sub = own_path
                    .map(|p| ann_paths(&p.args, &["value"]))
                    .unwrap_or_else(|| vec![String::new()]);
                for p in &class.prefixes {
                    for s in &sub {
                        found.push((a.name.clone(), join_path(p, s), a.line, "jax-rs"));
                    }
                }
            }
        }
        let open = guards.is_empty() && !public_names.is_empty();
        for (method, path, line, framework) in found {
            let auth_sources = if open {
                vec![AuthSource {
                    signal: format!("@{}", public_names[0]),
                    source: format!("{}:{} @{}", self.file, line, public_names[0]),
                    access: "public",
                }]
            } else {
                vec![]
            };
            self.out.routes.push(GraphRoute {
                method,
                path,
                file: self.file.to_string(),
                line,
                handler: id.to_string(),
                middleware: middleware.clone(),
                framework,
                auth_signals: guards.clone(),
                auth_sources,
                public: open,
                sinks_reachable: vec![],
                missing_guard: None,
            });
        }
    }

    // ---- Ktor ----

    /// `routing { }`, `route("/p") { }`, `authenticate("x") { }` and the verb handlers. Returns true
    /// when the call was a routing construct (its children are walked here).
    fn ktor_call(
        &mut self,
        node: Node,
        name: &str,
        suffix: Node,
        cur: &str,
        class: Option<&KClass>,
        ktor: &Ktor,
    ) -> bool {
        let Some(lambda) =
            first_kind(suffix, "annotated_lambda").and_then(|a| first_kind(a, "lambda_literal"))
        else {
            return false;
        };
        let args: Vec<Node> = first_kind(suffix, "value_arguments")
            .map(kids)
            .unwrap_or_default();
        let first_str = args.first().and_then(|a| {
            let e = kids(*a).into_iter().next()?;
            (e.kind() == "string_literal").then(|| self.text(e).trim_matches('"').to_string())
        });
        let line = self.line_of(node);
        match name {
            "routing" => {
                let k = Ktor {
                    active: true,
                    ..ktor.clone()
                };
                self.walk(lambda, cur, class, &k);
                true
            }
            "route" if ktor.active => {
                let mut k = ktor.clone();
                k.prefix = join_path(&k.prefix, first_str.as_deref().unwrap_or(""));
                self.walk(lambda, cur, class, &k);
                true
            }
            "authenticate" if ktor.active => {
                let mut k = ktor.clone();
                let a: String = args
                    .iter()
                    .map(|x| self.text(*x))
                    .collect::<Vec<_>>()
                    .join(",")
                    .replace('"', "");
                if !a.contains("optional=true") && !a.contains("optional = true") {
                    k.guards.push((
                        if a.is_empty() {
                            "authenticate".to_string()
                        } else {
                            format!("authenticate({a})")
                        },
                        line,
                    ));
                }
                self.walk(lambda, cur, class, &k);
                true
            }
            v if ktor.active && KTOR_VERBS.contains(&v) => {
                let method = v.to_uppercase();
                let path = join_path(&ktor.prefix, first_str.as_deref().unwrap_or(""));
                let hname = format!("<{method} {path}>");
                let id = self.symbol(&hname, &hname, "route-handler", lambda);
                let guards: Vec<String> = ktor.guards.iter().map(|g| g.0.clone()).collect();
                let auth_sources: Vec<AuthSource> = ktor
                    .guards
                    .iter()
                    .map(|(g, l)| AuthSource {
                        signal: g.clone(),
                        source: format!("{}:{} {}", self.file, l, g),
                        access: "authenticated",
                    })
                    .collect();
                self.out.routes.push(GraphRoute {
                    method,
                    path,
                    file: self.file.to_string(),
                    line,
                    handler: id.clone(),
                    middleware: guards.clone(),
                    framework: "ktor",
                    auth_signals: guards,
                    auth_sources,
                    public: false,
                    sinks_reachable: vec![],
                    missing_guard: None,
                });
                for a in &args {
                    self.walk(*a, cur, class, ktor);
                }
                self.walk(lambda, &id, class, ktor);
                true
            }
            _ => false,
        }
    }

    // ---- Spring Security ----

    fn matcher_args(&self, args: Node, regex: bool) -> (Vec<Pm>, Vec<String>) {
        let mut out = Vec::new();
        let mut unresolved = Vec::new();
        let mut method: Option<String> = None;
        for a in kids(args)
            .into_iter()
            .filter(|k| k.kind() == "value_argument")
        {
            if let Some(e) = kids(a).into_iter().next() {
                self.matcher_expr(e, regex, &mut method, &mut out, &mut unresolved);
            }
        }
        if out.is_empty() && unresolved.is_empty() && method.is_some() {
            out.push(Pm {
                method,
                regex: false,
                arg: PArg::Lit("/**".to_string()),
            });
        }
        (out, unresolved)
    }

    fn matcher_expr(
        &self,
        e: Node,
        regex: bool,
        method: &mut Option<String>,
        out: &mut Vec<Pm>,
        unresolved: &mut Vec<String>,
    ) {
        match e.kind() {
            "string_literal" => out.push(Pm {
                method: method.clone(),
                regex,
                arg: PArg::Lit(self.text(e).trim_matches('"').to_string()),
            }),
            "simple_identifier" | "navigation_expression" => {
                let t = self.text(e);
                if let Some(m) = t.strip_prefix("HttpMethod.") {
                    *method = Some(m.to_uppercase());
                } else {
                    out.push(Pm {
                        method: method.clone(),
                        regex,
                        arg: PArg::Const(t),
                    });
                }
            }
            "spread_expression" => {
                for k in kids(e) {
                    self.matcher_expr(k, regex, method, out, unresolved);
                }
            }
            "call_expression" => {
                let ks = kids(e);
                let callee = ks.first().map(|c| self.text(*c)).unwrap_or_default();
                let sfx =
                    first_kind(e, "call_suffix").and_then(|s| first_kind(s, "value_arguments"));
                if matches!(
                    callee.as_str(),
                    "arrayOf" | "listOf" | "setOf" | "antMatcher" | "mvcMatcher"
                ) {
                    if let Some(args) = sfx {
                        for a in kids(args) {
                            if let Some(x) = kids(a).into_iter().next() {
                                self.matcher_expr(x, regex, method, out, unresolved);
                            }
                        }
                        return;
                    }
                }
                unresolved.push(self.text(e));
            }
            _ => unresolved.push(self.text(e)),
        }
    }

    fn access_of(&self, name: &str, inner: &str) -> Access {
        match name {
            "permitAll" | "anonymous" => Access::Public,
            "denyAll" => Access::Denied,
            "authenticated" | "fullyAuthenticated" | "rememberMe" => Access::Authenticated,
            "access" if inner.contains("permitAll") => Access::Public,
            "access" if inner.contains("denyAll") => Access::Denied,
            _ => Access::Role(format!("{name}({})", inner.trim())),
        }
    }

    fn note_unresolved(&mut self, text: &str, line: usize) {
        let n = self
            .out
            .notes
            .iter()
            .filter(|n| n.starts_with("spring-security-url-rules: matcher"))
            .count();
        if n < 3 {
            let t: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
            let t: String = t.chars().take(80).collect();
            self.out.notes.push(format!(
                "spring-security-url-rules: matcher `{t}` at {}:{line} is not a string constant; the routes it covers are not marked",
                self.file
            ));
        }
    }

    fn push_rule(&mut self, rule: UrlRule) {
        let key = self.chain_key;
        let file = self.file;
        self.out.security.chain_mut(key, file).rules.push(rule);
    }

    /// Java-style chain: `auth.requestMatchers("/x").permitAll()`.
    fn chain_rule(&mut self, node: Node, callee: Node, name: &str) {
        let terminal = matches!(
            name,
            "permitAll"
                | "anonymous"
                | "denyAll"
                | "authenticated"
                | "fullyAuthenticated"
                | "rememberMe"
                | "hasRole"
                | "hasAnyRole"
                | "hasAuthority"
                | "hasAnyAuthority"
                | "hasIpAddress"
                | "access"
        );
        if !terminal {
            return;
        }
        let Some(recv) = kids(callee).first().copied() else {
            return;
        };
        if recv.kind() != "call_expression" {
            return;
        }
        let rk = kids(recv);
        let Some(rc) = rk.first().copied() else {
            return;
        };
        // The matcher's own position (a navigation expression starts at its receiver).
        let (mname, mline, mpos) = match rc.kind() {
            "simple_identifier" => (self.text(rc), self.line_of(rc), rc.start_byte()),
            "navigation_expression" => {
                let Some(sfx) = kids(rc)
                    .into_iter()
                    .rev()
                    .find(|k| k.kind() == "navigation_suffix")
                else {
                    return;
                };
                (
                    first_kind(sfx, "simple_identifier")
                        .map(|i| self.text(i))
                        .unwrap_or_default(),
                    self.line_of(sfx),
                    sfx.start_byte(),
                )
            }
            _ => return,
        };
        let any = mname == "anyRequest";
        if !(any || MATCHER_CALLS.contains(&mname.as_str())) {
            return;
        }
        let args_node =
            first_kind(node, "call_suffix").and_then(|s| first_kind(s, "value_arguments"));
        let inner = args_node
            .map(|a| self.text(a))
            .unwrap_or_default()
            .trim_start_matches('(')
            .trim_end_matches(')')
            .replace(['"', '\''], "");
        let (matchers, unresolved) = match (
            any,
            first_kind(recv, "call_suffix").and_then(|s| first_kind(s, "value_arguments")),
        ) {
            (false, Some(a)) => self.matcher_args(a, mname == "regexMatchers"),
            _ => (vec![], vec![]),
        };
        for u in unresolved.into_iter().take(1) {
            self.note_unresolved(&u, mline);
        }
        let matcher_text = if any {
            "anyRequest()".to_string()
        } else {
            format!(
                "{mname}{}",
                first_kind(recv, "call_suffix")
                    .and_then(|s| first_kind(s, "value_arguments"))
                    .map(|a| self.text(a))
                    .unwrap_or_default()
            )
        };
        let source: String = format!(
            "{}:{} {}.{}({})",
            self.file, mline, matcher_text, name, inner
        )
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(140)
        .collect();
        let access = self.access_of(name, &inner);
        self.push_rule(UrlRule {
            any,
            matchers,
            access,
            source,
            pos: mpos,
        });
    }

    /// Kotlin DSL: `authorize("/x/**", permitAll)`, `authorize(anyRequest, authenticated)`.
    fn dsl_rule(&mut self, node: Node, name: &str, suffix: Option<Node>) {
        if name != "authorize" {
            return;
        }
        let Some(args) = suffix.and_then(|s| first_kind(s, "value_arguments")) else {
            return;
        };
        let vals: Vec<Node> = kids(args)
            .into_iter()
            .filter(|k| k.kind() == "value_argument")
            .filter_map(|a| kids(a).into_iter().next())
            .collect();
        let Some((access_node, pattern_nodes)) = vals.split_last() else {
            return;
        };
        let any = pattern_nodes.iter().any(|p| self.text(*p) == "anyRequest");
        let (access_name, inner) = match access_node.kind() {
            "simple_identifier" => (self.text(*access_node), String::new()),
            "call_expression" => {
                let ks = kids(*access_node);
                let n = ks.first().map(|c| self.text(*c)).unwrap_or_default();
                let a = first_kind(*access_node, "call_suffix")
                    .and_then(|s| first_kind(s, "value_arguments"))
                    .map(|a| self.text(a))
                    .unwrap_or_default()
                    .trim_start_matches('(')
                    .trim_end_matches(')')
                    .replace(['"', '\''], "");
                (n, a)
            }
            _ => return,
        };
        if !matches!(
            access_name.as_str(),
            "permitAll"
                | "anonymous"
                | "denyAll"
                | "authenticated"
                | "fullyAuthenticated"
                | "rememberMe"
                | "hasRole"
                | "hasAnyRole"
                | "hasAuthority"
                | "hasAnyAuthority"
                | "hasIpAddress"
                | "access"
        ) {
            return;
        }
        let mut out = Vec::new();
        let mut unresolved = Vec::new();
        let mut method = None;
        if !any {
            for p in pattern_nodes {
                self.matcher_expr(*p, false, &mut method, &mut out, &mut unresolved);
            }
            if out.is_empty() && unresolved.is_empty() && method.is_some() {
                out.push(Pm {
                    method: method.clone(),
                    regex: false,
                    arg: PArg::Lit("/**".to_string()),
                });
            }
        }
        let line = self.line_of(node);
        for u in unresolved.into_iter().take(1) {
            self.note_unresolved(&u, line);
        }
        let source: String = format!("{}:{} {}", self.file, line, self.text(node))
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(140)
            .collect();
        let access = self.access_of(&access_name, &inner);
        self.push_rule(UrlRule {
            any,
            matchers: out,
            access,
            source,
            pos: node.start_byte(),
        });
    }

    /// `securityMatcher("/api/**")`, `web.ignoring().requestMatchers(..)`, `addFilterBefore(..)`.
    fn security_misc(&mut self, node: Node, name: &str, suffix: Option<Node>) {
        let args = suffix.and_then(|s| first_kind(s, "value_arguments"));
        match name {
            "securityMatcher" | "antMatcher" | "mvcMatcher" | "regexMatcher" => {
                if let Some(a) = args {
                    let (matchers, unresolved) = self.matcher_args(a, name == "regexMatcher");
                    let line = self.line_of(node);
                    for u in unresolved.into_iter().take(1) {
                        self.note_unresolved(&u, line);
                    }
                    let key = self.chain_key;
                    let file = self.file;
                    self.out
                        .security
                        .chain_mut(key, file)
                        .scope
                        .extend(matchers);
                }
            }
            "requestMatchers" | "antMatchers" | "mvcMatchers" | "regexMatchers" => {
                let Some(a) = args else { return };
                let callee_text = kids(node)
                    .first()
                    .map(|c| self.text(*c))
                    .unwrap_or_default();
                if !callee_text.contains("ignoring()") {
                    return;
                }
                let (matchers, unresolved) = self.matcher_args(a, name == "regexMatchers");
                let line = self.line_of(node);
                for u in unresolved.into_iter().take(1) {
                    self.note_unresolved(&u, line);
                }
                let source = format!("{}:{} web.ignoring().{}", self.file, line, name);
                self.out.security.ignoring.push(UrlRule {
                    any: false,
                    matchers,
                    access: Access::Public,
                    source,
                    pos: 0,
                });
            }
            "addFilterBefore" | "addFilterAfter" | "addFilterAt" | "addFilter" => {
                let Some(first) = args
                    .and_then(|a| kids(a).into_iter().next())
                    .and_then(|a| kids(a).into_iter().next())
                else {
                    return;
                };
                let filter = match first.kind() {
                    "call_expression" => kids(first).first().map(|c| self.text(*c)),
                    "simple_identifier" => Some(self.text(first)),
                    _ => None,
                };
                if let Some(f) = filter.filter(|f| !f.is_empty()) {
                    let source = format!("{}:{} {}({})", self.file, self.line_of(node), name, f);
                    let key = self.chain_key;
                    let file = self.file;
                    self.out
                        .security
                        .chain_mut(key, file)
                        .filters
                        .push((f, source));
                }
            }
            _ => {}
        }
    }
}

/// Extract the graph of one parsed Kotlin file.
pub(super) fn extract(rel: &str, source: &str, root: Node) -> FileGraph {
    let mut out = FileGraph::default();
    let mut w = Walker {
        file: rel,
        src: source.as_bytes(),
        out: &mut out,
        locals: HashMap::new(),
        chain_key: 0,
    };
    let module = w.symbol("<module>", "<module>", "module", root);
    w.scope(root);
    w.walk_children(root, &module, None, &Ktor::default());
    out
}
