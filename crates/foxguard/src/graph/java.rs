//! Java extractor for `foxguard graph`: methods, constructors, call edges, HTTP routes and entry
//! points (Spring MVC, JAX-RS, servlets), sink calls and auth signals.
//!
//! It is lexical, with declared types: a call carries the callee name, the receiver's declared type
//! (a field, parameter, local, `new T()`, or a path through fields and calls) and the classes of the
//! file are recorded for [`super::types::TypeTable`], which resolves the rest across files.
//! Annotations are matched by their simple name, so a project-local annotation called `PreAuthorize`
//! counts like the Spring one. Spring Security URL rules, `web.ignoring()` and filters are recorded for
//! [`super::security`].

use super::security::{
    auth_filter_name, Access, FilterDef, PArg, Pm, UrlRule,
};
use super::types::{
    parse_type, ClassDef, FieldDef, FileScope, RecvPath, Step, TypeRef,
};
use super::{AuthSource, FileGraph, GraphCall, GraphRoute, GraphSymbol, SinkTag};
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;
use tree_sitter::Node;

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static regex"))
}

/// Annotations that guard a handler (authentication, role, permission or ownership check).
const GUARD_ANNOTATIONS: [&str; 14] = [
    "PreAuthorize",
    "PostAuthorize",
    "PreFilter",
    "PostFilter",
    "Secured",
    "RolesAllowed",
    "DenyAll",
    "RequiresAuthentication",
    "RequiresPermissions",
    "RequiresRoles",
    "RequiresUser",
    "RunAs",
    "Authenticated",
    "AuthorizedRoles",
];

/// Annotation names kept on a route next to the guards, because they are the opposite signal.
const PUBLIC_ANNOTATIONS: [&str; 2] = ["PermitAll", "Anonymous"];

/// Case-sensitive on purpose: a case-insensitive `can` would match `scan` and `cancel`.
pub(super) fn auth_signal(name: &str, text: &str) -> bool {
    static NAME: OnceLock<Regex> = OnceLock::new();
    static TEXT: OnceLock<Regex> = OnceLock::new();
    re(
        &NAME,
        r"^(assert|ensure)[A-Z_]|^(check|verify|require|validate|enforce)(Access|Owner|Ownership|Permission|Role|User|Tenant|Auth|Admin|Principal|Scope|Membership|Rights?)|^(can|may)[A-Z_]|^(is|has)(Allowed|Authorized|Authenticated|Owner|Admin|Role|AnyRole|Authority|AnyAuthority|Permission|Member|UserInRole)|^(isOwnedBy|ownedBy|owns[A-Z_]|[a-z]+OwnerOrAdmin)|(?i:authenticat|authoriz|permission|ownership|credential|principal|csrf|jwt)",
    )
    .is_match(name)
        || re(
            &TEXT,
            r"SecurityContext|AuthenticationManager|AccessDecision|PermissionEvaluator|Subject\.|SecurityUtils",
        )
        .is_match(text)
}

fn guard_annotation(name: &str) -> bool {
    GUARD_ANNOTATIONS.contains(&name)
        || (!PUBLIC_ANNOTATIONS.contains(&name)
            && re(
                &ANN_GUARD,
                r"(?i)^(requires?|check|enforce)?(auth|login|permission|role|owner|admin|access)|(auth|login|permission|role|owner|admin)(ed|required|only|check|guard)$",
            )
            .is_match(name))
}
static ANN_GUARD: OnceLock<Regex> = OnceLock::new();

/// Sink category of a Java call, by name and receiver text only.
fn sink_category(text: &str, name: &str) -> Option<&'static str> {
    static CMD: OnceLock<Regex> = OnceLock::new();
    static EVAL: OnceLock<Regex> = OnceLock::new();
    static SQL: OnceLock<Regex> = OnceLock::new();
    static SQL_RECV: OnceLock<Regex> = OnceLock::new();
    static REPO: OnceLock<Regex> = OnceLock::new();
    static FILE: OnceLock<Regex> = OnceLock::new();
    static NET: OnceLock<Regex> = OnceLock::new();
    static DESER: OnceLock<Regex> = OnceLock::new();
    static TPL: OnceLock<Regex> = OnceLock::new();
    if re(
        &CMD,
        r"getRuntime\(\)\.exec$|^new ProcessBuilder$|(^|\.)ProcessBuilder\.(start|command)$|^Runtime\.exec$",
    )
    .is_match(text)
    {
        return Some("command");
    }
    if re(
        &EVAL,
        r"(^|\.)(eval|parseExpression)$|^Ognl\.getValue$|^new GroovyShell$|(^|\.)GroovyShell\.evaluate$",
    )
    .is_match(text)
    {
        return Some("code-eval");
    }
    let recv = text.rsplit_once('.').map(|(r, _)| r).unwrap_or("");
    if re(
        &SQL,
        r"^(createNativeQuery|createQuery|createSQLQuery|createNamedQuery|executeQuery|executeUpdate|executeLargeUpdate|executeBatch|prepareStatement|prepareCall|createStatement|queryForObject|queryForList|queryForMap|queryForRowSet|queryForStream|batchUpdate|nativeQuery)$",
    )
    .is_match(name)
        || (matches!(name, "execute" | "query" | "update")
            && re(
                &SQL_RECV,
                r"(?i)(stmt|statement|jdbc|template|sql|conn|dao|session|em|entityManager)\w*$",
            )
            .is_match(recv))
        || re(
            &REPO,
            r"(?i)(repository|repo|dao|entityManager)(\(\))?\.(find\w*|get\w*|delete\w*|save\w*|exists\w*|count\w*|merge|persist|remove|reference)$",
        )
        .is_match(text)
    {
        return Some("sql");
    }
    if re(
        &FILE,
        r"^new (File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|FileSystemResource|ZipFile)$|(^|\.)Files\.(read\w*|write\w*|delete\w*|newInputStream|newOutputStream|newBufferedReader|newBufferedWriter|copy|move|list|walk|lines|createFile|createTempFile)$|(^|\.)(FileUtils|FileCopyUtils|FileSystemUtils)\.\w+$|(^|\.)(getRealPath|transferTo|getResourceAsStream)$|^ResourceUtils\.getFile$",
    )
    .is_match(text)
    {
        return Some("file");
    }
    if re(
        &DESER,
        r"(^|\.)(readObject|readUnshared|fromXML)$|^new (ObjectInputStream|XMLDecoder)$|(?i)yaml\w*\.load(All)?$",
    )
    .is_match(text)
    {
        return Some("deserialize");
    }
    if re(
        &NET,
        r"(^|\.)(getForObject|getForEntity|postForObject|postForEntity|openConnection|openStream)$|(?i)(rest\w*|client|webclient|template)\.(exchange|execute|send|sendAsync)$|^new (URL|Socket)$",
    )
    .is_match(text)
    {
        return Some("network");
    }
    if re(
        &TPL,
        r"(?i)(template|freemarker|velocity|thymeleaf)\w*\.(process|evaluate|merge)$|^Velocity\.evaluate$",
    )
    .is_match(text)
    {
        return Some("template");
    }
    if name == "sendRedirect" || text == "new RedirectView" {
        return Some("redirect");
    }
    None
}

struct Ann<'t> {
    name: String,
    node: Node<'t>,
}

struct ClassInfo {
    qualified: String,
    /// Simple name of the class, the receiver type of unqualified and `this.` calls.
    simple: String,
    /// Declared type of each field, including those of enclosing classes.
    fields: HashMap<String, FieldDef>,
    /// Type parameters of the class and its enclosing classes.
    tparams: Vec<String>,
    /// Index of this class in `FileGraph::classes`.
    def: usize,
    /// Spring `@RequestMapping` / JAX-RS `@Path` prefixes of the class.
    prefixes: Vec<String>,
    servlet: bool,
    servlet_paths: Vec<String>,
    /// Guard annotations that apply to every method of the class.
    guards: Vec<String>,
    public: Vec<String>,
    feign: bool,
}

/// What a local variable or parameter is known by.
#[derive(Clone)]
enum Local {
    Ty(TypeRef),
    Path(RecvPath),
}

struct Walker<'a> {
    file: &'a str,
    src: &'a [u8],
    out: &'a mut FileGraph,
    /// Declared type of each parameter and local of the method being walked.
    locals: HashMap<String, Local>,
    /// Type parameters of the method being walked.
    mtparams: Vec<String>,
    /// The enclosing method (or 0 outside methods): Spring Security rules of one method form a chain.
    chain_key: usize,
}

fn type_params(decl: Node, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = decl.walk();
    for c in decl.children(&mut cursor) {
        if c.kind() == "type_parameters" {
            let mut inner = c.walk();
            for p in c.named_children(&mut inner) {
                if p.kind() == "type_parameter" {
                    let mut k = p.walk();
                    let ids: Vec<Node> = p
                        .named_children(&mut k)
                        .filter(|n| n.kind() == "type_identifier")
                        .collect();
                    if let Some(id) = ids.first() {
                        out.push(id.utf8_text(src).unwrap_or("").to_string());
                    }
                }
            }
        }
    }
    out
}

/// Spring stereotype annotations that make a class a bean.
const STEREOTYPES: [&str; 8] = [
    "Component",
    "Service",
    "Repository",
    "Controller",
    "RestController",
    "Configuration",
    "ControllerAdvice",
    "Named",
];

/// Literal string values of an expression: a literal, an array of them, `List.of(..)` and friends.
fn literal_strings(n: Node, src: &[u8]) -> Option<Vec<String>> {
    match n.kind() {
        "string_literal" => Some(vec![n
            .utf8_text(src)
            .unwrap_or("")
            .trim_matches('"')
            .to_string()]),
        "array_initializer" | "element_value_array_initializer" => {
            let mut cursor = n.walk();
            let items: Vec<Node> = n.named_children(&mut cursor).collect();
            let mut out = Vec::new();
            for i in items {
                out.extend(literal_strings(i, src)?);
            }
            Some(out)
        }
        "array_creation_expression" => {
            let mut cursor = n.walk();
            let init = n
                .named_children(&mut cursor)
                .find(|c| c.kind() == "array_initializer")?;
            literal_strings(init, src)
        }
        "method_invocation" => {
            let name = n.child_by_field_name("name")?.utf8_text(src).ok()?;
            if !matches!(name, "of" | "asList" | "copyOf") {
                return None;
            }
            let args = n.child_by_field_name("arguments")?;
            let mut cursor = args.walk();
            let items: Vec<Node> = args.named_children(&mut cursor).collect();
            let mut out = Vec::new();
            for i in items {
                out.extend(literal_strings(i, src)?);
            }
            Some(out)
        }
        "parenthesized_expression" => {
            let mut cursor = n.walk();
            let inner = n.named_children(&mut cursor).next()?;
            literal_strings(inner, src)
        }
        _ => None,
    }
}

fn simple_type(t: &str) -> String {
    parse_type(t).name
}

impl<'a> Walker<'a> {
    fn is_tparam(&self, name: &str, class: Option<&ClassInfo>) -> bool {
        self.mtparams.iter().any(|p| p == name)
            || class.is_some_and(|c| c.tparams.iter().any(|p| p == name))
    }

    /// `@Qualifier("x")`, `@Resource(name = "x")` or `@Named("x")` on a field or parameter.
    fn qualifier_of(&self, decl: Node) -> Option<String> {
        for a in self.annotations(decl) {
            if matches!(a.name.as_str(), "Qualifier" | "Resource" | "Named") {
                for v in self.arg_values(&a, &["value", "name"]) {
                    if let Some(s) = literal_strings(v, self.src).and_then(|v| v.into_iter().next())
                    {
                        return Some(s);
                    }
                }
            }
        }
        None
    }

    /// Fill `own` with the fields declared directly in a class body (`name -> declared type`, plus
    /// the Spring qualifier of the field or of the constructor parameter that sets it) and `consts`
    /// with fields initialised by string literals (security URL constants).
    fn collect_fields(
        &self,
        decl: Node,
        own: &mut HashMap<String, FieldDef>,
        consts: &mut Vec<(String, Vec<String>)>,
    ) {
        if decl.kind() == "record_declaration" {
            if let Some(params) = decl.child_by_field_name("parameters") {
                let mut cursor = params.walk();
                for p in params.named_children(&mut cursor) {
                    if let (Some(t), Some(n)) =
                        (p.child_by_field_name("type"), p.child_by_field_name("name"))
                    {
                        own.insert(
                            self.text(n),
                            FieldDef {
                                ty: parse_type(&self.text(t)),
                                qualifier: None,
                            },
                        );
                    }
                }
            }
        }
        let Some(body) = decl.child_by_field_name("body") else {
            return;
        };
        let mut cursor = body.walk();
        let members: Vec<Node> = body.children(&mut cursor).collect();
        for member in &members {
            if member.kind() != "field_declaration" {
                continue;
            }
            let Some(ty) = member.child_by_field_name("type") else {
                continue;
            };
            let ty = parse_type(&self.text(ty));
            let qualifier = self.qualifier_of(*member);
            let mut inner = member.walk();
            for d in member.children(&mut inner) {
                if d.kind() == "variable_declarator" {
                    if let Some(n) = d.child_by_field_name("name") {
                        let name = self.text(n);
                        if let Some(lits) = d
                            .child_by_field_name("value")
                            .and_then(|v| literal_strings(v, self.src))
                        {
                            consts.push((name.clone(), lits));
                        }
                        own.insert(
                            name,
                            FieldDef {
                                ty: ty.clone(),
                                qualifier: qualifier.clone(),
                            },
                        );
                    }
                }
            }
        }
        for member in members {
            if member.kind() != "constructor_declaration" {
                continue;
            }
            let Some(params) = member.child_by_field_name("parameters") else {
                continue;
            };
            let mut pc = params.walk();
            for p in params.named_children(&mut pc) {
                if p.kind() != "formal_parameter" {
                    continue;
                }
                if let (Some(n), Some(q)) = (p.child_by_field_name("name"), self.qualifier_of(p)) {
                    if let Some(f) = own.get_mut(&self.text(n)) {
                        f.qualifier = Some(q);
                    }
                }
            }
        }
    }

    /// Parameters and local variables of a method, by declared type (`var x = new T()` gives `T`).
    /// `var` locals initialised by anything else are returned for [`Self::recv_path`] to resolve.
    #[allow(clippy::type_complexity)]
    fn collect_locals<'t>(
        &self,
        method: Node<'t>,
        class: Option<&ClassInfo>,
    ) -> (
        HashMap<String, Local>,
        Vec<(usize, String, Node<'t>, Vec<Step>)>,
    ) {
        let mut map: HashMap<String, Local> = HashMap::new();
        let mut pending = Vec::new();
        let mut stack = vec![method];
        let put = |map: &mut HashMap<String, Local>, name: String, ty: TypeRef| {
            if !ty.name.is_empty() && ty.name != "var" && !self.is_tparam(&ty.name, class) {
                map.insert(name, Local::Ty(ty));
            }
        };
        while let Some(n) = stack.pop() {
            match n.kind() {
                "formal_parameter" | "catch_formal_parameter" | "resource" => {
                    if let (Some(t), Some(name)) =
                        (n.child_by_field_name("type"), n.child_by_field_name("name"))
                    {
                        put(&mut map, self.text(name), parse_type(&self.text(t)));
                    }
                }
                "local_variable_declaration" => {
                    if let Some(t) = n.child_by_field_name("type") {
                        let declared = parse_type(&self.text(t));
                        let mut cursor = n.walk();
                        let kids: Vec<Node> = n.children(&mut cursor).collect();
                        for d in kids {
                            if d.kind() != "variable_declarator" {
                                continue;
                            }
                            let Some(name) = d.child_by_field_name("name") else {
                                continue;
                            };
                            if declared.name != "var" {
                                put(&mut map, self.text(name), declared.clone());
                                continue;
                            }
                            let Some(v) = d.child_by_field_name("value") else {
                                continue;
                            };
                            if v.kind() == "object_creation_expression" {
                                if let Some(t) = v.child_by_field_name("type") {
                                    put(&mut map, self.text(name), parse_type(&self.text(t)));
                                }
                            } else {
                                pending.push((v.start_byte(), self.text(name), v, vec![]));
                            }
                        }
                    }
                }
                "enhanced_for_statement" => {
                    if let (Some(t), Some(name)) =
                        (n.child_by_field_name("type"), n.child_by_field_name("name"))
                    {
                        let declared = parse_type(&self.text(t));
                        if declared.name == "var" {
                            if let Some(v) = n.child_by_field_name("value") {
                                pending.push((
                                    v.start_byte(),
                                    self.text(name),
                                    v,
                                    vec![
                                        Step::Call("iterator".into()),
                                        Step::Call("next".into()),
                                    ],
                                ));
                            }
                        } else {
                            put(&mut map, self.text(name), declared);
                        }
                    }
                }
                _ => {}
            }
            let mut cursor = n.walk();
            stack.extend(n.children(&mut cursor));
        }
        pending.sort_by_key(|p| p.0);
        (map, pending)
    }

    /// The receiver of a call as a path from a known type: a variable, field, `this`, class name
    /// (static call), `new T()`, or a chain of those with field reads and calls.
    fn recv_path(&self, recv: Option<Node>, class: Option<&ClassInfo>, depth: usize) -> Option<RecvPath> {
        let this_path = || {
            class.map(|c| RecvPath {
                base: TypeRef::named(&c.simple),
                steps: vec![],
                hint: None,
            })
        };
        let Some(o) = recv else {
            return this_path();
        };
        if depth > 8 {
            return None;
        }
        let from_type = |ty: TypeRef, hint: Option<(String, Option<String>)>| {
            (!ty.name.is_empty() && ty.name != "var" && !self.is_tparam(&ty.name, class)).then_some(
                RecvPath {
                    base: ty,
                    steps: vec![],
                    hint,
                },
            )
        };
        match o.kind() {
            "this" => this_path(),
            "identifier" => {
                let name = self.text(o);
                if let Some(l) = self.locals.get(&name) {
                    return match l {
                        Local::Ty(t) => from_type(t.clone(), None),
                        Local::Path(p) => Some(p.clone()),
                    };
                }
                if let Some(f) = class.and_then(|c| c.fields.get(&name)) {
                    return from_type(f.ty.clone(), Some((name, f.qualifier.clone())));
                }
                name.chars()
                    .next()
                    .filter(|c| c.is_uppercase())
                    .and_then(|_| from_type(TypeRef::named(&name), None))
            }
            "field_access" => {
                let object = o.child_by_field_name("object")?;
                let field = self.text(o.child_by_field_name("field")?);
                if object.kind() == "this" {
                    let f = class?.fields.get(&field)?;
                    return from_type(f.ty.clone(), Some((field, f.qualifier.clone())));
                }
                let mut p = self.recv_path(Some(object), class, depth + 1)?;
                p.steps.push(Step::Field(field));
                p.hint = None;
                Some(p)
            }
            "method_invocation" => {
                let name = self.text(o.child_by_field_name("name")?);
                let mut p = self.recv_path(o.child_by_field_name("object"), class, depth + 1)?;
                p.steps.push(Step::Call(name));
                p.hint = None;
                Some(p)
            }
            "object_creation_expression" => o
                .child_by_field_name("type")
                .and_then(|t| from_type(parse_type(&self.text(t)), None)),
            "cast_expression" => o
                .child_by_field_name("type")
                .and_then(|t| from_type(parse_type(&self.text(t)), None)),
            "parenthesized_expression" => {
                let mut cursor = o.walk();
                let inner = o.named_children(&mut cursor).next()?;
                self.recv_path(Some(inner), class, depth + 1)
            }
            _ => None,
        }
    }

    fn text(&self, n: Node) -> String {
        n.utf8_text(self.src).unwrap_or("").to_string()
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
            language: "java",
        });
        id
    }

    fn annotations<'t>(&self, decl: Node<'t>) -> Vec<Ann<'t>> {
        let mut out = Vec::new();
        let mut cursor = decl.walk();
        for child in decl.children(&mut cursor) {
            if child.kind() != "modifiers" {
                continue;
            }
            let mut inner = child.walk();
            for m in child.children(&mut inner) {
                if matches!(m.kind(), "annotation" | "marker_annotation") {
                    if let Some(n) = m.child_by_field_name("name") {
                        let full = self.text(n);
                        let name = full.rsplit('.').next().unwrap_or("").to_string();
                        out.push(Ann { name, node: m });
                    }
                }
            }
        }
        out
    }

    /// The value nodes of an annotation argument named one of `keys` (`value` for a bare argument).
    fn arg_values<'t>(&self, ann: &Ann<'t>, keys: &[&str]) -> Vec<Node<'t>> {
        let Some(args) = ann.node.child_by_field_name("arguments") else {
            return vec![];
        };
        let mut out = Vec::new();
        let mut cursor = args.walk();
        for child in args.named_children(&mut cursor) {
            if child.kind() == "element_value_pair" {
                let key = child
                    .child_by_field_name("key")
                    .map(|k| self.text(k))
                    .unwrap_or_default();
                if let Some(v) = child.child_by_field_name("value") {
                    if keys.contains(&key.as_str()) {
                        out.push(v);
                    }
                }
            } else if keys.contains(&"value") {
                out.push(child);
            }
        }
        out
    }

    /// Path strings of an annotation value: literals, `A + "/x"` concatenations and `{...}` arrays.
    /// A constant that is not a literal is kept as `{NAME}`.
    fn path_strings(&self, n: Node) -> Vec<String> {
        match n.kind() {
            "string_literal" => {
                let t = self.text(n);
                vec![t.trim_matches('"').to_string()]
            }
            "element_value_array_initializer" | "array_initializer" => {
                let mut cursor = n.walk();
                let items: Vec<Node> = n.named_children(&mut cursor).collect();
                items
                    .into_iter()
                    .flat_map(|c| self.path_strings(c))
                    .collect()
            }
            "binary_expression" => {
                let (Some(l), Some(r)) = (
                    n.child_by_field_name("left"),
                    n.child_by_field_name("right"),
                ) else {
                    return vec![];
                };
                let ls = self.path_strings(l);
                let rs = self.path_strings(r);
                let mut out = Vec::new();
                for a in &ls {
                    for b in &rs {
                        out.push(format!("{a}{b}"));
                    }
                }
                out
            }
            "parenthesized_expression" => {
                let mut cursor = n.walk();
                let inner = n.named_children(&mut cursor).next();
                inner.map(|c| self.path_strings(c)).unwrap_or_default()
            }
            _ => vec![format!(
                "{{{}}}",
                self.text(n).replace(char::is_whitespace, "")
            )],
        }
    }

    fn paths_of(&self, ann: &Ann, keys: &[&str]) -> Vec<String> {
        let paths: Vec<String> = self
            .arg_values(ann, keys)
            .into_iter()
            .flat_map(|v| self.path_strings(v))
            .collect();
        if paths.is_empty() {
            vec![String::new()]
        } else {
            paths
        }
    }

    /// `extends` and `implements` types of a class or interface declaration.
    fn supertypes(&self, decl: Node) -> Vec<TypeRef> {
        let mut out = Vec::new();
        let mut cursor = decl.walk();
        for c in decl.children(&mut cursor) {
            if matches!(
                c.kind(),
                "superclass" | "super_interfaces" | "extends_interfaces"
            ) {
                let mut stack = vec![c];
                while let Some(n) = stack.pop() {
                    let mut k = n.walk();
                    for ch in n.named_children(&mut k) {
                        match ch.kind() {
                            "type_identifier" | "generic_type" | "scoped_type_identifier" => {
                                out.push(parse_type(&self.text(ch)))
                            }
                            "type_list" => stack.push(ch),
                            _ => {}
                        }
                    }
                }
            }
        }
        out
    }

    fn class_info(&mut self, decl: Node, parent: Option<&ClassInfo>) -> ClassInfo {
        let name = decl
            .child_by_field_name("name")
            .map(|n| self.text(n))
            .unwrap_or_default();
        let qualified = match parent {
            Some(p) => format!("{}.{}", p.qualified, name),
            None => name.clone(),
        };
        let anns = self.annotations(decl);
        let mut own = HashMap::new();
        let mut consts = Vec::new();
        self.collect_fields(decl, &mut own, &mut consts);
        for (n, v) in consts {
            self.out
                .security
                .consts
                .entry(format!("{name}.{n}"))
                .or_insert_with(|| v.clone());
            self.out.security.consts.entry(n).or_insert(v);
        }
        let mut fields = parent.map(|p| p.fields.clone()).unwrap_or_default();
        fields.extend(own.clone());
        let own_tparams = type_params(decl, self.src);
        let mut tparams = parent.map(|p| p.tparams.clone()).unwrap_or_default();
        tparams.extend(own_tparams.clone());
        let supers = self.supertypes(decl);
        let is_abstract = {
            let mut cursor = decl.walk();
            let abstract_modifier = decl
                .children(&mut cursor)
                .find(|c| c.kind() == "modifiers")
                .is_some_and(|m| self.text(m).split_whitespace().any(|w| w == "abstract"));
            abstract_modifier
        };
        let mut def = ClassDef {
            name: name.clone(),
            qualified: qualified.clone(),
            package: self.out.scope.package.clone(),
            file: self.file.to_string(),
            interface: matches!(
                decl.kind(),
                "interface_declaration" | "annotation_type_declaration"
            ),
            is_abstract,
            supers: supers.clone(),
            type_params: own_tparams,
            fields: own,
            ..Default::default()
        };
        let mut info = ClassInfo {
            simple: name.clone(),
            fields,
            tparams,
            def: 0,
            qualified,
            prefixes: vec![String::new()],
            servlet: false,
            servlet_paths: vec![],
            guards: vec![],
            public: vec![],
            feign: false,
        };
        let mut web_filter: Option<Vec<String>> = None;
        for a in &anns {
            match a.name.as_str() {
                "RequestMapping" => {
                    info.prefixes = self.paths_of(a, &["value", "path"]);
                }
                "Path" => {
                    info.prefixes = self.paths_of(a, &["value"]);
                }
                "FeignClient" => info.feign = true,
                "WebServlet" => {
                    info.servlet_paths = self.paths_of(a, &["value", "urlPatterns"]);
                }
                "WebFilter" => {
                    web_filter = Some(
                        self.paths_of(a, &["value", "urlPatterns"])
                            .into_iter()
                            .filter(|p| !p.is_empty())
                            .collect(),
                    );
                }
                "EnableMethodSecurity" | "EnableGlobalMethodSecurity" | "EnableReactiveMethodSecurity" => {
                    self.out.security.method_security = true;
                }
                "Primary" => def.primary = true,
                "Qualifier" => {
                    def.bean_name = self.qualifier_of(decl).or(def.bean_name.take());
                }
                n if STEREOTYPES.contains(&n) => {
                    def.component = true;
                    if def.bean_name.is_none() {
                        def.bean_name = self
                            .arg_values(a, &["value"])
                            .into_iter()
                            .find_map(|v| literal_strings(v, self.src))
                            .and_then(|v| v.into_iter().next())
                            .filter(|s| !s.is_empty());
                    }
                    if guard_annotation(n) {
                        info.guards.push(n.to_string());
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
        if let Some(sup) = decl.child_by_field_name("superclass") {
            let t = self.text(sup);
            if t.trim_start_matches("extends").trim().ends_with("Servlet") {
                info.servlet = true;
            }
        }
        if !info.servlet_paths.is_empty() {
            info.servlet = true;
        }
        // Jakarta filters: `@WebFilter` classes and anything extending a `*Filter`.
        if web_filter.is_some() || supers.iter().any(|s| s.name.ends_with("Filter")) {
            static BODY: OnceLock<Regex> = OnceLock::new();
            let body = re(
                &BODY,
                r"(?i)SC_UNAUTHORIZED|SC_FORBIDDEN|HttpStatus\.(UNAUTHORIZED|FORBIDDEN)|sendError\(\s*40[13]|getUserPrincipal|getRemoteUser|isUserInRole|SecurityContext|AuthenticationException|\bBearer\b|jwt",
            );
            let auth = auth_filter_name(&name) || body.is_match(&self.text(decl));
            let line = decl.start_position().row + 1;
            self.out.security.filters.push(FilterDef {
                name: name.clone(),
                patterns: web_filter.unwrap_or_default(),
                auth,
                source: format!("{}:{} filter class {}", self.file, line, name),
            });
        }
        self.out.classes.push(def);
        info.def = self.out.classes.len() - 1;
        info
    }

    /// Record the signature of a method (return type, whether it has a body) in its class.
    fn register_method(&mut self, node: Node, class: &ClassInfo) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = self.text(name_node);
        let own = type_params(node, self.src);
        let ret = node
            .child_by_field_name("type")
            .filter(|t| t.kind() != "void_type")
            .map(|t| parse_type(&self.text(t)));
        let has_body = node.child_by_field_name("body").is_some();
        let def = &mut self.out.classes[class.def];
        if let Some(r) = ret {
            let r = if own.contains(&r.name) { TypeRef::default() } else { r };
            def.methods.entry(name.clone()).or_default().push(r);
        }
        if has_body {
            def.bodied.insert(name);
        }
    }

    // ---- Spring Security rules -------------------------------------------------------------

    fn matcher_arg(
        &self,
        a: Node,
        regex: bool,
        method: &mut Option<String>,
        out: &mut Vec<Pm>,
        unresolved: &mut Vec<String>,
    ) {
        match a.kind() {
            "string_literal" => out.push(Pm {
                method: method.clone(),
                regex,
                arg: PArg::Lit(self.text(a).trim_matches('"').to_string()),
            }),
            "identifier" | "field_access" => {
                let t = self.text(a);
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
            "array_creation_expression" | "array_initializer" => {
                let mut cursor = a.walk();
                let kids: Vec<Node> = a.named_children(&mut cursor).collect();
                for k in kids {
                    if k.kind() != "dimensions_expr" && k.kind() != "type_identifier" {
                        self.matcher_arg(k, regex, method, out, unresolved);
                    }
                }
            }
            "method_invocation" => {
                let name = a
                    .child_by_field_name("name")
                    .map(|n| self.text(n))
                    .unwrap_or_default();
                if matches!(
                    name.as_str(),
                    "of" | "asList" | "copyOf" | "antMatcher" | "mvcMatcher" | "regexMatcher"
                        | "pattern"
                ) {
                    let regex = regex || name == "regexMatcher";
                    for x in args_of(a) {
                        self.matcher_arg(x, regex, method, out, unresolved);
                    }
                } else {
                    unresolved.push(self.text(a));
                }
            }
            "object_creation_expression" => {
                let ty = a
                    .child_by_field_name("type")
                    .map(|t| self.text(t))
                    .unwrap_or_default();
                if matches!(
                    ty.as_str(),
                    "AntPathRequestMatcher" | "MvcRequestMatcher" | "RegexRequestMatcher"
                ) {
                    let regex = regex || ty == "RegexRequestMatcher";
                    let mut local = method.clone();
                    let mut found: Vec<String> = Vec::new();
                    for x in args_of(a) {
                        if x.kind() == "string_literal" {
                            let v = self.text(x).trim_matches('"').to_string();
                            if !v.is_empty() && v.chars().all(|c| c.is_ascii_uppercase()) {
                                local = Some(v);
                            } else {
                                found.push(v);
                            }
                        } else if x.kind() == "field_access" && self.text(x).starts_with("HttpMethod.") {
                            local = self.text(x).strip_prefix("HttpMethod.").map(str::to_uppercase);
                        }
                    }
                    if found.is_empty() {
                        unresolved.push(self.text(a));
                    }
                    for v in found {
                        out.push(Pm {
                            method: local.clone(),
                            regex,
                            arg: PArg::Lit(v),
                        });
                    }
                } else {
                    unresolved.push(self.text(a));
                }
            }
            _ => unresolved.push(self.text(a)),
        }
    }

    fn matchers(&self, call: Node, regex: bool) -> (Vec<Pm>, Vec<String>) {
        let mut out = Vec::new();
        let mut unresolved = Vec::new();
        let mut method = None;
        for a in args_of(call) {
            self.matcher_arg(a, regex, &mut method, &mut out, &mut unresolved);
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

    fn security_hook(&mut self, node: Node, name: &str) {
        let compact = |s: String| -> String {
            let t: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
            t.chars().take(140).collect()
        };
        match name {
            "permitAll" | "anonymous" | "denyAll" | "authenticated" | "fullyAuthenticated"
            | "rememberMe" | "hasRole" | "hasAnyRole" | "hasAuthority" | "hasAnyAuthority"
            | "hasIpAddress" | "access" => {
                let Some(obj) = node.child_by_field_name("object") else {
                    return;
                };
                if obj.kind() != "method_invocation" {
                    return;
                }
                let Some(mname_node) = obj.child_by_field_name("name") else {
                    return;
                };
                let mname = self.text(mname_node);
                let any = mname == "anyRequest";
                if !(any || MATCHER_CALLS.contains(&mname.as_str())) {
                    return;
                }
                let args_text = node
                    .child_by_field_name("arguments")
                    .map(|a| self.text(a))
                    .unwrap_or_default();
                let inner: String = args_text
                    .trim_start_matches('(')
                    .trim_end_matches(')')
                    .replace(['"', '\''], "");
                let access = match name {
                    "permitAll" | "anonymous" => Access::Public,
                    "denyAll" => Access::Denied,
                    "authenticated" | "fullyAuthenticated" | "rememberMe" => Access::Authenticated,
                    "access" if inner.contains("permitAll") => Access::Public,
                    "access" if inner.contains("denyAll") => Access::Denied,
                    _ => Access::Role(compact(format!("{name}({})", inner.trim()))),
                };
                let (matchers, unresolved) = if any {
                    (vec![], vec![])
                } else {
                    self.matchers(obj, mname == "regexMatchers")
                };
                let line = mname_node.start_position().row + 1;
                let matcher_text = if any {
                    "anyRequest()".to_string()
                } else {
                    format!(
                        "{mname}{}",
                        obj.child_by_field_name("arguments")
                            .map(|a| self.text(a))
                            .unwrap_or_default()
                    )
                };
                let rule = UrlRule {
                    any,
                    matchers,
                    access,
                    source: compact(format!(
                        "{}:{} {}.{}{}",
                        self.file, line, matcher_text, name, args_text
                    )),
                    pos: mname_node.start_byte(),
                };
                for u in unresolved.into_iter().take(1) {
                    self.note_unresolved(&u, line);
                }
                let key = self.chain_key;
                self.out.security.chain_mut(key, self.file).rules.push(rule);
            }
            "requestMatchers" | "antMatchers" | "mvcMatchers" | "regexMatchers" => {
                // `web.ignoring().requestMatchers(...)`: the request never reaches the filter chain.
                let Some(obj) = node.child_by_field_name("object") else {
                    return;
                };
                if obj.kind() != "method_invocation"
                    || obj
                        .child_by_field_name("name")
                        .map(|n| self.text(n))
                        .as_deref()
                        != Some("ignoring")
                {
                    return;
                }
                let (matchers, unresolved) = self.matchers(node, name == "regexMatchers");
                let line = node.start_position().row + 1;
                for u in unresolved.into_iter().take(1) {
                    self.note_unresolved(&u, line);
                }
                let args_text = node
                    .child_by_field_name("arguments")
                    .map(|a| self.text(a))
                    .unwrap_or_default();
                let rule = UrlRule {
                    any: false,
                    matchers,
                    access: Access::Public,
                    source: compact(format!("{}:{} web.ignoring().{}{}", self.file, line, name, args_text)),
                    pos: 0,
                };
                // Ignored requests skip every chain.
                self.out.security.ignoring.push(rule);
            }
            "securityMatcher" | "antMatcher" | "mvcMatcher" | "regexMatcher" => {
                let (matchers, unresolved) = self.matchers(node, name == "regexMatcher");
                let line = node.start_position().row + 1;
                for u in unresolved.into_iter().take(1) {
                    self.note_unresolved(&u, line);
                }
                let key = self.chain_key;
                self.out.security.chain_mut(key, self.file).scope.extend(matchers);
            }
            "addFilterBefore" | "addFilterAfter" | "addFilterAt" | "addFilter" => {
                let Some(first) = args_of(node).into_iter().next() else {
                    return;
                };
                let filter = match first.kind() {
                    "object_creation_expression" => first
                        .child_by_field_name("type")
                        .map(|t| simple_type(&self.text(t))),
                    "method_invocation" => first.child_by_field_name("name").map(|n| self.text(n)),
                    "identifier" => Some(self.text(first)),
                    _ => None,
                };
                if let Some(f) = filter.filter(|f| !f.is_empty()) {
                    let line = node.start_position().row + 1;
                    let source = format!("{}:{} {}({})", self.file, line, name, f);
                    let key = self.chain_key;
                    self.out.security.chain_mut(key, self.file).filters.push((f, source));
                }
            }
            _ => {}
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

    fn render_callee(&self, n: Node, depth: usize) -> String {
        let t = match n.kind() {
            "method_invocation" if depth < 6 => {
                let name = n
                    .child_by_field_name("name")
                    .map(|x| self.text(x))
                    .unwrap_or_default();
                match n.child_by_field_name("object") {
                    Some(o) => format!("{}.{}()", self.render_callee(o, depth + 1), name),
                    None => format!("{name}()"),
                }
            }
            "object_creation_expression" => {
                let ty = n
                    .child_by_field_name("type")
                    .map(|x| self.text(x))
                    .unwrap_or_default();
                format!("new {ty}()")
            }
            "identifier" | "this" | "field_access" | "scoped_identifier" | "type_identifier" => {
                self.text(n)
            }
            _ => "<expr>".to_string(),
        };
        let t: String = t.split_whitespace().collect();
        t.chars().take(160).collect()
    }

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
        // A plain variable, field or class name gives the type at once; a chain is resolved later.
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

    fn walk(&mut self, node: Node, cur: &str, class: Option<&ClassInfo>) {
        match node.kind() {
            "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration" => {
                let info = self.class_info(node, class);
                let mut cursor = node.walk();
                let kids: Vec<Node> = node.children(&mut cursor).collect();
                for k in kids {
                    self.walk(k, cur, Some(&info));
                }
                return;
            }
            "method_declaration" | "constructor_declaration" => {
                if let (Some(c), "method_declaration") = (class, node.kind()) {
                    self.register_method(node, c);
                }
                let mtparams = type_params(node, self.src);
                if let Some(id) = self.method(node, class) {
                    let (locals, pending) = self.collect_locals(node, class);
                    let outer = std::mem::replace(&mut self.locals, locals);
                    let outer_tp = std::mem::replace(&mut self.mtparams, mtparams);
                    let outer_key = std::mem::replace(&mut self.chain_key, node.id());
                    for (_, name, value, extra) in pending {
                        if let Some(mut p) = self.recv_path(Some(value), class, 0) {
                            p.steps.extend(extra);
                            p.hint = None;
                            self.locals.insert(name, Local::Path(p));
                        }
                    }
                    let mut cursor = node.walk();
                    let kids: Vec<Node> = node.children(&mut cursor).collect();
                    for k in kids {
                        self.walk(k, &id, class);
                    }
                    self.locals = outer;
                    self.mtparams = outer_tp;
                    self.chain_key = outer_key;
                    return;
                }
            }
            "method_invocation" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = self.text(name_node);
                    let text = match node.child_by_field_name("object") {
                        Some(o) => format!("{}.{}", self.render_callee(o, 0), name),
                        None => name.clone(),
                    };
                    let rt = self.recv_path(node.child_by_field_name("object"), class, 0);
                    self.security_hook(node, &name);
                    self.add_call(cur, name, text, name_node.start_position().row + 1, rt);
                }
            }
            "object_creation_expression" => {
                if let Some(ty) = node.child_by_field_name("type") {
                    let full = self.text(ty);
                    let base = full.split('<').next().unwrap_or("");
                    let simple = base.rsplit('.').next().unwrap_or("").trim().to_string();
                    self.add_call(
                        cur,
                        simple.clone(),
                        format!("new {simple}"),
                        node.start_position().row + 1,
                        None,
                    );
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let kids: Vec<Node> = node.children(&mut cursor).collect();
        for k in kids {
            self.walk(k, cur, class);
        }
    }

    /// Record a method or constructor that has a body, plus the routes it serves.
    fn method(&mut self, node: Node, class: Option<&ClassInfo>) -> Option<String> {
        node.child_by_field_name("body")?;
        let name = self.text(node.child_by_field_name("name")?);
        let qualified = match class {
            Some(c) => format!("{}.{}", c.qualified, name),
            None => name.clone(),
        };
        let id = self.symbol(&name, &qualified, "method", node);
        if let Some(c) = class {
            if node.kind() == "method_declaration" {
                self.routes(node, c, &name, &id);
            }
        }
        Some(id)
    }

    fn routes(&mut self, node: Node, class: &ClassInfo, method_name: &str, id: &str) {
        if class.feign {
            return;
        }
        let anns = self.annotations(node);
        let mut middleware: Vec<String> = class.guards.clone();
        middleware.extend(class.public.iter().cloned());
        let mut guards: Vec<String> = class.guards.clone();
        let mut public_names: Vec<String> = class.public.clone();
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
            let line = a.node.start_position().row + 1;
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
                        let mut ms: Vec<String> = Vec::new();
                        for v in self.arg_values(a, &["method"]) {
                            static M: OnceLock<Regex> = OnceLock::new();
                            for c in re(&M, r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\b")
                                .captures_iter(&self.text(v))
                            {
                                ms.push(c[1].to_string());
                            }
                        }
                        if ms.is_empty() {
                            ms.push("ANY".to_string());
                        }
                        ms
                    }
                };
                let sub = self.paths_of(a, &["value", "path"]);
                for m in methods {
                    for p in &class.prefixes {
                        for s in &sub {
                            found.push((m.clone(), join_path(p, s), line, "spring"));
                        }
                    }
                }
                continue;
            }
            let jax = match a.name.as_str() {
                "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS" => {
                    Some(a.name.clone())
                }
                _ => None,
            };
            if let Some(m) = jax {
                let sub = own_path
                    .map(|p| self.paths_of(p, &["value"]))
                    .unwrap_or_else(|| vec![String::new()]);
                for p in &class.prefixes {
                    for s in &sub {
                        found.push((m.clone(), join_path(p, s), line, "jax-rs"));
                    }
                }
            }
        }
        if found.is_empty() && class.servlet {
            let verb = match method_name {
                "doGet" => Some("GET"),
                "doPost" => Some("POST"),
                "doPut" => Some("PUT"),
                "doDelete" => Some("DELETE"),
                "doHead" => Some("HEAD"),
                "doOptions" => Some("OPTIONS"),
                "service" => Some("ANY"),
                _ => None,
            };
            if let Some(v) = verb {
                let paths: Vec<String> = if class.servlet_paths.is_empty() {
                    vec![format!("/{{servlet:{}}}", class.qualified)]
                } else {
                    class
                        .servlet_paths
                        .iter()
                        .map(|p| join_path("", p))
                        .collect()
                };
                let line = node.start_position().row + 1;
                for p in paths {
                    found.push((v.to_string(), p, line, "servlet"));
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
}

fn join_path(prefix: &str, sub: &str) -> String {
    let joined = format!("/{}/{}", prefix.trim_matches('/'), sub.trim_matches('/'));
    let mut out = String::with_capacity(joined.len());
    for c in joined.chars() {
        if c == '/' && out.ends_with('/') {
            continue;
        }
        out.push(c);
    }
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

/// Extract the graph of one parsed Java file.
pub(super) fn extract(rel: &str, source: &str, root: Node) -> FileGraph {
    let mut out = FileGraph::default();
    let mut w = Walker {
        file: rel,
        src: source.as_bytes(),
        out: &mut out,
        locals: HashMap::new(),
        mtparams: vec![],
        chain_key: 0,
    };
    let module = w.symbol("<module>", "<module>", "module", root);
    w.scope(root);
    w.walk(root, &module, None);
    out
}

/// Annotations that only take effect when method security is enabled.
fn is_method_security_annotation(name: &str) -> bool {
    matches!(
        name,
        "PreAuthorize" | "PostAuthorize" | "PreFilter" | "PostFilter" | "Secured"
    )
}

/// Request matcher calls of the Spring Security authorization DSL.
const MATCHER_CALLS: [&str; 4] = ["requestMatchers", "antMatchers", "mvcMatchers", "regexMatchers"];

fn args_of<'t>(call: Node<'t>) -> Vec<Node<'t>> {
    super::args_of(call)
}

impl<'a> Walker<'a> {
    /// Package and imports of the file.
    fn scope(&mut self, root: Node) {
        let mut cursor = root.walk();
        let kids: Vec<Node> = root.children(&mut cursor).collect();
        let mut scope = FileScope::default();
        for k in kids {
            match k.kind() {
                "package_declaration" => {
                    scope.package = self
                        .text(k)
                        .trim_start_matches("package")
                        .trim()
                        .trim_end_matches(';')
                        .trim()
                        .to_string();
                }
                "import_declaration" => {
                    let t = self.text(k);
                    let t = t
                        .trim_start_matches("import")
                        .trim()
                        .trim_start_matches("static")
                        .trim()
                        .trim_end_matches(';')
                        .trim()
                        .to_string();
                    scope.imports.push(t);
                }
                _ => {}
            }
        }
        self.out.scope = scope;
    }
}
