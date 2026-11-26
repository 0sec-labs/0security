//! Java extractor for `foxguard graph`: methods, constructors, call edges, HTTP routes and entry
//! points (Spring MVC, JAX-RS, servlets), sink calls and auth signals.
//!
//! It is lexical. Types are not resolved: a call carries the callee name and the receiver text as
//! written, and a consumer joins it to symbols by name. Annotations are matched by their simple name,
//! so a project-local annotation called `PreAuthorize` counts like the Spring one.

use super::{FileGraph, GraphCall, GraphRoute, GraphSymbol, SinkTag};
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
    /// Declared type (simple name) of each field, including those of enclosing classes.
    fields: HashMap<String, String>,
    /// Spring `@RequestMapping` / JAX-RS `@Path` prefixes of the class.
    prefixes: Vec<String>,
    servlet: bool,
    servlet_paths: Vec<String>,
    /// Guard annotations that apply to every method of the class.
    guards: Vec<String>,
    public: Vec<String>,
    feign: bool,
}

struct Walker<'a> {
    file: &'a str,
    src: &'a [u8],
    out: &'a mut FileGraph,
    /// Declared type of each parameter and local of the method being walked.
    locals: HashMap<String, String>,
}

/// `java.util.List<String>[]` -> `List`.
fn simple_type(t: &str) -> String {
    let base = t.split('<').next().unwrap_or("");
    let base = base.trim().trim_end_matches("[]").trim_end_matches("...");
    base.rsplit('.').next().unwrap_or("").trim().to_string()
}

impl<'a> Walker<'a> {
    /// Fill `map` with `name -> declared type` for the fields declared directly in a class body.
    fn collect_fields(&self, decl: Node, map: &mut HashMap<String, String>) {
        let Some(body) = decl.child_by_field_name("body") else {
            return;
        };
        let mut cursor = body.walk();
        for member in body.children(&mut cursor) {
            if member.kind() != "field_declaration" {
                continue;
            }
            let Some(ty) = member.child_by_field_name("type") else {
                continue;
            };
            let ty = simple_type(&self.text(ty));
            let mut inner = member.walk();
            for d in member.children(&mut inner) {
                if d.kind() == "variable_declarator" {
                    if let Some(n) = d.child_by_field_name("name") {
                        map.insert(self.text(n), ty.clone());
                    }
                }
            }
        }
    }

    /// Parameters and local variables of a method, by declared type (`var x = new T()` gives `T`).
    fn collect_locals(&self, method: Node) -> HashMap<String, String> {
        let mut map = HashMap::new();
        let mut stack = vec![method];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "formal_parameter" | "catch_formal_parameter" | "resource" => {
                    if let (Some(t), Some(name)) =
                        (n.child_by_field_name("type"), n.child_by_field_name("name"))
                    {
                        map.insert(self.text(name), simple_type(&self.text(t)));
                    }
                }
                "local_variable_declaration" | "enhanced_for_statement" => {
                    if let Some(t) = n.child_by_field_name("type") {
                        let declared = simple_type(&self.text(t));
                        let mut cursor = n.walk();
                        let kids: Vec<Node> = n.children(&mut cursor).collect();
                        for d in kids {
                            if d.kind() != "variable_declarator" {
                                continue;
                            }
                            let Some(name) = d.child_by_field_name("name") else {
                                continue;
                            };
                            let mut ty = declared.clone();
                            if ty == "var" {
                                ty = d
                                    .child_by_field_name("value")
                                    .filter(|v| v.kind() == "object_creation_expression")
                                    .and_then(|v| v.child_by_field_name("type"))
                                    .map(|t| simple_type(&self.text(t)))
                                    .unwrap_or_default();
                            }
                            if !ty.is_empty() {
                                map.insert(self.text(name), ty);
                            }
                        }
                        if n.kind() == "enhanced_for_statement" {
                            if let Some(name) = n.child_by_field_name("name") {
                                map.insert(self.text(name), declared.clone());
                            }
                        }
                    }
                }
                _ => {}
            }
            let mut cursor = n.walk();
            stack.extend(n.children(&mut cursor));
        }
        map
    }

    /// Declared type of a call receiver, when it is a plain variable, `this.field`, a class name
    /// (static call) or a `new T()`. `None` for chains and expressions.
    fn receiver_type(&self, recv: Option<Node>, class: Option<&ClassInfo>) -> Option<String> {
        let this_class = class.map(|c| c.simple.clone());
        let Some(o) = recv else {
            return this_class;
        };
        let lookup = |name: &str| {
            self.locals
                .get(name)
                .cloned()
                .or_else(|| class.and_then(|c| c.fields.get(name).cloned()))
        };
        match o.kind() {
            "this" => this_class,
            "identifier" => {
                let name = self.text(o);
                lookup(&name).or_else(|| {
                    name.chars()
                        .next()
                        .filter(|c| c.is_uppercase())
                        .map(|_| name.clone())
                })
            }
            "field_access" => {
                let object = o.child_by_field_name("object")?;
                let field = self.text(o.child_by_field_name("field")?);
                if object.kind() == "this" {
                    class.and_then(|c| c.fields.get(&field).cloned())
                } else {
                    None
                }
            }
            "object_creation_expression" => o
                .child_by_field_name("type")
                .map(|t| simple_type(&self.text(t))),
            _ => None,
        }
        .filter(|t| !t.is_empty() && t != "var")
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

    fn class_info(&self, decl: Node, parent: Option<&ClassInfo>) -> ClassInfo {
        let name = decl
            .child_by_field_name("name")
            .map(|n| self.text(n))
            .unwrap_or_default();
        let qualified = match parent {
            Some(p) => format!("{}.{}", p.qualified, name),
            None => name.clone(),
        };
        let anns = self.annotations(decl);
        let mut fields = parent.map(|p| p.fields.clone()).unwrap_or_default();
        self.collect_fields(decl, &mut fields);
        let mut info = ClassInfo {
            simple: name.clone(),
            fields,
            qualified,
            prefixes: vec![String::new()],
            servlet: false,
            servlet_paths: vec![],
            guards: vec![],
            public: vec![],
            feign: false,
        };
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
                n if guard_annotation(n) => info.guards.push(n.to_string()),
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
        info
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
        receiver_type: Option<String>,
    ) {
        if name.is_empty() {
            return;
        }
        let sink = sink_category(&text, &name).map(|category| SinkTag {
            category,
            text: text.clone(),
        });
        let auth = auth_signal(&name, &text);
        if matches!(
            name.as_str(),
            "authorizeHttpRequests"
                | "authorizeRequests"
                | "requestMatchers"
                | "antMatchers"
                | "mvcMatchers"
        ) && !self
            .out
            .notes
            .iter()
            .any(|n| n.starts_with("spring-security-url-rules"))
        {
            self.out.notes.push(
                "spring-security-url-rules: URL-pattern authorization rules exist; they are not mapped to routes, so a route can be guarded there without an annotation".to_string(),
            );
        }
        self.out.calls.push(GraphCall {
            from: from.to_string(),
            name,
            text,
            file: self.file.to_string(),
            line,
            sink,
            auth,
            receiver_type,
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
                if let Some(id) = self.method(node, class) {
                    let locals = self.collect_locals(node);
                    let outer = std::mem::replace(&mut self.locals, locals);
                    let mut cursor = node.walk();
                    let kids: Vec<Node> = node.children(&mut cursor).collect();
                    for k in kids {
                        self.walk(k, &id, class);
                    }
                    self.locals = outer;
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
                    let rt = self.receiver_type(node.child_by_field_name("object"), class);
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
        for a in &anns {
            if guard_annotation(&a.name) {
                guards.push(a.name.clone());
                middleware.push(a.name.clone());
            } else if PUBLIC_ANNOTATIONS.contains(&a.name.as_str()) {
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
        for (method, path, line, framework) in found {
            self.out.routes.push(GraphRoute {
                method,
                path,
                file: self.file.to_string(),
                line,
                handler: id.to_string(),
                middleware: middleware.clone(),
                framework,
                auth_signals: guards.clone(),
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
    };
    let module = w.symbol("<module>", "<module>", "module", root);
    w.walk(root, &module, None);
    out
}
