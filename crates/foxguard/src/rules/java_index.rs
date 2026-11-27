//! A project-wide index of Java types and their fields.
//!
//! The flow interpreter in [`crate::rules::java_flow`] treats `Type.NAME` as a
//! constant only when it can read the declaration. When `Type` lives in another
//! file of the scanned project, this index says which class a simple name
//! denotes from the point of view of one file (package, imports, nesting) and
//! which fields that class declares, so the field's initialiser can be read in
//! its own file.
//!
//! Everything here is conservative: a name that resolves to no class, to
//! several classes, or to a class we may not have seen is reported as
//! unresolved, and the interpreter then treats the value as unknown.

use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tree_sitter::Node;

/// Parsed files kept for reading initialisers; the cache is bounded.
const PARSE_CACHE_LIMIT: usize = 32;
/// Supertype chains longer than this are not followed.
const MAX_SUPER_DEPTH: usize = 8;

const TYPE_DECLS: &[&str] = &[
    "class_declaration",
    "interface_declaration",
    "enum_declaration",
    "record_declaration",
    "annotation_type_declaration",
];

/// What a file says about the names it can use: its package, imports and the
/// types it declares.
#[derive(Clone, Debug, Default)]
pub struct ImportCtx {
    pub package: String,
    /// Simple name -> fully qualified name, from `import a.b.C;`.
    single: HashMap<String, String>,
    /// Packages or types imported with `import a.b.*;`.
    on_demand: Vec<String>,
    /// Member name -> class names, from `import static a.b.C.NAME;`.
    static_single: HashMap<String, Vec<String>>,
    /// Classes imported with `import static a.b.C.*;`.
    static_on_demand: Vec<String>,
    /// Simple name -> declared types of this file (nested ones included).
    local_types: HashMap<String, Vec<String>>,
}

impl ImportCtx {
    pub fn from_tree(root: Node<'_>, src: &str) -> Self {
        let mut ctx = ImportCtx::default();
        let mut c = root.walk();
        for n in root.named_children(&mut c) {
            let text = &src[n.byte_range()];
            match n.kind() {
                "package_declaration" => {
                    ctx.package = text
                        .trim_start_matches("package")
                        .trim_end_matches(';')
                        .split_whitespace()
                        .collect::<String>();
                }
                "import_declaration" => ctx.add_import(text),
                _ => {}
            }
        }
        let mut decls = Vec::new();
        collect_types(root, src, &ctx.package, true, &mut decls);
        for d in decls {
            ctx.local_types.entry(d.simple).or_default().push(d.fqn);
        }
        ctx
    }

    fn add_import(&mut self, text: &str) {
        let body = text
            .trim()
            .trim_start_matches("import")
            .trim_end_matches(';');
        let mut words = body.split_whitespace().peekable();
        let is_static = words.peek() == Some(&"static");
        if is_static {
            words.next();
        }
        let path: String = words.collect();
        if path.is_empty() {
            return;
        }
        if let Some(prefix) = path.strip_suffix(".*") {
            if is_static {
                self.static_on_demand.push(prefix.to_string());
            } else {
                self.on_demand.push(prefix.to_string());
            }
            return;
        }
        let Some((owner, last)) = path.rsplit_once('.') else {
            return;
        };
        if is_static {
            self.static_single
                .entry(last.to_string())
                .or_default()
                .push(owner.to_string());
        } else {
            self.single.insert(last.to_string(), path.clone());
        }
    }

    /// Classes named by `import static ...Class.name;`.
    pub fn static_import_classes(&self, name: &str) -> &[String] {
        self.static_single.get(name).map_or(&[], |v| v.as_slice())
    }

    /// Classes imported with `import static ...Class.*;`.
    pub fn static_on_demand_classes(&self) -> &[String] {
        &self.static_on_demand
    }
}

struct TypeDecl<'t> {
    simple: String,
    fqn: String,
    node: Node<'t>,
    /// Declared as a member of the file or of another member type, not inside
    /// a method or an initialiser.
    member: bool,
}

/// Every type declaration of the file. Member types get `pkg.Outer.Inner`
/// names; a type declared inside a method or expression gets a name that never
/// matches an indexed class (it can still shadow one).
fn collect_types<'t>(
    node: Node<'t>,
    src: &str,
    prefix: &str,
    member: bool,
    out: &mut Vec<TypeDecl<'t>>,
) {
    let mut c = node.walk();
    for child in node.named_children(&mut c) {
        if TYPE_DECLS.contains(&child.kind()) {
            let Some(name) = child
                .child_by_field_name("name")
                .map(|n| src[n.byte_range()].to_string())
            else {
                continue;
            };
            let fqn = if member {
                join(prefix, &name)
            } else {
                join(prefix, &format!("#local#{name}"))
            };
            out.push(TypeDecl {
                simple: name,
                fqn: fqn.clone(),
                node: child,
                member,
            });
            collect_types(child, src, &fqn, member, out);
        } else if matches!(
            child.kind(),
            "class_body" | "interface_body" | "enum_body" | "enum_body_declarations"
        ) {
            collect_types(child, src, prefix, member, out);
        } else if child.named_child_count() > 0 {
            collect_types(child, src, prefix, false, out);
        }
    }
}

fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}.{name}")
    }
}

#[derive(Clone, Debug)]
pub struct FieldFacts {
    /// `static final`, an interface field, or an enum constant.
    pub constant: bool,
    /// Declared with an immutable value type (a string, a primitive or its
    /// box, a file or path). A mutable object stored in a constant can still be
    /// changed through its methods, so those stay unknown.
    pub value_type: bool,
    pub enum_constant: bool,
    /// Byte range of the initialiser in the declaring file.
    pub init: Option<(usize, usize)>,
}

#[derive(Debug)]
pub struct ClassFacts {
    pub file: usize,
    pub fields: HashMap<String, FieldFacts>,
    /// Raw names of the superclass and implemented or extended interfaces.
    pub supers: Vec<String>,
}

pub struct Parsed {
    pub src: String,
    pub tree: tree_sitter::Tree,
}

pub struct JavaProjectIndex {
    files: Vec<(PathBuf, ImportCtx)>,
    classes: HashMap<String, ClassFacts>,
    /// Simple names that an unindexed file may also declare.
    shadowed: HashSet<String>,
    /// Names assigned, incremented or compound-assigned anywhere.
    assigned: HashSet<String>,
    parsed: Mutex<HashMap<usize, Arc<Parsed>>>,
    results: Mutex<HashMap<String, bool>>,
}

/// What one file contributed.
struct FileFacts {
    path: PathBuf,
    ctx: ImportCtx,
    classes: Vec<(String, Vec<String>, HashMap<String, FieldFacts>)>,
    assigned: Vec<String>,
}

impl JavaProjectIndex {
    /// Index the files. A file that cannot be read or parsed is not skipped
    /// silently: its stem is recorded so a name it probably declares is never
    /// resolved to another class.
    pub fn build(paths: &[PathBuf], max_file_size: u64) -> Self {
        let results: Vec<Result<FileFacts, String>> = paths
            .par_iter()
            .map(|path| {
                let stem = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                if std::fs::metadata(path).map_or(true, |m| m.len() > max_file_size) {
                    return Err(stem);
                }
                let source = std::fs::read_to_string(path).map_err(|_| stem.clone())?;
                let tree = crate::engine::parser::parse_file(&source, crate::Language::Java)
                    .ok_or(stem)?;
                Ok(extract(path, &source, tree.root_node()))
            })
            .collect();
        let mut idx = JavaProjectIndex {
            files: Vec::new(),
            classes: HashMap::new(),
            shadowed: HashSet::new(),
            assigned: HashSet::new(),
            parsed: Mutex::new(HashMap::new()),
            results: Mutex::new(HashMap::new()),
        };
        // Two declarations of one qualified name (a duplicate or a generated
        // copy) make that class unknowable.
        let mut seen: HashSet<String> = HashSet::new();
        let mut duplicated: HashSet<String> = HashSet::new();
        for r in results {
            match r {
                Err(stem) => {
                    idx.shadowed.insert(stem);
                }
                Ok(f) => {
                    let file = idx.files.len();
                    for (fqn, supers, fields) in f.classes {
                        if !seen.insert(fqn.clone()) {
                            duplicated.insert(fqn.clone());
                        }
                        idx.classes.insert(
                            fqn,
                            ClassFacts {
                                file,
                                fields,
                                supers,
                            },
                        );
                    }
                    idx.assigned.extend(f.assigned);
                    idx.files.push((f.path, f.ctx));
                }
            }
        }
        for fqn in duplicated {
            idx.classes.remove(&fqn);
            if let Some(simple) = fqn.rsplit('.').next() {
                idx.shadowed.insert(simple.to_string());
            }
        }
        idx
    }

    /// The fully qualified class `text` (`Type`, `Outer.Inner`, `pkg.Type`)
    /// denotes in a file with context `ctx`, or `None` when it is not a
    /// scanned class or the name could mean something else.
    pub fn resolve_type(&self, ctx: &ImportCtx, text: &str) -> Option<String> {
        let text: String = text
            .split('<')
            .next()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        let mut parts = text.split('.');
        let head = parts.next().filter(|h| !h.is_empty())?;
        let mut cur = if head.starts_with(|c: char| c.is_ascii_lowercase()) {
            // A qualified name: the longest package prefix that names a class.
            let all: Vec<&str> = text.split('.').collect();
            let mut found = None;
            for n in 1..=all.len() {
                let cand = all[..n].join(".");
                if self.classes.contains_key(&cand) {
                    found = Some((cand, n));
                    break;
                }
            }
            let (cand, n) = found?;
            for _ in 1..n {
                parts.next();
            }
            cand
        } else {
            self.resolve_simple(ctx, head)?
        };
        for p in parts {
            cur = format!("{cur}.{p}");
            if !self.classes.contains_key(&cur) {
                return None;
            }
        }
        self.classes.contains_key(&cur).then_some(cur)
    }

    fn resolve_simple(&self, ctx: &ImportCtx, name: &str) -> Option<String> {
        if let Some(local) = ctx.local_types.get(name) {
            return match local.as_slice() {
                [one] if self.classes.contains_key(one) => Some(one.clone()),
                _ => None,
            };
        }
        if let Some(full) = ctx.single.get(name) {
            return self.classes.contains_key(full).then(|| full.clone());
        }
        if self.shadowed.contains(name) {
            return None;
        }
        let same = join(&ctx.package, name);
        if self.classes.contains_key(&same) {
            return Some(same);
        }
        let mut hits: Vec<String> = ctx
            .on_demand
            .iter()
            .map(|p| join(p, name))
            .filter(|f| self.classes.contains_key(f))
            .collect();
        hits.sort();
        hits.dedup();
        match hits.as_slice() {
            [one] if !is_implicit_import(name) => Some(one.clone()),
            _ => None,
        }
    }

    /// The classes, starting at `class` and walking its supertypes, whose own
    /// members include `name`. Several owners mean the name is ambiguous.
    pub fn field_owners(&self, class: &str, name: &str) -> Vec<String> {
        let mut out = Vec::new();
        self.collect_owners(class, name, 0, &mut Vec::new(), &mut out);
        out.sort();
        out.dedup();
        out
    }

    fn collect_owners(
        &self,
        class: &str,
        name: &str,
        depth: usize,
        seen: &mut Vec<String>,
        out: &mut Vec<String>,
    ) {
        let Some(c) = self.classes.get(class) else {
            return;
        };
        if c.fields.contains_key(name) {
            out.push(class.to_string());
            return;
        }
        if depth >= MAX_SUPER_DEPTH || seen.iter().any(|s| s == class) {
            return;
        }
        seen.push(class.to_string());
        let ctx = &self.files[c.file].1;
        for s in &c.supers {
            if let Some(fqn) = self.resolve_type(ctx, s) {
                self.collect_owners(&fqn, name, depth + 1, seen, out);
            }
        }
        seen.pop();
    }

    pub fn field(&self, class: &str, name: &str) -> Option<&FieldFacts> {
        self.classes.get(class)?.fields.get(name)
    }

    pub fn class_file(&self, class: &str) -> Option<usize> {
        self.classes.get(class).map(|c| c.file)
    }

    /// Is `name` written to anywhere in the scanned project? A constant that
    /// something assigns (a blank final set in an initialiser, a field some
    /// other code writes) is not a constant.
    pub fn is_assigned(&self, name: &str) -> bool {
        self.assigned.contains(name)
    }

    pub fn path(&self, file: usize) -> &Path {
        &self.files[file].0
    }

    /// Read and parse a file again to evaluate an initialiser in it.
    pub fn load(&self, file: usize) -> Option<Arc<Parsed>> {
        if let Some(p) = self.parsed.lock().ok()?.get(&file) {
            return Some(p.clone());
        }
        let src = std::fs::read_to_string(self.path(file)).ok()?;
        let tree = crate::engine::parser::parse_file(&src, crate::Language::Java)?;
        let p = Arc::new(Parsed { src, tree });
        let mut cache = self.parsed.lock().ok()?;
        if cache.len() >= PARSE_CACHE_LIMIT {
            cache.clear();
        }
        cache.insert(file, p.clone());
        Some(p)
    }

    pub fn cached_result(&self, key: &str) -> Option<bool> {
        self.results.lock().ok()?.get(key).copied()
    }

    pub fn store_result(&self, key: String, safe: bool) {
        if let Ok(mut r) = self.results.lock() {
            r.insert(key, safe);
        }
    }

    pub fn ctx_of_file(&self, file: usize) -> &ImportCtx {
        &self.files[file].1
    }
}

fn is_implicit_import(name: &str) -> bool {
    matches!(
        name,
        "Object"
            | "String"
            | "Math"
            | "System"
            | "Integer"
            | "Long"
            | "Boolean"
            | "Character"
            | "Thread"
            | "Runtime"
            | "Process"
            | "Class"
            | "Number"
            | "Enum"
            | "Record"
            | "Double"
            | "Float"
            | "Short"
            | "Byte"
    )
}

/// Names of the supertypes in a type declaration's `extends`, `implements` and
/// `permits`-free clauses, or the type of an anonymous class.
pub fn super_types(decl: Node<'_>, src: &str) -> Vec<String> {
    let mut out = Vec::new();
    if decl.kind() == "object_creation_expression" {
        if let Some(t) = decl.child_by_field_name("type") {
            out.push(src[t.byte_range()].to_string());
        }
        return out;
    }
    let mut c = decl.walk();
    for child in decl.named_children(&mut c) {
        match child.kind() {
            "superclass" | "super_interfaces" | "extends_interfaces" => {
                collect_type_names(child, src, &mut out)
            }
            _ => {}
        }
    }
    out
}

fn collect_type_names(node: Node<'_>, src: &str, out: &mut Vec<String>) {
    let mut c = node.walk();
    for child in node.named_children(&mut c) {
        match child.kind() {
            "type_identifier" | "scoped_type_identifier" => {
                out.push(src[child.byte_range()].to_string())
            }
            "generic_type" => {
                if let Some(first) = child.named_child(0) {
                    out.push(src[first.byte_range()].to_string());
                }
            }
            "type_list" => collect_type_names(child, src, out),
            _ => {}
        }
    }
}

fn is_value_type(ty: &str) -> bool {
    let base = ty.rsplit('.').next().unwrap_or(ty).trim();
    matches!(
        base,
        "String"
            | "int"
            | "long"
            | "short"
            | "byte"
            | "char"
            | "boolean"
            | "float"
            | "double"
            | "Integer"
            | "Long"
            | "Short"
            | "Byte"
            | "Character"
            | "Boolean"
            | "Float"
            | "Double"
            | "File"
            | "Path"
    )
}

fn extract(path: &Path, src: &str, root: Node<'_>) -> FileFacts {
    let ctx = ImportCtx::from_tree(root, src);
    let mut decls = Vec::new();
    collect_types(root, src, &ctx.package, true, &mut decls);
    let mut classes = Vec::new();
    for d in decls.iter().filter(|d| d.member) {
        classes.push((
            d.fqn.clone(),
            super_types(d.node, src),
            fields_of(d.node, src),
        ));
    }
    let mut assigned = Vec::new();
    walk(root, &mut |n| {
        let target = match n.kind() {
            "assignment_expression" => n.child_by_field_name("left"),
            "update_expression" => n.named_child(0),
            _ => None,
        };
        let Some(t) = target else { return };
        let name = match t.kind() {
            "identifier" => Some(&src[t.byte_range()]),
            "field_access" => t.child_by_field_name("field").map(|f| &src[f.byte_range()]),
            _ => None,
        };
        if let Some(name) = name {
            assigned.push(name.to_string());
        }
    });
    FileFacts {
        path: path.to_path_buf(),
        ctx,
        classes,
        assigned,
    }
}

fn fields_of(decl: Node<'_>, src: &str) -> HashMap<String, FieldFacts> {
    let mut out: HashMap<String, FieldFacts> = HashMap::new();
    let interface = decl.kind() == "interface_declaration";
    let Some(body) = decl.child_by_field_name("body") else {
        return out;
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
        if m.kind() == "enum_constant" {
            if let Some(n) = m.child_by_field_name("name") {
                insert_field(
                    &mut out,
                    src[n.byte_range()].to_string(),
                    FieldFacts {
                        constant: true,
                        value_type: true,
                        enum_constant: true,
                        init: None,
                    },
                );
            }
            continue;
        }
        if !matches!(m.kind(), "field_declaration" | "constant_declaration") {
            continue;
        }
        let mods = m
            .children(&mut m.walk())
            .find(|x| x.kind() == "modifiers")
            .map_or("", |x| &src[x.byte_range()]);
        let words: Vec<&str> = mods.split_whitespace().collect();
        let constant = interface || (words.contains(&"static") && words.contains(&"final"));
        let value_type = m
            .child_by_field_name("type")
            .is_some_and(|t| is_value_type(&src[t.byte_range()]));
        let mut c3 = m.walk();
        for d in m.children_by_field_name("declarator", &mut c3) {
            let Some(n) = d.child_by_field_name("name") else {
                continue;
            };
            // `int A[] = ...` declares an array whatever the base type says.
            let dims = d.child_by_field_name("dimensions").is_some();
            insert_field(
                &mut out,
                src[n.byte_range()].to_string(),
                FieldFacts {
                    constant,
                    value_type: value_type && !dims,
                    enum_constant: false,
                    init: d
                        .child_by_field_name("value")
                        .map(|v| (v.start_byte(), v.end_byte())),
                },
            );
        }
    }
    out
}

/// A second field of one name makes the name unknowable.
fn insert_field(out: &mut HashMap<String, FieldFacts>, name: String, f: FieldFacts) {
    use std::collections::hash_map::Entry;
    match out.entry(name) {
        Entry::Vacant(v) => {
            v.insert(f);
        }
        Entry::Occupied(mut o) => {
            o.insert(FieldFacts {
                constant: false,
                value_type: false,
                enum_constant: false,
                init: None,
            });
        }
    }
}

fn walk<'t>(node: Node<'t>, f: &mut impl FnMut(Node<'t>)) {
    f(node);
    let mut c = node.walk();
    for child in node.children(&mut c) {
        walk(child, f);
    }
}
