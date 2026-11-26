//! Declared-type model shared by the Java and Kotlin extractors and the call resolver.
//!
//! The extractors record classes (fields, method return types, supertypes, Spring bean metadata)
//! and, for each call, the receiver as a short path (`this.service.repo().find()` is the base type
//! `Self` with steps field `service`, call `repo`). After all files are read, [`TypeTable`] walks
//! the paths through the classes of the tree to a type, and picks the concrete classes an interface
//! or abstract type can dispatch to.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct TypeRef {
    /// Simple name (`java.util.List<String>` gives `List`).
    pub name: String,
    pub args: Vec<TypeRef>,
}

impl TypeRef {
    pub fn named(name: &str) -> Self {
        TypeRef {
            name: name.to_string(),
            args: vec![],
        }
    }
}

/// Parse a Java or Kotlin type text: `a.b.Map<String, List<User>>`, `User[]`, `List<? extends T>`,
/// `Map<String, User>?`.
pub fn parse_type(text: &str) -> TypeRef {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    parse_at(&chars, &mut i)
}

fn parse_at(c: &[char], i: &mut usize) -> TypeRef {
    let mut raw = String::new();
    while *i < c.len() && !matches!(c[*i], '<' | ',' | '>') {
        raw.push(c[*i]);
        *i += 1;
    }
    let mut name = raw.trim();
    for p in ["? extends ", "? super ", "out ", "in "] {
        if let Some(r) = name.strip_prefix(p) {
            name = r.trim();
        }
    }
    let name = name
        .trim_end_matches('?')
        .trim_end_matches("[]")
        .trim_end_matches("...")
        .trim_end_matches('?')
        .trim();
    let simple = name.rsplit('.').next().unwrap_or("").trim().to_string();
    let mut args = Vec::new();
    if *i < c.len() && c[*i] == '<' {
        *i += 1;
        loop {
            let a = parse_at(c, i);
            if !a.name.is_empty() && a.name != "?" {
                args.push(a);
            }
            match c.get(*i) {
                Some(',') => *i += 1,
                Some('>') => {
                    *i += 1;
                    break;
                }
                _ => break,
            }
        }
        // `[]` or `?` after the generic part.
        while *i < c.len() && !matches!(c[*i], ',' | '>') {
            *i += 1;
        }
    }
    TypeRef { name: simple, args }
}

#[derive(Debug, Clone)]
pub enum Step {
    Field(String),
    Call(String),
}

/// A call receiver as a path from a known type.
#[derive(Debug, Clone)]
pub struct RecvPath {
    pub base: TypeRef,
    pub steps: Vec<Step>,
    /// The base is a field or parameter named so, with this `@Qualifier`/`@Resource` value, if any.
    pub hint: Option<(String, Option<String>)>,
}

#[derive(Debug, Clone)]
pub struct FieldDef {
    pub ty: TypeRef,
    pub qualifier: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ClassDef {
    pub name: String,
    pub qualified: String,
    pub package: String,
    pub file: String,
    pub interface: bool,
    pub is_abstract: bool,
    pub supers: Vec<TypeRef>,
    pub type_params: Vec<String>,
    pub fields: HashMap<String, FieldDef>,
    /// Method name -> return types of the overloads (`void` and constructors are not recorded).
    pub methods: HashMap<String, Vec<TypeRef>>,
    /// Methods with a body.
    pub bodied: HashSet<String>,
    /// Spring stereotype class (`@Component`, `@Service`, ...).
    pub component: bool,
    pub bean_name: Option<String>,
    pub primary: bool,
}

#[derive(Debug, Default, Clone)]
pub struct FileScope {
    pub package: String,
    pub imports: Vec<String>,
}

#[derive(Debug, Default)]
pub struct TypeTable {
    pub classes: Vec<ClassDef>,
    pub by_name: HashMap<String, Vec<usize>>,
    /// Super type simple name -> classes that name it directly.
    pub direct_subtypes: HashMap<String, Vec<usize>>,
    pub scopes: HashMap<String, FileScope>,
    cache: Caches,
}

/// Memo of the per-type walks: a large tree asks the same few questions about the same types
/// millions of times.
#[derive(Debug, Default)]
struct Caches {
    closure: RwLock<HashMap<String, Arc<Vec<TypeRef>>>>,
    subtypes: RwLock<HashMap<String, Arc<Vec<usize>>>>,
    dispatch: RwLock<HashMap<String, Option<Arc<Vec<String>>>>>,
    ret: RwLock<HashMap<String, Option<TypeRef>>>,
    field: RwLock<HashMap<String, Option<TypeRef>>>,
}

pub(super) fn cached<T: Clone>(
    map: &RwLock<HashMap<String, T>>,
    key: &str,
    compute: impl FnOnce() -> T,
) -> T {
    if let Ok(m) = map.read() {
        if let Some(v) = m.get(key) {
            return v.clone();
        }
    }
    let v = compute();
    if let Ok(mut m) = map.write() {
        m.insert(key.to_string(), v.clone());
    }
    v
}

fn lower_camel(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Containers whose element type is the first or last type argument.
fn builtin_return(owner: &TypeRef, method: &str) -> Option<TypeRef> {
    let first = owner.args.first();
    let last = owner.args.last();
    let name = owner.name.as_str();
    match name {
        "Optional" | "OptionalInt" | "Supplier" | "AtomicReference" | "ThreadLocal" | "Future"
        | "CompletableFuture" | "Callable" | "Mono" | "Lazy" | "Provider" | "ObjectProvider"
        | "ObjectFactory" => match method {
            "get" | "orElseThrow" | "orElse" | "orElseGet" | "join" | "block"
            | "getIfAvailable" | "getObject" | "getIfUnique" | "getNow" => first.cloned(),
            _ => None,
        },
        "List" | "ArrayList" | "LinkedList" | "Collection" | "Set" | "HashSet" | "TreeSet"
        | "SortedSet" | "Queue" | "Deque" | "ArrayDeque" | "Iterator" | "ListIterator"
        | "Stack" | "Vector" | "Iterable" | "Page" | "Slice" | "PriorityQueue" => match method {
            "get" | "getFirst" | "getLast" | "next" | "poll" | "peek" | "pop" | "first"
            | "last" | "element" | "remove" | "removeFirst" | "removeLast" | "pollFirst"
            | "pollLast" | "peekFirst" | "peekLast" | "previous" => first.cloned(),
            "iterator" | "listIterator" => Some(TypeRef {
                name: "Iterator".into(),
                args: owner.args.clone(),
            }),
            "getContent" | "subList" | "toList" => Some(TypeRef {
                name: "List".into(),
                args: owner.args.clone(),
            }),
            _ => None,
        },
        "Map" | "HashMap" | "TreeMap" | "LinkedHashMap" | "ConcurrentHashMap" | "SortedMap"
        | "NavigableMap" | "ConcurrentMap" | "MultiValueMap" => match method {
            "get" | "getOrDefault" | "remove" | "put" | "computeIfAbsent" | "putIfAbsent"
            | "merge" | "compute" | "getFirst" => last.cloned(),
            "values" => Some(TypeRef {
                name: "Collection".into(),
                args: last.cloned().into_iter().collect(),
            }),
            "keySet" => Some(TypeRef {
                name: "Set".into(),
                args: first.cloned().into_iter().collect(),
            }),
            _ => None,
        },
        "ResponseEntity" | "HttpEntity" | "RequestEntity" => match method {
            "getBody" => first.cloned(),
            _ => None,
        },
        "JpaRepository"
        | "CrudRepository"
        | "PagingAndSortingRepository"
        | "Repository"
        | "ListCrudRepository"
        | "MongoRepository"
        | "ReactiveCrudRepository"
        | "JpaSpecificationExecutor"
        | "ListPagingAndSortingRepository"
        | "QueryByExampleExecutor" => {
            let entity = first.cloned()?;
            match method {
                "findById" => Some(TypeRef {
                    name: "Optional".into(),
                    args: vec![entity],
                }),
                "getById" | "getReferenceById" | "getOne" | "save" | "saveAndFlush" => Some(entity),
                "findAll" | "saveAll" | "findAllById" => Some(TypeRef {
                    name: "List".into(),
                    args: vec![entity],
                }),
                _ => None,
            }
        }
        _ => None,
    }
}

impl TypeTable {
    pub fn build(classes: Vec<ClassDef>, scopes: HashMap<String, FileScope>) -> Self {
        let mut t = TypeTable {
            classes,
            scopes,
            ..Default::default()
        };
        for (i, c) in t.classes.iter().enumerate() {
            t.by_name.entry(c.name.clone()).or_default().push(i);
            for s in &c.supers {
                t.direct_subtypes.entry(s.name.clone()).or_default().push(i);
            }
        }
        t
    }

    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }

    fn classes_named(&self, name: &str) -> &[usize] {
        self.by_name.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    /// `t` and its supertypes (with type arguments substituted), breadth first, bounded.
    fn closure(&self, t: &TypeRef) -> Arc<Vec<TypeRef>> {
        if t.args.is_empty() {
            return cached(&self.cache.closure, &t.name, || self.closure_uncached(t));
        }
        self.closure_uncached(t)
    }

    fn closure_uncached(&self, t: &TypeRef) -> Arc<Vec<TypeRef>> {
        let mut out = vec![t.clone()];
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(t.name.clone());
        let mut i = 0;
        while i < out.len() && out.len() < 24 {
            let cur = out[i].clone();
            i += 1;
            for &ci in self.classes_named(&cur.name) {
                let c = &self.classes[ci];
                for s in &c.supers {
                    let sub = substitute(s, &c.type_params, &cur.args);
                    if seen.insert(sub.name.clone()) {
                        out.push(sub);
                    }
                }
            }
        }
        Arc::new(out)
    }

    fn field_type(&self, owner: &TypeRef, field: &str) -> Option<TypeRef> {
        if owner.args.is_empty() {
            let key = format!("{}\0{}", owner.name, field);
            return cached(&self.cache.field, &key, || {
                self.field_type_uncached(owner, field)
            });
        }
        self.field_type_uncached(owner, field)
    }

    fn field_type_uncached(&self, owner: &TypeRef, field: &str) -> Option<TypeRef> {
        for t in self.closure(owner).iter() {
            for &ci in self.classes_named(&t.name) {
                let c = &self.classes[ci];
                if let Some(f) = c.fields.get(field) {
                    return Some(substitute(&f.ty, &c.type_params, &t.args));
                }
            }
        }
        None
    }

    fn method_return(&self, owner: &TypeRef, method: &str) -> Option<TypeRef> {
        if owner.args.is_empty() {
            let key = format!("{}\0{}", owner.name, method);
            return cached(&self.cache.ret, &key, || {
                self.method_return_uncached(owner, method)
            });
        }
        self.method_return_uncached(owner, method)
    }

    fn method_return_uncached(&self, owner: &TypeRef, method: &str) -> Option<TypeRef> {
        for t in self.closure(owner).iter() {
            let mut found: Vec<TypeRef> = Vec::new();
            for &ci in self.classes_named(&t.name) {
                let c = &self.classes[ci];
                if let Some(rets) = c.methods.get(method) {
                    found.extend(rets.iter().map(|r| substitute(r, &c.type_params, &t.args)));
                }
            }
            if !found.is_empty() {
                // Overloads that disagree leave the type unknown.
                return found
                    .iter()
                    .all(|r| r == &found[0])
                    .then(|| found[0].clone());
            }
            if let Some(r) = builtin_return(t, method) {
                return Some(r);
            }
        }
        None
    }

    /// The type a receiver path evaluates to.
    pub fn eval(&self, p: &RecvPath) -> Option<TypeRef> {
        let mut cur = p.base.clone();
        for s in &p.steps {
            cur = match s {
                Step::Field(f) => self.field_type(&cur, f)?,
                Step::Call(m) => self.method_return(&cur, m)?,
            };
        }
        (!cur.name.is_empty()).then_some(cur)
    }

    /// Transitive subtypes of `name` present in the tree.
    fn subtypes(&self, name: &str) -> Arc<Vec<usize>> {
        cached(&self.cache.subtypes, name, || {
            Arc::new(self.subtypes_uncached(name))
        })
    }

    fn subtypes_uncached(&self, name: &str) -> Vec<usize> {
        let mut out: Vec<usize> = Vec::new();
        let mut seen: HashSet<usize> = HashSet::new();
        let mut queue: Vec<String> = vec![name.to_string()];
        let mut done: HashSet<String> = HashSet::new();
        while let Some(n) = queue.pop() {
            if !done.insert(n.clone()) || done.len() > 400 {
                continue;
            }
            for &ci in self.direct_subtypes.get(&n).into_iter().flatten() {
                if seen.insert(ci) {
                    out.push(ci);
                    queue.push(self.classes[ci].name.clone());
                }
            }
        }
        out
    }

    /// Class names (simple) whose method `method` a call on `ty` can reach, when the type model
    /// can tell: `Some(vec![])` means the receiver type is known and the tree has no such method
    /// (a library call); `None` means the model has nothing to say (unknown type).
    pub fn dispatch(
        &self,
        ty: &TypeRef,
        method: &str,
        hint: Option<&(String, Option<String>)>,
    ) -> Option<Arc<Vec<String>>> {
        let key = format!(
            "{}\0{}\0{}\0{}",
            ty.name,
            method,
            hint.map(|h| h.0.as_str()).unwrap_or(""),
            hint.and_then(|h| h.1.as_deref()).unwrap_or("")
        );
        cached(&self.cache.dispatch, &key, || {
            self.dispatch_uncached(ty, method, hint).map(Arc::new)
        })
    }

    fn dispatch_uncached(
        &self,
        ty: &TypeRef,
        method: &str,
        hint: Option<&(String, Option<String>)>,
    ) -> Option<Vec<String>> {
        let own = self.classes_named(&ty.name);
        let mut targets: Vec<usize> = Vec::new();
        let mut abstract_type = own.is_empty();
        for &ci in own {
            let c = &self.classes[ci];
            if c.interface || c.is_abstract {
                abstract_type = true;
            }
            // The class itself or the nearest supertype in the tree that has the method with a body.
            if c.bodied.contains(method) {
                targets.push(ci);
            } else {
                for s in self.closure(&TypeRef::named(&c.name)).iter().skip(1) {
                    let mut hit = false;
                    for &si in self.classes_named(&s.name) {
                        if self.classes[si].bodied.contains(method) {
                            targets.push(si);
                            hit = true;
                        }
                    }
                    if hit {
                        break;
                    }
                }
            }
        }
        // Implementors: for interfaces, abstract classes and types outside the tree (`Runnable`),
        // and for any type whose subclasses may override.
        let mut impls: Vec<usize> = self
            .subtypes(&ty.name)
            .iter()
            .copied()
            .filter(|&ci| self.classes[ci].bodied.contains(method))
            .collect();
        if abstract_type
            || own
                .iter()
                .all(|&ci| !self.classes[ci].bodied.contains(method))
        {
            impls = self.pick_bean(impls, hint);
            targets.extend(impls);
        } else if !impls.is_empty() {
            // A concrete type with overriding subclasses: the type itself, plus the overrides.
            targets.extend(impls);
        }
        if targets.is_empty() {
            // Not a class of the tree and nothing in the tree that has the method extends it: a
            // library type. A class of the tree without the method says nothing.
            return own.is_empty().then(Vec::new);
        }
        let mut names: Vec<String> = targets
            .into_iter()
            .map(|ci| self.classes[ci].name.clone())
            .collect();
        names.sort();
        names.dedup();
        Some(names)
    }

    /// Spring wiring: among several implementors of an injected interface, the `@Qualifier` one,
    /// then the `@Primary` one, then the bean whose name is the field name. Several stay several.
    fn pick_bean(&self, impls: Vec<usize>, hint: Option<&(String, Option<String>)>) -> Vec<usize> {
        let beans: Vec<usize> = impls
            .iter()
            .copied()
            .filter(|&ci| self.classes[ci].component)
            .collect();
        // Without a single stereotype class there is no bean wiring to apply.
        if beans.is_empty() {
            return impls;
        }
        let pool = beans;
        if pool.len() <= 1 {
            return pool;
        }
        let bean = |ci: usize| -> String {
            let c = &self.classes[ci];
            c.bean_name.clone().unwrap_or_else(|| lower_camel(&c.name))
        };
        if let Some((var, qualifier)) = hint {
            if let Some(q) = qualifier {
                let hit: Vec<usize> = pool.iter().copied().filter(|&ci| &bean(ci) == q).collect();
                if !hit.is_empty() {
                    return hit;
                }
            }
            let primary: Vec<usize> = pool
                .iter()
                .copied()
                .filter(|&ci| self.classes[ci].primary)
                .collect();
            if qualifier.is_none() && primary.len() == 1 {
                return primary;
            }
            let named: Vec<usize> = pool
                .iter()
                .copied()
                .filter(|&ci| &bean(ci) == var)
                .collect();
            if !named.is_empty() {
                return named;
            }
        }
        pool
    }
}

fn substitute(t: &TypeRef, params: &[String], args: &[TypeRef]) -> TypeRef {
    if let Some(i) = params.iter().position(|p| p == &t.name) {
        if let Some(a) = args.get(i) {
            return a.clone();
        }
        return TypeRef::default();
    }
    TypeRef {
        name: t.name.clone(),
        args: t.args.iter().map(|a| substitute(a, params, args)).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_generics() {
        let t = parse_type("java.util.Map<String, List<User>>");
        assert_eq!(t.name, "Map");
        assert_eq!(t.args.len(), 2);
        assert_eq!(t.args[1].name, "List");
        assert_eq!(t.args[1].args[0].name, "User");
        assert_eq!(parse_type("User[]").name, "User");
        assert_eq!(parse_type("List<? extends Base>").args[0].name, "Base");
        assert_eq!(parse_type("Optional<User>?").name, "Optional");
        assert_eq!(parse_type("Foo<Bar<Baz>, Qux>").args.len(), 2);
    }

    #[test]
    fn builtin_containers() {
        let t = parse_type("Optional<User>");
        assert_eq!(builtin_return(&t, "orElseThrow").unwrap().name, "User");
        let m = parse_type("Map<String, Account>");
        assert_eq!(builtin_return(&m, "get").unwrap().name, "Account");
    }
}
