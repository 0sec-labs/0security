//! Call resolution for Java and Kotlin: which symbols of the tree a call can reach.
//!
//! A call is joined to the methods of its name. The join is narrowed by the receiver's type: the
//! declared type of a variable or field, or a type computed through chains, `this` and field-of-field
//! paths and generics ([`super::types::TypeTable::eval`]). A call on an interface or abstract type
//! goes to the implementors present in the tree, and an injected interface field to the single
//! implementor, the `@Qualifier` one, the `@Primary` one or the bean named like the field. A name that
//! is still ambiguous is ranked by proximity (same file, same package, imported class, same module
//! directory) before the call is given up, and the calls given up are counted in `droppedCalls`.

use super::types::{cached, FileScope, TypeRef, TypeTable};
use super::{class_of, GraphCall, GraphSymbol};
use serde::Serialize;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

/// A name still shared by more than this many methods after narrowing and ranking is not followed.
pub(super) const MAX_NAME_DEFS: usize = 25;

#[derive(Debug, Serialize, Default, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CallStats {
    /// Calls seen in Java and Kotlin files, before any were dropped.
    pub jvm_calls: usize,
    /// Calls whose method is defined nowhere in the tree (JDK and library calls).
    pub external: usize,
    /// Calls that join exactly one symbol.
    pub resolved: usize,
    /// Calls kept with several candidate symbols.
    pub ambiguous: usize,
    /// Calls kept because ranking by receiver, imports and package singled out candidates.
    pub ranked: usize,
}

#[derive(Default)]
struct NameEntry {
    all: Vec<u32>,
    by_class: HashMap<String, Vec<u32>>,
}

pub(super) struct SymIndex {
    by_name: HashMap<String, NameEntry>,
}

impl SymIndex {
    pub fn new(symbols: &[GraphSymbol], jvm_only: bool) -> Self {
        let mut by_name: HashMap<String, NameEntry> = HashMap::new();
        for (i, s) in symbols.iter().enumerate() {
            if !(s.kind == "function" || s.kind == "method") {
                continue;
            }
            if jvm_only && s.language != "java" && s.language != "kotlin" {
                continue;
            }
            let e = by_name.entry(s.name.clone()).or_default();
            e.all.push(i as u32);
            e.by_class
                .entry(class_of(&s.qualified).to_string())
                .or_default()
                .push(i as u32);
        }
        SymIndex { by_name }
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

/// The old rule: an exact class match wins, then a class whose name starts or ends with the type
/// (`UserService` and `UserServiceImpl`), then every method of the name.
fn narrow_by_name<'a>(e: &'a NameEntry, ty: Option<&str>) -> Cow<'a, [u32]> {
    let Some(t) = ty else {
        return Cow::Borrowed(&e.all);
    };
    if let Some(exact) = e.by_class.get(t) {
        return Cow::Borrowed(exact);
    }
    if t.len() >= 4 {
        let fuzzy: Vec<u32> = e
            .by_class
            .iter()
            .filter(|(c, _)| c.starts_with(t) || c.ends_with(t))
            .flat_map(|(_, v)| v.iter().copied())
            .collect();
        if !fuzzy.is_empty() {
            return Cow::Owned(fuzzy);
        }
    }
    Cow::Borrowed(&e.all)
}

fn dir_of(file: &str) -> &str {
    file.rsplit_once('/').map(|(d, _)| d).unwrap_or("")
}

fn common_dirs(a: &str, b: &str) -> usize {
    a.split('/')
        .zip(b.split('/'))
        .take_while(|(x, y)| x == y)
        .count()
}

/// The imports of the calling file, split once per ranking.
struct Imports<'a> {
    /// Last two segments of every import: the class (or the class of a static import).
    simple: HashSet<&'a str>,
    wild_pkgs: HashSet<&'a str>,
}

impl<'a> Imports<'a> {
    fn of(scope: &'a FileScope) -> Self {
        let mut simple = HashSet::new();
        let mut wild_pkgs = HashSet::new();
        for i in &scope.imports {
            let base = match i.strip_suffix(".*") {
                Some(p) => {
                    wild_pkgs.insert(p);
                    p
                }
                None => i.as_str(),
            };
            let mut segs = base.rsplit('.');
            simple.extend(segs.next());
            simple.extend(segs.next());
        }
        Imports { simple, wild_pkgs }
    }
}

/// Proximity of a candidate to the calling file: same file, same package, imported class,
/// wildcard-imported package, then shared directory depth.
fn score(
    sym: &GraphSymbol,
    call_file: &str,
    scope: &FileScope,
    imports: &Imports,
    table: &TypeTable,
) -> usize {
    if sym.file == call_file {
        return 1000;
    }
    let mut s = 0;
    let sym_pkg = table
        .scopes
        .get(&sym.file)
        .map(|sc| sc.package.as_str())
        .unwrap_or("");
    let same_pkg = if scope.package.is_empty() && sym_pkg.is_empty() {
        dir_of(&sym.file) == dir_of(call_file)
    } else {
        scope.package == sym_pkg
    };
    if same_pkg {
        s += 300;
    }
    let top = sym.qualified.split('.').next().unwrap_or("");
    if !top.is_empty() && imports.simple.contains(top) {
        s += 250;
    }
    if !sym_pkg.is_empty() && imports.wild_pkgs.contains(sym_pkg) {
        s += 150;
    }
    s + common_dirs(&sym.file, call_file).min(20)
}

/// Keep the best-scoring candidates when they single some out; `None` when ranking does not help.
fn rank(
    cands: &[u32],
    symbols: &[GraphSymbol],
    call_file: &str,
    table: &TypeTable,
) -> Option<Vec<u32>> {
    let empty = FileScope::default();
    let scope = table.scopes.get(call_file).unwrap_or(&empty);
    let imports = Imports::of(scope);
    let mut best = 0usize;
    let mut top: Vec<u32> = Vec::new();
    for &c in cands {
        let sc = score(&symbols[c as usize], call_file, scope, &imports, table);
        if sc > best {
            best = sc;
            top.clear();
        }
        if sc == best {
            top.push(c);
        }
    }
    // Directory depth alone is a weak signal: it must come with a package, import or file match.
    (best >= 150 && top.len() <= MAX_NAME_DEFS && top.len() < cands.len()).then_some(top)
}

pub(super) struct Verdict {
    pub keep: bool,
    pub cand: Option<Box<[u32]>>,
    pub receiver_type: Option<String>,
    pub kind: Kind,
}

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Kind {
    NotJvm,
    External,
    Resolved,
    Ambiguous,
    Ranked,
    Dropped,
}

pub(super) struct Resolver<'a> {
    pub symbols: &'a [GraphSymbol],
    pub index: &'a SymIndex,
    pub table: &'a TypeTable,
    /// Ranking results by (name, receiver type, file), shared by all threads.
    pub rank_cache: RwLock<HashMap<String, Option<Arc<Vec<u32>>>>>,
}

impl<'a> Resolver<'a> {
    pub fn decide(&self, c: &GraphCall) -> Verdict {
        if !(c.file.ends_with(".java") || c.file.ends_with(".kt") || c.file.ends_with(".kts")) {
            return Verdict {
                keep: true,
                cand: None,
                receiver_type: None,
                kind: Kind::NotJvm,
            };
        }
        let always = c.sink.is_some() || c.auth;
        let hint = c.recv.as_ref().and_then(|p| p.hint.as_ref());
        let ty: Option<TypeRef> = match &c.recv {
            Some(p) => self.table.eval(p),
            None => c.receiver_type.as_ref().map(|n| TypeRef::named(n)),
        };
        let Some(entry) = self.index.by_name.get(c.name.as_str()) else {
            return Verdict {
                keep: always,
                cand: Some(Box::new([])),
                receiver_type: ty.map(|t| t.name),
                kind: Kind::External,
            };
        };
        let mut receiver_type = ty.as_ref().map(|t| t.name.clone());
        let mut cands: Cow<[u32]> = match &ty {
            None => Cow::Borrowed(&entry.all),
            Some(t) => match self.table.dispatch(t, &c.name, hint) {
                Some(names) if names.is_empty() => Cow::Owned(vec![]),
                Some(names) => {
                    let found: Vec<u32> = names
                        .iter()
                        .filter_map(|n| entry.by_class.get(n.as_str()))
                        .flatten()
                        .copied()
                        .collect();
                    if found.is_empty() {
                        narrow_by_name(entry, Some(&t.name))
                    } else {
                        if names.len() == 1 {
                            receiver_type = Some(names[0].clone());
                        }
                        Cow::Owned(found)
                    }
                }
                None => narrow_by_name(entry, Some(&t.name)),
            },
        };
        let mut ranked = false;
        if cands.len() > MAX_NAME_DEFS {
            let key = format!(
                "{}\0{}\0{}",
                c.name,
                receiver_type.as_deref().unwrap_or(""),
                c.file
            );
            let hit = cached(&self.rank_cache, &key, || {
                rank(&cands, self.symbols, &c.file, self.table).map(Arc::new)
            });
            if let Some(top) = hit {
                cands = Cow::Owned(top.as_ref().clone());
                ranked = true;
            }
        }
        let n = cands.len();
        if n == 0 {
            return Verdict {
                keep: always,
                cand: Some(Box::new([])),
                receiver_type,
                kind: Kind::External,
            };
        }
        if n > MAX_NAME_DEFS {
            return Verdict {
                keep: always,
                cand: Some(Box::new([])),
                receiver_type,
                kind: Kind::Dropped,
            };
        }
        Verdict {
            keep: true,
            cand: Some(cands.into_owned().into_boxed_slice()),
            receiver_type,
            kind: if ranked {
                Kind::Ranked
            } else if n == 1 {
                Kind::Resolved
            } else {
                Kind::Ambiguous
            },
        }
    }
}
