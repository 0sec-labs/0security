//! Security configuration outside annotations, mapped onto routes.
//!
//! Spring Security URL rules (`authorizeHttpRequests` / `authorizeRequests` with `requestMatchers`,
//! `antMatchers`, `mvcMatchers`, `regexMatchers`, `anyRequest`), `securityMatcher` chain scopes,
//! `web.ignoring()`, servlet `web.xml` security constraints and filter mappings, and Jakarta
//! `@WebFilter` classes are collected per file by the Java/Kotlin extractors and joined to the routes
//! of the whole tree here. A route covered by a rule gets an auth signal and the rule that gave it
//! (`authSources`); a route an explicit `permitAll` covers is marked `public`.
//!
//! Matching is lexical and conservative: a path-variable segment (`{id}`) is covered only by a wildcard
//! or variable in the pattern, never by a literal, and rules that cannot be resolved (constants outside
//! the tree, request matcher beans) are reported through `notes`.

use super::{AuthSource, CodeGraph, GraphRoute};
use regex::Regex;
use std::collections::{HashMap, HashSet};

/// What a URL rule grants.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Access {
    Public,
    Denied,
    Authenticated,
    /// `hasRole('X')`, `hasAuthority('X')`, `access(...)`: the rendered requirement.
    Role(String),
}

#[derive(Debug, Clone)]
pub(super) enum PArg {
    Lit(String),
    /// A constant (`WHITELIST`, `Urls.PUBLIC`), resolved against the constants of the whole tree.
    Const(String),
}

#[derive(Debug, Clone)]
pub(super) struct Pm {
    pub method: Option<String>,
    pub regex: bool,
    pub arg: PArg,
}

#[derive(Debug, Clone)]
pub(super) struct UrlRule {
    pub any: bool,
    pub matchers: Vec<Pm>,
    pub access: Access,
    /// `file:line rule`, shown to the consumer.
    pub source: String,
    /// Byte offset of the matcher in its file: rules of a chain apply in source order.
    pub pos: usize,
}

#[derive(Debug, Default, Clone)]
pub(super) struct Chain {
    /// File that declares the chain.
    pub file: String,
    /// `securityMatcher(...)`: the chain only handles requests matching one of these. Empty: all.
    pub scope: Vec<Pm>,
    pub rules: Vec<UrlRule>,
    /// Filters added to the chain (`addFilterBefore(new JwtFilter(), ...)`): name and source.
    pub filters: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub(super) struct FilterDef {
    pub name: String,
    /// `@WebFilter` URL patterns; empty when the filter is mapped elsewhere (web.xml, Spring chain).
    pub patterns: Vec<String>,
    pub auth: bool,
    pub source: String,
}

#[derive(Debug, Default)]
pub(super) struct FileSecurity {
    pub chains: Vec<Chain>,
    /// `web.ignoring()` rules: requests that skip every chain.
    pub ignoring: Vec<UrlRule>,
    pub chain_index: HashMap<usize, usize>,
    pub consts: HashMap<String, Vec<String>>,
    pub filters: Vec<FilterDef>,
    /// `@EnableMethodSecurity` / `@EnableGlobalMethodSecurity` seen.
    pub method_security: bool,
    /// A route-level `@PreAuthorize` / `@Secured` seen.
    pub method_guards: bool,
}

impl FileSecurity {
    pub fn chain_mut(&mut self, key: usize, file: &str) -> &mut Chain {
        let next = self.chains.len();
        let idx = *self.chain_index.entry(key).or_insert(next);
        if idx == next {
            self.chains.push(Chain {
                file: file.to_string(),
                ..Default::default()
            });
        }
        &mut self.chains[idx]
    }

    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
            && self.ignoring.is_empty()
            && self.filters.is_empty()
            && !self.method_security
            && !self.method_guards
            && self.consts.is_empty()
    }
}

// ---------------------------------------------------------------------------------------------
// Pattern matching

fn glob(pat: &[char], s: &[char]) -> bool {
    match pat.split_first() {
        None => s.is_empty(),
        Some(('*', rest)) => (0..=s.len()).any(|i| glob(rest, &s[i..])),
        Some(('?', rest)) => !s.is_empty() && glob(rest, &s[1..]),
        Some((c, rest)) => s.first() == Some(c) && glob(rest, &s[1..]),
    }
}

fn one_segment(pat: &str, seg: &str) -> bool {
    if pat.starts_with('{') {
        return true;
    }
    if seg.starts_with('{') {
        // A path variable of the route is covered by wildcards only, not by a literal.
        return pat.chars().all(|c| c == '*');
    }
    let p: Vec<char> = pat.chars().collect();
    let s: Vec<char> = seg.chars().collect();
    glob(&p, &s)
}

fn segments_match(p: &[&str], q: &[&str]) -> bool {
    match p.split_first() {
        None => q.is_empty(),
        Some((first, rest)) if *first == "**" || first.starts_with("{*") => {
            rest.is_empty() || (0..=q.len()).any(|i| segments_match(rest, &q[i..]))
        }
        Some((first, rest)) => {
            !q.is_empty() && one_segment(first, q[0]) && segments_match(rest, &q[1..])
        }
    }
}

/// Spring `AntPathMatcher` semantics on a route path.
pub(super) fn ant_match(pattern: &str, path: &str) -> bool {
    let p: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let q: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    segments_match(&p, &q)
}

/// Servlet URL-pattern matching (`web.xml`, `@WebFilter`): the match specificity, or `None`.
/// Exact beats longest prefix beats extension beats the default servlet.
pub(super) fn servlet_match(pattern: &str, path: &str) -> Option<usize> {
    let path = if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    };
    if pattern == "/" {
        return Some(1);
    }
    if pattern == "/*" {
        return Some(2);
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return (path == prefix || path.starts_with(&format!("{prefix}/")))
            .then_some(100 + prefix.len());
    }
    if let Some(ext) = pattern.strip_prefix("*.") {
        let last = path.rsplit('/').next().unwrap_or("");
        return (!last.starts_with('{') && last.ends_with(&format!(".{ext}"))).then_some(50);
    }
    (path == pattern.trim_end_matches('/') || (pattern == "/" && path.is_empty())).then_some(1000)
}

// ---------------------------------------------------------------------------------------------
// Resolution and the join

enum Matcher {
    Ant(String),
    Regex(Regex),
}

struct Rpm {
    method: Option<String>,
    m: Matcher,
}

struct RRule {
    any: bool,
    pms: Vec<Rpm>,
    access: Access,
    source: String,
}

/// The chain that handles a route: a `securityMatcher` chain that matches it, otherwise an unscoped
/// one; among several, the one with rules whose file shares the longest directory prefix with the
/// route's file (several applications in one tree each have their own configuration).
fn pick_chain<'a>(chains: &'a [RChain], r: &GraphRoute) -> Option<&'a RChain> {
    let scoped: Vec<&RChain> = chains
        .iter()
        .filter(|c| !c.scope.is_empty() && c.scope.iter().any(|p| route_matches(p, r)))
        .collect();
    let pool: Vec<&RChain> = if scoped.is_empty() {
        chains.iter().filter(|c| c.scope.is_empty()).collect()
    } else {
        scoped
    };
    let near = |c: &RChain| -> (bool, usize) {
        let a = c.file.rsplit_once('/').map(|x| x.0).unwrap_or("");
        let b = r.file.rsplit_once('/').map(|x| x.0).unwrap_or("");
        let shared = a
            .split('/')
            .zip(b.split('/'))
            .take_while(|(x, y)| x == y)
            .count();
        (!c.rules.is_empty(), shared)
    };
    let mut best: Option<&RChain> = None;
    for c in pool {
        if best.is_none_or(|b| near(c) > near(b)) {
            best = Some(c);
        }
    }
    best
}

struct RChain {
    file: String,
    scope: Vec<Rpm>,
    rules: Vec<RRule>,
    filters: Vec<(String, String)>,
}

fn route_matches(pm: &Rpm, r: &GraphRoute) -> bool {
    if let Some(m) = &pm.method {
        if &r.method != m {
            return false;
        }
    }
    match &pm.m {
        Matcher::Ant(p) => ant_match(p, &r.path),
        Matcher::Regex(re) => {
            // A path variable is probed with a letter and a digit: a regex that accepts either covers it.
            let a = path_sample(&r.path, 'x');
            let b = path_sample(&r.path, '1');
            re.is_match(&a) || re.is_match(&b)
        }
    }
}

fn path_sample(path: &str, fill: char) -> String {
    path.split('/')
        .map(|s| {
            if s.starts_with('{') {
                fill.to_string()
            } else {
                s.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn resolve_pm(pm: &Pm, consts: &HashMap<String, Vec<String>>, unresolved: &mut usize) -> Vec<Rpm> {
    let values: Vec<String> = match &pm.arg {
        PArg::Lit(s) => vec![s.clone()],
        PArg::Const(name) => consts
            .get(name)
            .or_else(|| consts.get(name.rsplit('.').next().unwrap_or(name)))
            .cloned()
            .unwrap_or_else(|| {
                *unresolved += 1;
                vec![]
            }),
    };
    values
        .into_iter()
        .filter_map(|v| {
            let m = if pm.regex {
                Matcher::Regex(Regex::new(&format!("^(?:{})$", v)).ok()?)
            } else {
                Matcher::Ant(v)
            };
            Some(Rpm {
                method: pm.method.clone(),
                m,
            })
        })
        .collect()
}

fn signal_of(access: &Access, kind: &str) -> (String, &'static str) {
    match access {
        Access::Public => (format!("{kind}:permitAll"), "public"),
        Access::Denied => (format!("{kind}:denyAll"), "denied"),
        Access::Authenticated => (format!("{kind}:authenticated"), "authenticated"),
        Access::Role(r) => (format!("{kind}:{r}"), "role"),
    }
}

/// Servlet deployment descriptor facts relevant to routes.
#[derive(Debug, Default)]
pub(super) struct WebXml {
    pub file: String,
    pub constraints: Vec<WebConstraint>,
    /// servlet-name -> class (simple name)
    pub servlets: HashMap<String, String>,
    /// servlet-name -> url patterns
    pub servlet_maps: Vec<(String, String)>,
    pub filters: HashMap<String, String>,
    pub filter_maps: Vec<WebFilterMap>,
}

#[derive(Debug)]
pub(super) struct WebConstraint {
    pub patterns: Vec<String>,
    pub methods: Vec<String>,
    /// `None`: no `<auth-constraint>` (open). `Some(empty)`: no role is allowed.
    pub roles: Option<Vec<String>>,
    pub line: usize,
}

#[derive(Debug)]
pub(super) struct WebFilterMap {
    pub filter: String,
    pub patterns: Vec<String>,
    pub servlets: Vec<String>,
    pub line: usize,
}

fn strip_comments(text: &str) -> String {
    static C: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    // Keep newlines so line numbers stay right.
    C.get_or_init(|| Regex::new(r"(?s)<!--.*?-->").expect("static regex"))
        .replace_all(text, |c: &regex::Captures| {
            "\n".repeat(c[0].matches('\n').count())
        })
        .into_owned()
}

fn tag_values(block: &str, tag: &str) -> Vec<String> {
    let re = Regex::new(&format!(r"(?s)<{tag}\s*>\s*(.*?)\s*</{tag}\s*>")).expect("tag regex");
    re.captures_iter(block)
        .map(|c| c[1].trim().to_string())
        .collect()
}

fn blocks<'a>(text: &'a str, tag: &str) -> Vec<(usize, &'a str)> {
    let re = Regex::new(&format!(r"(?s)<{tag}(?:\s[^>]*?)?(?:/>|>(.*?)</{tag}\s*>)"))
        .expect("block regex");
    re.captures_iter(text)
        .map(|c| {
            let m = c.get(0).expect("whole match");
            let line = text[..m.start()].matches('\n').count() + 1;
            (line, c.get(1).map(|g| g.as_str()).unwrap_or(""))
        })
        .collect()
}

pub(super) fn parse_web_xml(file: &str, raw: &str) -> WebXml {
    let text = strip_comments(raw);
    let mut w = WebXml {
        file: file.to_string(),
        ..Default::default()
    };
    for (line, body) in blocks(&text, "security-constraint") {
        let mut patterns = Vec::new();
        let mut methods = Vec::new();
        for (_, rc) in blocks(body, "web-resource-collection") {
            patterns.extend(tag_values(rc, "url-pattern"));
            methods.extend(tag_values(rc, "http-method"));
        }
        let auth = blocks(body, "auth-constraint");
        let roles = auth.first().map(|(_, b)| tag_values(b, "role-name"));
        w.constraints.push(WebConstraint {
            patterns,
            methods: methods.into_iter().map(|m| m.to_uppercase()).collect(),
            roles,
            line,
        });
    }
    let simple = |c: &str| c.rsplit('.').next().unwrap_or(c).to_string();
    for (_, body) in blocks(&text, "servlet") {
        if let (Some(n), Some(c)) = (
            tag_values(body, "servlet-name").pop(),
            tag_values(body, "servlet-class").pop(),
        ) {
            w.servlets.insert(n, simple(&c));
        }
    }
    for (_, body) in blocks(&text, "servlet-mapping") {
        if let Some(n) = tag_values(body, "servlet-name").pop() {
            for p in tag_values(body, "url-pattern") {
                w.servlet_maps.push((n.clone(), p));
            }
        }
    }
    for (_, body) in blocks(&text, "filter") {
        if let (Some(n), Some(c)) = (
            tag_values(body, "filter-name").pop(),
            tag_values(body, "filter-class").pop(),
        ) {
            w.filters.insert(n, simple(&c));
        }
    }
    for (line, body) in blocks(&text, "filter-mapping") {
        if let Some(n) = tag_values(body, "filter-name").pop() {
            w.filter_maps.push(WebFilterMap {
                filter: n,
                patterns: tag_values(body, "url-pattern"),
                servlets: tag_values(body, "servlet-name"),
                line,
            });
        }
    }
    w
}

fn is_java_route(r: &GraphRoute) -> bool {
    matches!(r.framework, "spring" | "jax-rs" | "servlet")
}

/// Filter names that look like an authentication or authorization filter.
pub(super) fn auth_filter_name(name: &str) -> bool {
    static R: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)auth|jwt|token|security|login|session|acl|permission|role|principal|shiro|csrf|apikey|bearer")
            .expect("static regex")
    })
    .is_match(name)
}

fn push_hit(r: &mut GraphRoute, signal: String, source: String, access: &'static str) {
    if r.auth_sources
        .iter()
        .any(|a| a.signal == signal && a.source == source)
    {
        return;
    }
    if access != "public" && !r.auth_signals.contains(&signal) {
        r.auth_signals.push(signal.clone());
    }
    r.auth_sources.push(AuthSource {
        signal,
        source,
        access,
    });
}

/// Map the collected rules onto the routes of the graph and add the resulting notes.
pub(super) fn apply(g: &mut CodeGraph, secs: Vec<FileSecurity>, webs: Vec<WebXml>) {
    let mut consts: HashMap<String, Vec<String>> = HashMap::new();
    let mut filter_defs: HashMap<String, FilterDef> = HashMap::new();
    let mut method_security = false;
    let mut method_guards = false;
    let mut raw_chains: Vec<Chain> = Vec::new();
    let mut raw_ignoring: Vec<UrlRule> = Vec::new();
    let mut web_filter_defs: Vec<FilterDef> = Vec::new();
    for s in secs {
        for (k, v) in s.consts {
            consts.entry(k).or_insert(v);
        }
        for f in s.filters {
            if !f.patterns.is_empty() {
                web_filter_defs.push(f.clone());
            }
            filter_defs.entry(f.name.clone()).or_insert(f);
        }
        method_security |= s.method_security;
        method_guards |= s.method_guards;
        raw_ignoring.extend(s.ignoring);
        raw_chains.extend(
            s.chains
                .into_iter()
                .filter(|c| !c.rules.is_empty() || !c.filters.is_empty()),
        );
    }
    for c in &mut raw_chains {
        c.rules.sort_by_key(|r| r.pos);
    }

    if method_guards && !method_security {
        g.notes.push("method-security: routes carry @PreAuthorize/@Secured, but no @EnableMethodSecurity or @EnableGlobalMethodSecurity was found in the tree, so those annotations may not be enforced".to_string());
    }

    // Resolve chains; scoped chains are consulted first, as Spring orders matching chains.
    let mut unresolved = 0usize;
    let chains: Vec<RChain> = raw_chains
        .iter()
        .map(|c| RChain {
            scope: c
                .scope
                .iter()
                .flat_map(|p| resolve_pm(p, &consts, &mut unresolved))
                .collect(),
            rules: c
                .rules
                .iter()
                .map(|r| RRule {
                    any: r.any,
                    pms: r
                        .matchers
                        .iter()
                        .flat_map(|p| resolve_pm(p, &consts, &mut unresolved))
                        .collect(),
                    access: r.access.clone(),
                    source: r.source.clone(),
                })
                .collect(),
            filters: c.filters.clone(),
            file: c.file.clone(),
        })
        .collect();
    let ignoring: Vec<RRule> = raw_ignoring
        .iter()
        .map(|r| RRule {
            any: false,
            pms: r
                .matchers
                .iter()
                .flat_map(|p| resolve_pm(p, &consts, &mut unresolved))
                .collect(),
            access: Access::Public,
            source: r.source.clone(),
        })
        .collect();
    if unresolved > 0 {
        g.notes.push(format!("spring-security-url-rules: {unresolved} request matcher value(s) are constants that are not string literals in the tree; the routes they cover are not marked"));
    }
    let unscoped = chains
        .iter()
        .filter(|c| c.scope.is_empty() && !c.rules.is_empty())
        .count();
    if unscoped > 1 {
        g.notes.push(format!("spring-security-url-rules: {unscoped} security filter chains without a securityMatcher exist; each route takes the one declared nearest to it in the tree"));
    }

    // web.xml: expand servlets mapped there onto the routes the extractor named `/{servlet:Class}`.
    let mut by_class: HashMap<String, Vec<String>> = HashMap::new();
    for w in &webs {
        for (name, pat) in &w.servlet_maps {
            if let Some(class) = w.servlets.get(name) {
                by_class.entry(class.clone()).or_default().push(pat.clone());
            }
        }
    }
    if !by_class.is_empty() {
        let mut extra = Vec::new();
        for r in &mut g.routes {
            let Some(class) = r
                .path
                .strip_prefix("/{servlet:")
                .and_then(|p| p.strip_suffix('}'))
            else {
                continue;
            };
            let Some(pats) = by_class.get(class.rsplit('.').next().unwrap_or(class)) else {
                continue;
            };
            let mut it = pats.iter();
            let first = it.next().expect("non-empty");
            for p in it {
                let mut c = r.clone();
                c.path = p.clone();
                extra.push(c);
            }
            r.path = first.clone();
        }
        g.routes.extend(extra);
    }

    let has_rules = !chains.is_empty()
        || !ignoring.is_empty()
        || !webs.is_empty()
        || !web_filter_defs.is_empty();
    if !has_rules {
        return;
    }
    let filter_is_auth = |name: &str| -> bool {
        filter_defs
            .get(name)
            .map(|f| f.auth)
            .unwrap_or_else(|| auth_filter_name(name))
    };
    let mut web_constraint_notes: HashSet<String> = HashSet::new();
    for r in g.routes.iter_mut().filter(|r| is_java_route(r)) {
        // `web.ignoring()`: the request skips the filter chain.
        let ignored = ignoring
            .iter()
            .find(|rule| rule.pms.iter().any(|p| route_matches(p, r)));
        if let Some(rule) = ignored {
            push_hit(
                r,
                "url-rule:permitAll".to_string(),
                rule.source.clone(),
                "public",
            );
        }
        // Spring Security chain.
        if let Some(chain) = pick_chain(&chains, r).filter(|_| ignored.is_none()) {
            let rule = chain
                .rules
                .iter()
                .find(|rule| rule.any || rule.pms.iter().any(|p| route_matches(p, r)));
            if let Some(rule) = rule {
                let (signal, access) = signal_of(&rule.access, "url-rule");
                push_hit(r, signal, rule.source.clone(), access);
            }
            for (name, source) in &chain.filters {
                if filter_is_auth(name) {
                    push_hit(r, format!("filter:{name}"), source.clone(), "filter");
                }
            }
        }
        // Servlet security constraints: the most specific matching pattern decides.
        for w in &webs {
            let mut best: Option<(usize, Vec<&WebConstraint>)> = None;
            for c in &w.constraints {
                if !c.methods.is_empty() && !c.methods.contains(&r.method) {
                    continue;
                }
                let Some(score) = c
                    .patterns
                    .iter()
                    .filter_map(|p| servlet_match(p, &r.path))
                    .max()
                else {
                    continue;
                };
                match &mut best {
                    Some((s, v)) if *s == score => v.push(c),
                    Some((s, _)) if *s > score => {}
                    _ => best = Some((score, vec![c])),
                }
            }
            if let Some((_, cs)) = best {
                let guarded = cs.iter().find(|c| c.roles.is_some());
                let source_of = |c: &WebConstraint| {
                    format!(
                        "{}:{} security-constraint {}",
                        w.file,
                        c.line,
                        c.patterns.join(",")
                    )
                };
                match guarded {
                    Some(c) => {
                        let roles = c.roles.clone().unwrap_or_default();
                        let (signal, access) = if roles.is_empty() {
                            ("web.xml:auth-constraint(none)".to_string(), "denied")
                        } else if roles.iter().any(|x| x == "*" || x == "**") {
                            ("web.xml:authenticated".to_string(), "authenticated")
                        } else {
                            (
                                format!("web.xml:auth-constraint({})", roles.join(",")),
                                "role",
                            )
                        };
                        push_hit(r, signal, source_of(c), access);
                    }
                    None => push_hit(
                        r,
                        "web.xml:unrestricted".to_string(),
                        source_of(cs[0]),
                        "public",
                    ),
                }
            } else if w.constraints.iter().any(|c| !c.methods.is_empty()) {
                // Constraints that list HTTP methods leave the others open (a known web.xml pitfall).
                web_constraint_notes.insert(w.file.clone());
            }
            for fm in &w.filter_maps {
                let class = w
                    .filters
                    .get(&fm.filter)
                    .cloned()
                    .unwrap_or_else(|| fm.filter.clone());
                if !filter_is_auth(&class) && !filter_is_auth(&fm.filter) {
                    continue;
                }
                let by_url = fm
                    .patterns
                    .iter()
                    .any(|p| servlet_match(p, &r.path).is_some());
                let by_servlet = fm.servlets.iter().any(|s| {
                    w.servlet_maps
                        .iter()
                        .any(|(n, p)| n == s && servlet_match(p, &r.path).is_some())
                });
                if by_url || by_servlet {
                    push_hit(
                        r,
                        format!("filter:{class}"),
                        format!("{}:{} filter-mapping {}", w.file, fm.line, fm.filter),
                        "filter",
                    );
                }
            }
        }
        // Jakarta `@WebFilter` classes.
        for f in web_filter_defs.iter().filter(|f| f.auth) {
            if f.patterns
                .iter()
                .any(|p| servlet_match(p, &r.path).is_some())
            {
                push_hit(r, format!("filter:{}", f.name), f.source.clone(), "filter");
            }
        }
        if r.auth_signals.is_empty() && r.auth_sources.iter().any(|a| a.access == "public") {
            r.public = true;
        }
    }
    if !web_constraint_notes.is_empty() {
        g.notes.push("web-xml-security: a security-constraint lists HTTP methods; the other methods of the same URL are not restricted by it".to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ant_patterns() {
        assert!(ant_match("/api/**", "/api/users/{id}"));
        assert!(ant_match("/api/**", "/api"));
        assert!(ant_match("/api/*/x", "/api/{v}/x"));
        assert!(ant_match("/users/{id}", "/users/{uid}"));
        assert!(ant_match("/css/*.css", "/css/site.css"));
        assert!(
            !ant_match("/users/me", "/users/{id}"),
            "a literal does not cover a variable"
        );
        assert!(!ant_match("/api/*", "/api/a/b"));
        assert!(ant_match("/**", "/anything/at/all"));
        assert!(ant_match("/files/{*rest}", "/files/a/b"));
    }

    #[test]
    fn servlet_patterns() {
        assert_eq!(servlet_match("/admin/*", "/admin/x"), Some(106));
        assert_eq!(servlet_match("/admin/*", "/administrator"), None);
        assert_eq!(servlet_match("*.do", "/a/b.do"), Some(50));
        assert_eq!(servlet_match("/hello", "/hello"), Some(1000));
        assert!(servlet_match("/hello", "/{id}").is_none());
    }

    #[test]
    fn web_xml_constraints_and_filters() {
        let w = parse_web_xml(
            "web.xml",
            r#"<web-app>
<!-- <security-constraint><web-resource-collection><url-pattern>/x</url-pattern></web-resource-collection></security-constraint> -->
<servlet><servlet-name>h</servlet-name><servlet-class>com.a.Hello</servlet-class></servlet>
<servlet-mapping><servlet-name>h</servlet-name><url-pattern>/hello</url-pattern></servlet-mapping>
<security-constraint>
  <web-resource-collection><url-pattern>/admin/*</url-pattern><http-method>GET</http-method></web-resource-collection>
  <auth-constraint><role-name>admin</role-name></auth-constraint>
</security-constraint>
<security-constraint>
  <web-resource-collection><url-pattern>/open/*</url-pattern></web-resource-collection>
</security-constraint>
<filter><filter-name>f</filter-name><filter-class>com.a.AuthFilter</filter-class></filter>
<filter-mapping><filter-name>f</filter-name><url-pattern>/*</url-pattern></filter-mapping>
</web-app>"#,
        );
        assert_eq!(w.constraints.len(), 2);
        assert_eq!(w.constraints[0].roles, Some(vec!["admin".to_string()]));
        assert_eq!(w.constraints[0].methods, vec!["GET"]);
        assert_eq!(w.constraints[1].roles, None);
        assert_eq!(w.servlets.get("h").map(String::as_str), Some("Hello"));
        assert_eq!(w.filters.get("f").map(String::as_str), Some("AuthFilter"));
        assert_eq!(w.filter_maps[0].patterns, vec!["/*"]);
    }
}
