//! Security rules outside annotations, mapped onto routes (`graph::security`).

use super::*;

pub(super) fn graph_of(files: &[(&str, &str)]) -> CodeGraph {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "fg-graph-ext-{}-{}",
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

pub(super) fn route<'a>(g: &'a CodeGraph, method: &str, path: &str) -> &'a GraphRoute {
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

const CONTROLLER: &str = r#"package a;
@RestController
public class Api {
    @GetMapping("/css/site.css") String css() { return ""; }
    @GetMapping("/login") String login() { return ""; }
    @PostMapping("/mail") void mailIn() {}
    @GetMapping("/mail") String mailOut() { return ""; }
    @GetMapping("/service/admin/users") String admin() { return ""; }
    @GetMapping("/users/{id}") String user() { return ""; }
    @DeleteMapping("/users/{id}") void del() { jdbc.execute("x"); }
}
"#;

const CONFIG: &str = r#"package a;
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(auth ->
            auth.requestMatchers("/css/**", "/login").permitAll()
                .requestMatchers(HttpMethod.POST, "/mail").permitAll()
                .requestMatchers("/service/admin/**").hasAuthority("ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/users/**").hasRole("OPS")
                .anyRequest().authenticated()).build();
    }
}
"#;

#[test]
fn spring_security_url_rules_give_signals_and_public_routes() {
    let g = graph_of(&[("Api.java", CONTROLLER), ("SecurityConfig.java", CONFIG)]);
    let css = route(&g, "GET", "/css/site.css");
    assert!(css.public);
    assert!(css.auth_signals.is_empty());
    assert_eq!(css.auth_sources[0].access, "public");
    assert!(css.auth_sources[0].source.contains("SecurityConfig.java:8"));
    assert!(route(&g, "GET", "/login").public);
    // The method-specific rule opens POST /mail only; GET /mail falls to anyRequest.
    assert!(route(&g, "POST", "/mail").public);
    let mail = route(&g, "GET", "/mail");
    assert!(!mail.public);
    assert_eq!(mail.auth_signals, vec!["url-rule:authenticated"]);
    let admin = route(&g, "GET", "/service/admin/users");
    assert_eq!(admin.auth_signals, vec!["url-rule:hasAuthority(ADMIN)"]);
    assert_eq!(admin.auth_sources[0].access, "role");
    assert!(admin.auth_sources[0].source.contains("requestMatchers"));
    assert_eq!(
        route(&g, "DELETE", "/users/{id}").auth_signals,
        vec!["url-rule:hasRole(OPS)"]
    );
    // GET /users/{id}: no earlier rule matches it, so anyRequest does.
    assert_eq!(
        route(&g, "GET", "/users/{id}").auth_signals,
        vec!["url-rule:authenticated"]
    );
}

#[test]
fn missing_guard_uses_url_rules_and_keeps_open_routes_flagged_as_public() {
    let mut g = graph_of(&[("Api.java", CONTROLLER), ("SecurityConfig.java", CONFIG)]);
    mark_missing_guards(&mut g);
    // Guarded by hasRole through the URL rule: no longer a false positive.
    assert_eq!(
        route(&g, "DELETE", "/users/{id}").missing_guard,
        Some(false)
    );

    let mut open = graph_of(&[
        (
            "Api.java",
            "@RestController class Api { @GetMapping(\"/open/{x}\") void run(String x) { Runtime.getRuntime().exec(x); } }",
        ),
        (
            "Cfg.java",
            "class Cfg { SecurityFilterChain c(HttpSecurity h) { return h.authorizeHttpRequests(a -> a.requestMatchers(\"/open/**\").permitAll().anyRequest().authenticated()).build(); } }",
        ),
    ]);
    mark_missing_guards(&mut open);
    let r = route(&open, "GET", "/open/{x}");
    assert!(r.public, "explicit permitAll is reported as public");
    assert_eq!(
        r.missing_guard,
        Some(true),
        "still reaches a sink with no check"
    );
}

#[test]
fn legacy_ant_matchers_order_and_string_constants() {
    let g = graph_of(&[
        (
            "Urls.java",
            "public final class Urls { public static final String[] OPEN = {\"/health\", \"/docs/**\"}; public static final String ADMIN = \"/admin/**\"; }",
        ),
        (
            "Api.java",
            r#"@RestController class Api {
    @GetMapping("/health") String h() { return ""; }
    @GetMapping("/docs/a") String d() { return ""; }
    @GetMapping("/admin/x") String a() { return ""; }
    @GetMapping("/other") String o() { return ""; }
}"#,
        ),
        (
            "Cfg.java",
            r#"class Cfg extends WebSecurityConfigurerAdapter {
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers(Urls.OPEN).permitAll()
            .antMatchers(Urls.ADMIN).access("hasRole('ADMIN')")
            .anyRequest().fullyAuthenticated();
    }
}"#,
        ),
    ]);
    assert!(route(&g, "GET", "/health").public);
    assert!(route(&g, "GET", "/docs/a").public);
    assert_eq!(
        route(&g, "GET", "/admin/x").auth_signals,
        vec!["url-rule:access(hasRole(ADMIN))"]
    );
    assert_eq!(
        route(&g, "GET", "/other").auth_signals,
        vec!["url-rule:authenticated"]
    );
}

#[test]
fn rule_order_matters_and_an_early_deny_wins() {
    let g = graph_of(&[
        (
            "Api.java",
            "@RestController class Api { @GetMapping(\"/a/b\") String x() { return \"\"; } }",
        ),
        (
            "Cfg.java",
            "class Cfg { void c(HttpSecurity h) throws Exception { h.authorizeHttpRequests(a -> a.requestMatchers(\"/a/**\").denyAll().requestMatchers(\"/a/b\").permitAll()); } }",
        ),
    ]);
    let r = route(&g, "GET", "/a/b");
    assert!(!r.public);
    assert_eq!(r.auth_signals, vec!["url-rule:denyAll"]);
}

#[test]
fn web_ignoring_and_security_matcher_scopes() {
    let g = graph_of(&[
        (
            "Api.java",
            r#"@RestController class Api {
    @GetMapping("/static/x") String s() { return ""; }
    @GetMapping("/api/v1/n") String n() { return ""; }
    @GetMapping("/internal/m") String m() { return ""; }
}"#,
        ),
        (
            "Cfg.java",
            r#"class Cfg {
    WebSecurityCustomizer ignore() { return web -> web.ignoring().requestMatchers("/static/**"); }
    SecurityFilterChain api(HttpSecurity h) throws Exception {
        return h.securityMatcher("/api/**").authorizeHttpRequests(a -> a.anyRequest().hasRole("API")).build();
    }
    SecurityFilterChain rest(HttpSecurity h) throws Exception {
        return h.authorizeHttpRequests(a -> a.anyRequest().authenticated()).build();
    }
}"#,
        ),
    ]);
    assert!(route(&g, "GET", "/static/x").public);
    assert_eq!(
        route(&g, "GET", "/api/v1/n").auth_signals,
        vec!["url-rule:hasRole(API)"]
    );
    assert_eq!(
        route(&g, "GET", "/internal/m").auth_signals,
        vec!["url-rule:authenticated"]
    );
}

#[test]
fn unresolved_matchers_and_inert_method_security_are_reported_in_notes() {
    let g = graph_of(&[
        (
            "Api.java",
            "@RestController class Api { @PreAuthorize(\"hasRole('A')\") @GetMapping(\"/a\") String a() { return \"\"; } @GetMapping(\"/b\") String b() { return \"\"; } }",
        ),
        (
            "Cfg.java",
            "class Cfg { void c(HttpSecurity h) throws Exception { h.authorizeHttpRequests(a -> a.requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll().requestMatchers(Missing.URLS).permitAll()); } }",
        ),
    ]);
    assert!(
        g.notes.iter().any(|n| n.contains("PathRequest")),
        "{:?}",
        g.notes
    );
    assert!(
        g.notes.iter().any(|n| n.contains("not string literals")),
        "{:?}",
        g.notes
    );
    assert!(g.notes.iter().any(|n| n.starts_with("method-security:")));
    assert!(!route(&g, "GET", "/b").public);

    let enabled = graph_of(&[
        (
            "Api.java",
            "@RestController class Api { @PreAuthorize(\"hasRole('A')\") @GetMapping(\"/a\") String a() { return \"\"; } }",
        ),
        ("M.java", "@EnableMethodSecurity @Configuration class M {}"),
    ]);
    assert!(!enabled
        .notes
        .iter()
        .any(|n| n.starts_with("method-security:")));
}

#[test]
fn permit_all_annotation_marks_the_route_public_and_a_guard_overrides_it() {
    let g = graph_of(&[(
        "A.java",
        r#"@RestController class A {
    @PermitAll @GetMapping("/p") String p() { return ""; }
    @PermitAll @PreAuthorize("x") @GetMapping("/q") String q() { return ""; }
}"#,
    )]);
    let p = route(&g, "GET", "/p");
    assert!(p.public);
    assert_eq!(p.auth_sources[0].signal, "@PermitAll");
    assert!(!route(&g, "GET", "/q").public);
}

#[test]
fn web_xml_constraints_servlet_mappings_and_filters() {
    let g = graph_of(&[
        (
            "src/Admin.java",
            "public class Admin extends HttpServlet { protected void doGet(HttpServletRequest q, HttpServletResponse s) { new java.io.File(q.getParameter(\"f\")); } }",
        ),
        (
            "src/Pub.java",
            "public class Pub extends HttpServlet { protected void doGet(HttpServletRequest q, HttpServletResponse s) {} }",
        ),
        (
            "src/Plain.java",
            "public class Plain extends HttpServlet { protected void doGet(HttpServletRequest q, HttpServletResponse s) {} }",
        ),
        (
            "web/WEB-INF/web.xml",
            r#"<web-app>
  <servlet><servlet-name>admin</servlet-name><servlet-class>com.x.Admin</servlet-class></servlet>
  <servlet-mapping><servlet-name>admin</servlet-name><url-pattern>/admin/panel</url-pattern></servlet-mapping>
  <servlet><servlet-name>pub</servlet-name><servlet-class>com.x.Pub</servlet-class></servlet>
  <servlet-mapping><servlet-name>pub</servlet-name><url-pattern>/open/hello</url-pattern></servlet-mapping>
  <servlet><servlet-name>plain</servlet-name><servlet-class>com.x.Plain</servlet-class></servlet>
  <servlet-mapping><servlet-name>plain</servlet-name><url-pattern>/plain</url-pattern></servlet-mapping>
  <security-constraint>
    <web-resource-collection><web-resource-name>a</web-resource-name><url-pattern>/admin/*</url-pattern></web-resource-collection>
    <auth-constraint><role-name>manager</role-name></auth-constraint>
  </security-constraint>
  <security-constraint>
    <web-resource-collection><url-pattern>/open/*</url-pattern></web-resource-collection>
  </security-constraint>
</web-app>"#,
        ),
    ]);
    let mut g = g;
    mark_missing_guards(&mut g);
    let admin = route(&g, "GET", "/admin/panel");
    assert_eq!(admin.auth_signals, vec!["web.xml:auth-constraint(manager)"]);
    assert!(admin.auth_sources[0].source.contains("web.xml:"));
    assert_eq!(
        admin.missing_guard,
        Some(false),
        "servlet container enforces the constraint"
    );
    let open = route(&g, "GET", "/open/hello");
    assert!(open.public);
    let plain = route(&g, "GET", "/plain");
    assert!(plain.auth_signals.is_empty() && !plain.public);
    assert!(g.routes.iter().all(|r| !r.path.starts_with("/{servlet:")));
    assert_eq!(
        g.unsupported.get("xml"),
        None,
        "web.xml is read, not skipped"
    );
}

#[test]
fn web_filters_and_spring_filter_chain_filters_count_when_they_check_auth() {
    let g = graph_of(&[
        (
            "Api.java",
            r#"@RestController class Api {
    @GetMapping("/secure/x") String s() { return ""; }
    @GetMapping("/public/y") String p() { return ""; }
    @GetMapping("/logged/z") String l() { return ""; }
}"#,
        ),
        (
            "TokenFilter.java",
            "@WebFilter(urlPatterns = \"/secure/*\") public class TokenFilter implements Filter { public void doFilter(ServletRequest q, ServletResponse r, FilterChain c) { if (q.getHeader(\"X\") == null) { ((HttpServletResponse) r).sendError(401); } } }",
        ),
        (
            "LogFilter.java",
            "@WebFilter(\"/logged/*\") public class LogFilter implements Filter { public void doFilter(ServletRequest q, ServletResponse r, FilterChain c) { c.doFilter(q, r); } }",
        ),
    ]);
    assert_eq!(
        route(&g, "GET", "/secure/x").auth_signals,
        vec!["filter:TokenFilter"]
    );
    assert!(route(&g, "GET", "/logged/z").auth_signals.is_empty());
    assert!(route(&g, "GET", "/public/y").auth_signals.is_empty());

    let chain = graph_of(&[
        (
            "Api.java",
            "@RestController class Api { @GetMapping(\"/x\") String s() { return \"\"; } }",
        ),
        (
            "Cfg.java",
            "class Cfg { SecurityFilterChain c(HttpSecurity h) throws Exception { h.addFilterBefore(new JwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class); return h.build(); } }",
        ),
    ]);
    assert_eq!(
        route(&chain, "GET", "/x").auth_signals,
        vec!["filter:JwtAuthenticationFilter"]
    );
}

#[test]
fn several_applications_each_use_their_own_chain() {
    let g = graph_of(&[
        (
            "a/App1Api.java",
            "@RestController class App1Api { @GetMapping(\"/files\") String f() { return \"\"; } }",
        ),
        (
            "a/App1Security.java",
            "class S1 { void c(HttpSecurity h) throws Exception { h.authorizeHttpRequests(a -> a.anyRequest().authenticated()); } }",
        ),
        (
            "b/App2Api.java",
            "@RestController class App2Api { @GetMapping(\"/files2\") String f() { return \"\"; } }",
        ),
        (
            "b/App2Security.java",
            "class S2 { void c(HttpSecurity h) throws Exception { h.authorizeHttpRequests(a -> a.anyRequest().permitAll()); } }",
        ),
    ]);
    assert_eq!(
        route(&g, "GET", "/files").auth_signals,
        vec!["url-rule:authenticated"]
    );
    assert!(route(&g, "GET", "/files2").public);
}
