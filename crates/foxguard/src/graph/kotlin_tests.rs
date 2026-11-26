//! Kotlin: functions, calls with receiver types, Spring annotations, Ktor routing and auth signals.

use super::security_tests::{graph_of, route};
use super::*;

fn targets(g: &CodeGraph, from_method: &str, text: &str) -> Vec<String> {
    let from = g
        .symbols
        .iter()
        .find(|s| s.qualified == from_method)
        .unwrap_or_else(|| panic!("no symbol {from_method}"));
    let c = g
        .calls
        .iter()
        .find(|c| c.from == from.id && c.text == text)
        .unwrap_or_else(|| panic!("no call {text} in {from_method}"));
    let mut v: Vec<String> = c
        .cand
        .as_ref()
        .map(|cand| cand.iter().map(|&i| g.symbols[i as usize].qualified.clone()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

const SPRING: &str = r#"package com.x

import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api")
class UserApi(private val repo: UserRepository, @Qualifier("sms") private val notifier: Notifier) {
    @Autowired lateinit var svc: Service

    @GetMapping("/users/{id}")
    @PreAuthorize("hasRole('USER') and #id > (1)")
    fun one(@PathVariable id: Long): User = repo.find(id)

    @RequestMapping(value = ["/users", "/people"], method = [RequestMethod.POST, RequestMethod.PUT])
    fun write(@RequestBody u: User) { repo.save(u); svc.touch(u) }

    @DeleteMapping("/users/{id}")
    @PermitAll
    fun wipe(@PathVariable id: Long) { repo.deleteById(id) }

    @GetMapping("/export")
    fun export() { notifier.send(svc.name()) ; Runtime.getRuntime().exec("ls") }
}

class UserRepository { fun find(id: Long): User = TODO(); fun save(u: User) {} fun deleteById(id: Long) {} }
class Other { fun save(u: User) {} }
interface Notifier { fun send(m: String) }
@Service("sms") class SmsNotifier : Notifier { override fun send(m: String) {} }
@Service class MailNotifier : Notifier { override fun send(m: String) {} }
class Service { fun touch(u: User) {}; fun name(): String = "" }
class User
"#;

#[test]
fn kotlin_spring_controller_routes_symbols_and_guards() {
    let g = graph_of(&[("UserApi.kt", SPRING)]);
    assert_eq!(g.unsupported.get("kt"), None);
    assert!(g.symbols.iter().all(|s| s.language == "kotlin"));
    let names: Vec<&str> = g.symbols.iter().map(|s| s.qualified.as_str()).collect();
    assert!(names.contains(&"UserApi.one") && names.contains(&"UserApi.write"));
    let one = route(&g, "GET", "/api/users/{id}");
    assert_eq!(one.framework, "spring");
    assert_eq!(one.auth_signals, vec!["PreAuthorize"]);
    route(&g, "POST", "/api/users");
    route(&g, "PUT", "/api/people");
    let wipe = route(&g, "DELETE", "/api/users/{id}");
    assert!(wipe.public);
    assert!(wipe.auth_sources.iter().any(|a| a.signal == "@PermitAll"));
}

#[test]
fn kotlin_calls_use_constructor_properties_and_wiring() {
    let g = graph_of(&[("UserApi.kt", SPRING)]);
    // `repo` is a constructor property of type UserRepository: not Other.save.
    assert_eq!(targets(&g, "UserApi.write", "repo.save"), vec!["UserRepository.save"]);
    // `@Qualifier("sms")` on a constructor property picks the bean.
    assert_eq!(targets(&g, "UserApi.export", "notifier.send"), vec!["SmsNotifier.send"]);
    assert!(g.calls.iter().any(|c| c.text == "Runtime.getRuntime().exec"
        && c.sink.as_ref().map(|s| s.category) == Some("command")));
}

#[test]
fn kotlin_missing_guard_flags_the_unguarded_export() {
    let mut g = graph_of(&[("UserApi.kt", SPRING)]);
    mark_missing_guards(&mut g);
    assert_eq!(route(&g, "GET", "/api/export").missing_guard, Some(true));
    assert_eq!(route(&g, "GET", "/api/users/{id}").missing_guard, Some(false));
}

const KTOR: &str = r#"package com.x

fun Application.module() {
    routing {
        get("/health") { call.respondText("ok") }
        authenticate("auth-jwt") {
            get("/me") { val u = call.principal<JWTPrincipal>(); call.respondText(load(u)) }
            route("/items") {
                post { Runtime.getRuntime().exec(call.receive<String>()) }
                get("/{id}") { call.respond(find(call.parameters["id"])) }
            }
        }
    }
}

fun Route.admin() {
    delete("/admin/{id}") { Files.delete(Path.of("x")) }
}
"#;

#[test]
fn ktor_routes_prefixes_and_authenticate_wrappers() {
    let mut g = graph_of(&[("App.kt", KTOR)]);
    mark_missing_guards(&mut g);
    let health = route(&g, "GET", "/health");
    assert_eq!(health.framework, "ktor");
    assert!(health.auth_signals.is_empty());
    let me = route(&g, "GET", "/me");
    assert_eq!(me.auth_signals, vec!["authenticate(auth-jwt)"]);
    assert_eq!(me.auth_sources[0].access, "authenticated");
    let post = route(&g, "POST", "/items");
    assert_eq!(post.auth_signals, vec!["authenticate(auth-jwt)"]);
    assert_eq!(post.missing_guard, Some(false), "the authenticate block guards it");
    route(&g, "GET", "/items/{id}");
    // A handler is a symbol and owns the calls in its lambda.
    let handler = g
        .symbols
        .iter()
        .find(|s| s.qualified == "<POST /items>")
        .expect("handler symbol");
    assert_eq!(handler.kind, "route-handler");
    assert!(g
        .calls
        .iter()
        .any(|c| c.from == handler.id && c.sink.as_ref().map(|s| s.category) == Some("command")));
    // `Route.admin()` extension functions are routing context too, and this one is unguarded.
    let del = route(&g, "DELETE", "/admin/{id}");
    assert_eq!(del.missing_guard, Some(true));
}

#[test]
fn kotlin_spring_security_url_rules_dsl_and_chains() {
    let g = graph_of(&[
        (
            "Api.kt",
            r#"@RestController
class Api {
    @GetMapping("/css/a.css") fun css() = ""
    @GetMapping("/admin/x") fun admin() = ""
    @GetMapping("/other") fun other() = ""
}
"#,
        ),
        (
            "Cfg.kt",
            r#"@Configuration
class Cfg {
    @Bean
    fun chain(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeHttpRequests {
                authorize("/css/**", permitAll)
                authorize("/admin/**", hasAuthority("ADMIN"))
                authorize(anyRequest, authenticated)
            }
        }
        return http.build()
    }
}
"#,
        ),
    ]);
    assert!(route(&g, "GET", "/css/a.css").public);
    assert_eq!(
        route(&g, "GET", "/admin/x").auth_signals,
        vec!["url-rule:hasAuthority(ADMIN)"]
    );
    assert_eq!(route(&g, "GET", "/other").auth_signals, vec!["url-rule:authenticated"]);

    let chain = graph_of(&[
        ("Api.kt", "@RestController class Api { @GetMapping(\"/a\") fun a() = \"\" }"),
        (
            "Cfg.kt",
            "class Cfg { fun c(h: HttpSecurity) { h.authorizeHttpRequests { it.requestMatchers(\"/a\").hasRole(\"OPS\").anyRequest().authenticated() } } }",
        ),
    ]);
    assert_eq!(route(&chain, "GET", "/a").auth_signals, vec!["url-rule:hasRole(OPS)"]);
}

#[test]
fn kotlin_chains_and_generics_resolve_types() {
    let g = graph_of(&[(
        "A.kt",
        r#"class Repo { fun save(s: String) {} }
class Other { fun save(s: String) {} }
class Service { fun repo(): Repo = Repo() }
class Holder(val service: Service, val users: List<Repo>)
class Use(private val holder: Holder, private val maybe: Optional<Repo>) {
    fun a() { holder.service.repo().save("x") }
    fun b() { holder.users.get(0).save("x") }
    fun c() { maybe.get().save("x") }
    fun d() { val r = holder.service.repo(); r.save("x") }
    fun e() { Repo().also { it.save("x") }.save("y") }
}
"#,
    )]);
    for m in ["Use.a", "Use.b", "Use.c", "Use.d"] {
        let text = match m {
            "Use.a" => "holder.service.repo().save",
            "Use.b" => "holder.users.get().save",
            "Use.c" => "maybe.get().save",
            _ => "r.save",
        };
        assert_eq!(targets(&g, m, text), vec!["Repo.save"], "{m}");
    }
}
