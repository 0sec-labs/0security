//! `foxguard graph` on the Java fixture project: three Spring routes, one without an
//! authorization or ownership check. Runs the real binary, as the code-index consumer does.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/java_graph_app")
}

fn graph(extra: &[&str]) -> Value {
    let out = Command::new(env!("CARGO_BIN_EXE_foxguard"))
        .arg("graph")
        .arg(fixture())
        .args(extra)
        .output()
        .expect("run foxguard graph");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("graph is JSON")
}

#[test]
fn help_names_the_schema_version() {
    let out = Command::new(env!("CARGO_BIN_EXE_foxguard"))
        .args(["graph", "--help"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("schema version 1"));
}

#[test]
fn java_fixture_has_three_routes_and_one_missing_guard() {
    let g = graph(&["--missing-guard"]);
    assert_eq!(g["version"], 1);
    assert_eq!(g["files"], 5);
    let routes = g["routes"].as_array().unwrap();
    let mut seen: Vec<(String, bool)> = routes
        .iter()
        .map(|r| {
            (
                format!(
                    "{} {}",
                    r["method"].as_str().unwrap(),
                    r["path"].as_str().unwrap()
                ),
                r["missingGuard"].as_bool().unwrap(),
            )
        })
        .collect();
    seen.sort();
    assert_eq!(
        seen,
        vec![
            ("GET /api/notes/{id}".to_string(), false),
            ("GET /api/notes/{id}/export".to_string(), true),
            ("PUT /api/notes/{id}".to_string(), false),
        ]
    );
    let export = routes
        .iter()
        .find(|r| r["path"] == "/api/notes/{id}/export")
        .unwrap();
    assert_eq!(export["sinksReachable"], serde_json::json!(["file", "sql"]));
    assert!(g["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["qualified"] == "OwnershipChecker.assertOwner"));
}

#[test]
fn without_the_flag_routes_carry_no_verdict() {
    let g = graph(&[]);
    assert!(g["routes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r.get("missingGuard").is_none()));
    assert_eq!(g["taintSummaries"], serde_json::json!([]));
}

#[test]
fn taint_summaries_are_exported_on_request() {
    let g = graph(&["--taint-summaries"]);
    let s = g["taintSummaries"].as_array().unwrap();
    assert!(s
        .iter()
        .any(|x| x["function"] == "load" && x["language"] == "java"));
}

fn security_graph(extra: &[&str]) -> Value {
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/java_graph_security_app");
    let out = Command::new(env!("CARGO_BIN_EXE_foxguard"))
        .arg("graph")
        .arg(dir)
        .args(extra)
        .output()
        .expect("run foxguard graph");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("graph is JSON")
}

fn route<'a>(g: &'a Value, method: &str, path: &str) -> &'a Value {
    g["routes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["method"] == method && r["path"] == path)
        .unwrap_or_else(|| panic!("no route {method} {path}"))
}

#[test]
fn url_rules_and_web_xml_reach_the_routes_of_the_security_fixture() {
    let g = security_graph(&["--missing-guard"]);
    // Covered by anyRequest().authenticated() with no annotation on the method.
    let order = route(&g, "GET", "/shop/orders/{id}");
    assert_eq!(
        order["authSignals"],
        serde_json::json!(["url-rule:authenticated"])
    );
    assert_eq!(order["missingGuard"], false);
    assert!(order["authSources"][0]["source"]
        .as_str()
        .unwrap()
        .contains("SecurityConfig.java:"));
    // The method-specific rule.
    assert_eq!(
        route(&g, "DELETE", "/shop/orders/{id}")["authSignals"],
        serde_json::json!(["url-rule:hasRole(OPS)"])
    );
    // hasAuthority over a file sink: guarded, no longer a false positive.
    let export = route(&g, "GET", "/admin/export");
    assert_eq!(
        export["authSignals"],
        serde_json::json!(["url-rule:hasAuthority(ADMIN)"])
    );
    assert_eq!(export["sinksReachable"], serde_json::json!(["file"]));
    assert_eq!(export["missingGuard"], false);
    // permitAll: public, reaches SQL through the interface, and is flagged as unguarded.
    let search = route(&g, "GET", "/public/search");
    assert_eq!(search["public"], true);
    assert!(search.get("authSignals").is_none());
    assert_eq!(search["sinksReachable"], serde_json::json!(["sql"]));
    assert_eq!(search["missingGuard"], true);
    // web.xml: the servlet mapping gives the path and the security constraint the role.
    let legacy = route(&g, "GET", "/legacy/report");
    assert_eq!(legacy["framework"], "servlet");
    // The Spring chain (anyRequest) and the servlet container constraint both apply.
    assert_eq!(
        legacy["authSignals"],
        serde_json::json!(["url-rule:authenticated", "web.xml:auth-constraint(auditor)"])
    );
    assert_eq!(legacy["missingGuard"], false);
    // Kotlin: Ktor routes, `authenticate` is the signal.
    assert_eq!(route(&g, "GET", "/kt/health")["framework"], "ktor");
    assert_eq!(
        route(&g, "GET", "/kt/me")["authSignals"],
        serde_json::json!(["authenticate(jwt)"])
    );
    assert_eq!(route(&g, "GET", "/kt/me")["missingGuard"], false);
    assert_eq!(route(&g, "GET", "/kt/health")["missingGuard"], false);
    assert!(g["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["language"] == "kotlin" && s["qualified"] == "HealthChecker.status"));
}

#[test]
fn interface_calls_resolve_to_the_single_implementor_in_the_security_fixture() {
    let g = security_graph(&[]);
    let call = g["calls"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["text"] == "orders.load")
        .expect("orders.load");
    assert_eq!(call["receiverType"], "OrderServiceImpl");
    assert_eq!(g["droppedCalls"], 0);
    assert!(g["callStats"]["resolved"].as_u64().unwrap() >= 4);
    assert!(
        g.get("notes").is_none(),
        "nothing unresolved: {:?}",
        g.get("notes")
    );
}
