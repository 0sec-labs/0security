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
