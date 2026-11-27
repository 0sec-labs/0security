//! Fixture-driven tests for the Java weak-primitive, cookie and
//! trust-boundary rules. Each rule has a vulnerable fixture whose hits are
//! counted exactly and a safe fixture that must stay silent for that rule.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Rule-id -> lines of all findings of that rule for one fixture.
fn scan(name: &str) -> std::collections::BTreeMap<String, Vec<u64>> {
    let output = Command::new(env!("CARGO_BIN_EXE_foxguard"))
        .args(["--config", "/dev/null", "-f", "json"])
        .arg(fixture(name))
        .output()
        .expect("failed to execute foxguard");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("scan output should be JSON");
    let mut by_rule: std::collections::BTreeMap<String, Vec<u64>> = Default::default();
    for f in report["findings"].as_array().expect("findings array") {
        by_rule
            .entry(f["rule_id"].as_str().unwrap_or_default().to_string())
            .or_default()
            .push(f["line"].as_u64().unwrap_or(0));
    }
    by_rule
}

fn count(findings: &std::collections::BTreeMap<String, Vec<u64>>, rule: &str) -> usize {
    findings.get(rule).map_or(0, Vec::len)
}

#[test]
fn trust_boundary_flags_request_data_stored_in_session() {
    let f = scan("vulnerable_java_trust_boundary.java");
    assert_eq!(count(&f, "java/taint-trust-boundary"), 3, "{f:?}");
}

#[test]
fn trust_boundary_ignores_constants_request_scope_and_replaced_values() {
    let f = scan("safe_java_trust_boundary.java");
    assert_eq!(count(&f, "java/taint-trust-boundary"), 0, "{f:?}");
}
