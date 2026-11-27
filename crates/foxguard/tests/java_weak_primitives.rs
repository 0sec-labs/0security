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

/// Scan a copy of a fixture placed at `relative` inside a temp project, for
/// rules whose behaviour depends on the file's location.
fn scan_findings_at(name: &str, relative: &str) -> Vec<serde_json::Value> {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let dest = dir.path().join(relative);
    std::fs::create_dir_all(dest.parent().expect("parent")).expect("create dirs");
    std::fs::copy(fixture(name), &dest).expect("copy fixture");
    let output = Command::new(env!("CARGO_BIN_EXE_foxguard"))
        .args(["--config", "/dev/null", "-f", "json"])
        .arg(dir.path())
        .output()
        .expect("failed to execute foxguard");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("scan output should be JSON");
    report["findings"]
        .as_array()
        .expect("findings array")
        .clone()
}

fn scan_at(name: &str, relative: &str) -> std::collections::BTreeMap<String, Vec<u64>> {
    let mut by_rule: std::collections::BTreeMap<String, Vec<u64>> = Default::default();
    for f in scan_findings_at(name, relative) {
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

#[test]
fn weak_hash_flags_broken_digests_including_resolved_constants() {
    let f = scan("vulnerable_java_weak_hash.java");
    assert_eq!(count(&f, "java/weak-hash"), 7, "{f:?}");
}

#[test]
fn weak_hash_ignores_strong_unknown_and_reassigned_algorithms() {
    let f = scan("safe_java_weak_hash.java");
    assert_eq!(count(&f, "java/weak-hash"), 0, "{f:?}");
}

#[test]
fn weak_cipher_flags_weak_algorithms_and_ecb() {
    let f = scan("vulnerable_java_weak_cipher.java");
    assert_eq!(count(&f, "java/no-weak-crypto"), 10, "{f:?}");
}

#[test]
fn weak_cipher_ignores_aead_rsa_placeholder_and_unknown_algorithms() {
    let f = scan("safe_java_weak_cipher.java");
    assert_eq!(count(&f, "java/no-weak-crypto"), 0, "{f:?}");
}

#[test]
fn cookie_without_secure_flag_is_flagged() {
    let f = scan("vulnerable_java_cookie.java");
    assert_eq!(count(&f, "java/cookie-missing-secure"), 4, "{f:?}");
}

#[test]
fn cookie_with_secure_flag_or_unseen_owner_is_not_flagged() {
    for name in ["safe_java_cookie.java", "safe_java_cookie_foreign.java"] {
        let f = scan(name);
        assert_eq!(count(&f, "java/cookie-missing-secure"), 0, "{name}: {f:?}");
    }
}

#[test]
fn weak_random_is_a_low_severity_hygiene_finding() {
    let f = scan_at(
        "vulnerable_java_weak_random.java",
        "src/main/java/app/Randoms.java",
    );
    assert_eq!(count(&f, "hygiene/java-weak-random"), 3, "{f:?}");

    let findings = scan_findings_at(
        "vulnerable_java_weak_random.java",
        "src/main/java/app/Randoms.java",
    );
    for finding in findings {
        if finding["rule_id"] == "hygiene/java-weak-random" {
            assert_eq!(finding["severity"], "low");
            assert_eq!(finding["cwe"], "CWE-330");
        }
    }
}

#[test]
fn weak_random_skips_test_sources_seeded_and_foreign_random() {
    let f = scan_at(
        "vulnerable_java_weak_random.java",
        "src/test/java/app/Randoms.java",
    );
    assert_eq!(
        count(&f, "hygiene/java-weak-random"),
        0,
        "test source: {f:?}"
    );
    for name in [
        "safe_java_weak_random.java",
        "safe_java_weak_random_foreign.java",
    ] {
        let f = scan_at(name, "src/main/java/app/Safe.java");
        assert_eq!(count(&f, "hygiene/java-weak-random"), 0, "{name}: {f:?}");
    }
}

fn lines(findings: &std::collections::BTreeMap<String, Vec<u64>>, rule: &str) -> Vec<u64> {
    let mut v = findings.get(rule).cloned().unwrap_or_default();
    v.sort_unstable();
    v
}

#[test]
fn injection_rules_flag_every_vulnerable_sink() {
    let f = scan("vulnerable_java_injection.java");
    assert_eq!(count(&f, "java/taint-path-traversal"), 12, "{f:?}");
    assert_eq!(count(&f, "java/taint-command-injection"), 5, "{f:?}");
    assert_eq!(count(&f, "java/taint-sql-injection"), 7, "{f:?}");
    assert_eq!(count(&f, "java/taint-ldap-injection"), 2, "{f:?}");
    assert_eq!(count(&f, "java/taint-xpath-injection"), 2, "{f:?}");
}

#[test]
fn injection_rules_ignore_constants_parameters_and_shell_free_commands() {
    let f = scan("safe_java_injection.java");
    for rule in [
        "java/taint-path-traversal",
        "java/taint-command-injection",
        "java/taint-sql-injection",
        "java/taint-ldap-injection",
        "java/taint-xpath-injection",
    ] {
        assert_eq!(lines(&f, rule), Vec::<u64>::new(), "{rule}: {f:?}");
    }
}

#[test]
fn upper_snake_parameters_are_request_data_but_static_final_constants_are_not() {
    let f = scan("vulnerable_java_upper_snake.java");
    // Spring handler, loop variable, helper parameter and shadowed constant.
    assert_eq!(
        lines(&f, "java/no-command-injection"),
        vec![17, 24, 29, 34],
        "{f:?}"
    );
    assert_eq!(
        lines(&f, "java/taint-command-injection"),
        vec![17, 24, 34],
        "{f:?}"
    );
    let f = scan("safe_java_upper_snake.java");
    assert_eq!(
        lines(&f, "java/no-command-injection"),
        Vec::<u64>::new(),
        "{f:?}"
    );
    assert_eq!(
        lines(&f, "java/taint-command-injection"),
        Vec::<u64>::new(),
        "{f:?}"
    );
}
