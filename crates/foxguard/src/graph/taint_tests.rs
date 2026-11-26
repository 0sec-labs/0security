//! `taintSummaries`: keyed by symbol and class, not by bare method name.

use super::*;

#[test]
fn taint_summaries_are_keyed_by_symbol_and_do_not_mix_same_named_methods() {
    let dir = std::env::temp_dir().join(format!("fg-graph-taint-keys-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("Runner.java"),
        "class Runner { String load(String cmd) throws Exception { Runtime.getRuntime().exec(cmd); return cmd; } }\n\
         class Cfg { void load(String path) { props.load(path); } }\n\
         class Over { void run(String a) { Runtime.getRuntime().exec(a); } void run(String a, String b) { log(b); } }\n",
    )
    .unwrap();
    let g = build_graph_with(
        &dir,
        &GraphOptions {
            taint_summaries: true,
            ..Default::default()
        },
    );
    let _ = std::fs::remove_dir_all(&dir);
    let loads: Vec<_> = g
        .taint_summaries
        .iter()
        .filter(|s| s.function == "load")
        .collect();
    assert_eq!(
        loads.len(),
        1,
        "Cfg.load is not a deserialization sink: {loads:?}"
    );
    assert_eq!(loads[0].qualified, "Runner.load");
    assert!(
        g.symbols.iter().any(|s| s.id == loads[0].symbol),
        "the summary names its symbol: {}",
        loads[0].symbol
    );
    assert!(loads[0]
        .params_to_sink
        .iter()
        .all(|f| f.rule_id == "java/taint-command-injection"));
    let run = g
        .taint_summaries
        .iter()
        .find(|s| s.qualified == "Over.run")
        .expect("Over.run");
    assert_eq!(run.arity, 1, "the one-argument overload is the sink");
    assert_eq!(
        g.taint_summaries
            .iter()
            .filter(|s| s.qualified == "Over.run")
            .count(),
        1,
        "the two-argument overload has nothing to report"
    );
}
