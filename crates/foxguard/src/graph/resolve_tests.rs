//! Call resolution: chains, `this`/field-of-field, interface dispatch, Spring wiring, generics,
//! ranking and dropped-call accounting (`graph::resolve`, `graph::types`).

use super::security_tests::graph_of;
use super::*;

/// Qualified names of the symbols the (first) call with this text reaches.
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
        .unwrap_or_else(|| {
            panic!(
                "no call {text} in {from_method}; have {:?}",
                g.calls
                    .iter()
                    .filter(|c| c.from == from.id)
                    .map(|c| &c.text)
                    .collect::<Vec<_>>()
            )
        });
    let mut v: Vec<String> = match &c.cand {
        Some(cand) => cand
            .iter()
            .map(|&i| g.symbols[i as usize].qualified.clone())
            .collect(),
        None => vec!["<unresolved>".to_string()],
    };
    v.sort();
    v
}

#[test]
fn chained_receivers_this_and_field_of_field_are_narrowed() {
    let g = graph_of(&[
        (
            "Repo.java",
            "class Repo { void save(String s) { jdbc.update(s); } }\nclass Other { void save(String s) {} }",
        ),
        (
            "Service.java",
            "class Service { Repo repo() { return null; } void run() { repo().save(\"a\"); } }",
        ),
        (
            "Holder.java",
            "class Holder { Service service; Repo direct; }",
        ),
        (
            "Ctl.java",
            r#"class Ctl {
    Holder holder;
    Service svc;
    void a() { svc.repo().save("x"); }
    void b() { this.holder.service.repo().save("x"); }
    void c() { this.holder.direct.save("x"); }
    void d() { var r = svc.repo(); r.save("x"); }
    void e() { holder.service.run(); }
}"#,
        ),
    ]);
    for m in ["Ctl.a", "Ctl.b", "Ctl.c", "Ctl.d"] {
        let t = if m == "Ctl.b" {
            "this.holder.service.repo().save"
        } else if m == "Ctl.c" {
            "this.holder.direct.save"
        } else if m == "Ctl.a" {
            "svc.repo().save"
        } else {
            "r.save"
        };
        assert_eq!(targets(&g, m, t), vec!["Repo.save"], "{m}");
    }
    assert_eq!(
        targets(&g, "Ctl.e", "holder.service.run"),
        vec!["Service.run"]
    );
}

#[test]
fn interface_calls_reach_implementors_and_spring_wiring_picks_one() {
    let g = graph_of(&[
        (
            "Notifier.java",
            "public interface Notifier { void send(String m); }",
        ),
        (
            "Mail.java",
            "@Service public class MailNotifier implements Notifier { public void send(String m) { jdbc.update(m); } }",
        ),
        (
            "Sms.java",
            "@Service(\"sms\") public class SmsNotifier implements Notifier { public void send(String m) {} }",
        ),
        (
            "Push.java",
            "@Service @Primary public class PushNotifier implements Notifier { public void send(String m) {} }",
        ),
        (
            "Use.java",
            r#"@RestController class Use {
    @Autowired Notifier notifier;
    @Autowired @Qualifier("sms") Notifier chosen;
    @Autowired Notifier mailNotifier;
    void a() { notifier.send("x"); }
    void b() { chosen.send("x"); }
    void c() { mailNotifier.send("x"); }
}"#,
        ),
        (
            "Single.java",
            r#"interface Mapper { void map(String s); }
@Component class OnlyMapper implements Mapper { public void map(String s) {} }
class UseMapper { private final Mapper mapper; UseMapper(Mapper mapper) { this.mapper = mapper; } void go() { mapper.map("x"); } }"#,
        ),
    ]);
    // @Primary wins over several implementors.
    assert_eq!(
        targets(&g, "Use.a", "notifier.send"),
        vec!["PushNotifier.send"]
    );
    // @Qualifier names the bean.
    assert_eq!(
        targets(&g, "Use.b", "chosen.send"),
        vec!["SmsNotifier.send"]
    );
    // Otherwise the field name is the bean name (here also `@Primary` is checked first, so primary wins).
    assert_eq!(
        targets(&g, "Use.c", "mailNotifier.send"),
        vec!["PushNotifier.send"]
    );
    // One implementor: constructor injection of the interface reaches it.
    assert_eq!(
        targets(&g, "UseMapper.go", "mapper.map"),
        vec!["OnlyMapper.map"]
    );
    let call = g
        .calls
        .iter()
        .find(|c| c.text == "mapper.map")
        .expect("call kept");
    assert_eq!(call.receiver_type.as_deref(), Some("OnlyMapper"));
}

#[test]
fn bean_named_like_the_field_and_unresolvable_wiring() {
    let g = graph_of(&[
        ("N.java", "interface Notifier { void send(String m); }"),
        ("A.java", "@Service class MailNotifier implements Notifier { public void send(String m) {} }"),
        ("B.java", "@Service class SmsNotifier implements Notifier { public void send(String m) {} }"),
        (
            "U.java",
            "class U { Notifier smsNotifier; Notifier other; void a() { smsNotifier.send(\"x\"); } void b() { other.send(\"x\"); } }",
        ),
    ]);
    assert_eq!(
        targets(&g, "U.a", "smsNotifier.send"),
        vec!["SmsNotifier.send"]
    );
    assert_eq!(
        targets(&g, "U.b", "other.send"),
        vec!["MailNotifier.send", "SmsNotifier.send"],
        "two beans and no hint stay two candidates"
    );
}

#[test]
fn abstract_classes_dispatch_to_overrides_and_inherited_methods() {
    let g = graph_of(&[
        (
            "Base.java",
            "abstract class Base { abstract void step(); void run() { step(); } void common() {} }",
        ),
        ("A.java", "class A extends Base { void step() {} }"),
        ("B.java", "class B extends Base { void step() {} }"),
        (
            "Use.java",
            "class Use { Base b; A a; void x() { b.step(); } void y() { a.common(); } void z() { a.step(); } }",
        ),
    ]);
    assert_eq!(targets(&g, "Base.run", "step"), vec!["A.step", "B.step"]);
    assert_eq!(targets(&g, "Use.x", "b.step"), vec!["A.step", "B.step"]);
    // `common` is inherited from Base.
    assert_eq!(targets(&g, "Use.y", "a.common"), vec!["Base.common"]);
    assert_eq!(targets(&g, "Use.z", "a.step"), vec!["A.step"]);
}

#[test]
fn generics_resolve_container_elements_and_class_type_parameters() {
    let g = graph_of(&[
        (
            "User.java",
            "class User { void touch() { jdbc.update(\"x\"); } }\nclass Account { void touch() {} }",
        ),
        (
            "Box.java",
            "class Box<T> { T value; T get() { return value; } }",
        ),
        (
            "UserRepository.java",
            "interface UserRepository extends JpaRepository<User, Long> {}",
        ),
        (
            "Use.java",
            r#"class Use {
    Optional<User> maybe;
    List<Account> accounts;
    Map<String, User> byName;
    Box<User> box;
    UserRepository repo;
    void a() { maybe.get().touch(); }
    void b() { accounts.get(0).touch(); }
    void c() { byName.get("x").touch(); }
    void d() { box.get().touch(); }
    void e() { box.value.touch(); }
    void f() { repo.findById(1L).orElseThrow().touch(); }
    void g() { for (var acc : accounts) { acc.touch(); } }
}"#,
        ),
    ]);
    assert_eq!(
        targets(&g, "Use.a", "maybe.get().touch"),
        vec!["User.touch"]
    );
    assert_eq!(
        targets(&g, "Use.b", "accounts.get().touch"),
        vec!["Account.touch"]
    );
    assert_eq!(
        targets(&g, "Use.c", "byName.get().touch"),
        vec!["User.touch"]
    );
    assert_eq!(targets(&g, "Use.d", "box.get().touch"), vec!["User.touch"]);
    assert_eq!(targets(&g, "Use.e", "box.value.touch"), vec!["User.touch"]);
    assert_eq!(
        targets(&g, "Use.f", "repo.findById().orElseThrow().touch"),
        vec!["User.touch"]
    );
    assert_eq!(targets(&g, "Use.g", "acc.touch"), vec!["Account.touch"]);
}

#[test]
fn library_receivers_do_not_join_same_named_methods_of_the_tree() {
    let g = graph_of(&[
        ("T.java", "class Tree { void add(String s) {} }"),
        (
            "U.java",
            "class U { List<String> list; Tree tree; void a() { list.add(\"x\"); } void b() { tree.add(\"x\"); } }",
        ),
    ]);
    assert!(
        !g.calls.iter().any(|c| c.text == "list.add"),
        "a List receiver is a library call"
    );
    assert_eq!(targets(&g, "U.b", "tree.add"), vec!["Tree.add"]);
}

#[test]
fn type_parameters_are_not_mistaken_for_library_types() {
    let g = graph_of(&[
        ("T.java", "class Item { void run() {} }"),
        (
            "U.java",
            "class U<T extends Item> { void a(T item) { item.run(); } <E> void b(E e) { e.run(); } }",
        ),
    ]);
    // `T` and `E` are type variables: nothing is known, so the by-name join stays.
    assert_eq!(targets(&g, "U.a", "item.run"), vec!["Item.run"]);
    assert_eq!(targets(&g, "U.b", "e.run"), vec!["Item.run"]);
}

#[test]
fn names_defined_many_times_are_ranked_by_proximity_and_the_rest_are_counted_as_dropped() {
    let mut files: Vec<(String, String)> = Vec::new();
    for i in 0..30 {
        files.push((
            format!("m{i}/p{i}/Cls{i}.java"),
            format!("package p{i};\npublic class Cls{i} {{ public void handle() {{}} }}"),
        ));
    }
    // Same file: local candidate wins.
    files.push((
        "m0/p0/Caller.java".to_string(),
        "package p0;\nclass Caller { void handle() {} void go() { handle(); } }".to_string(),
    ));
    // Same package.
    files.push((
        "m5/p5/User5.java".to_string(),
        "package p5;\nclass User5 { void go() { make().handle(); } }".to_string(),
    ));
    // Imported class decides.
    files.push((
        "other/Importer.java".to_string(),
        "package other;\nimport p9.Cls9;\nclass Importer { void go(Cls9 x) { x.handle(); } void h() { make().handle(); } }".to_string(),
    ));
    // No signal at all.
    files.push((
        "z/Lost.java".to_string(),
        "package z;\nclass Lost { void go() { make().handle(); } }".to_string(),
    ));
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let g = graph_of(&refs);
    assert_eq!(targets(&g, "Caller.go", "handle"), vec!["Caller.handle"]);
    assert_eq!(
        targets(&g, "User5.go", "make().handle"),
        vec!["Cls5.handle"]
    );
    assert_eq!(targets(&g, "Importer.go", "x.handle"), vec!["Cls9.handle"]);
    assert_eq!(
        targets(&g, "Importer.h", "make().handle"),
        vec!["Cls9.handle"]
    );
    // `Lost` has no package, import or directory in common with any candidate.
    assert!(!g
        .calls
        .iter()
        .any(|c| c.file.ends_with("Lost.java") && c.name == "handle"));
    assert_eq!(g.dropped_calls, 1);
    let stats = g.call_stats.clone().expect("stats");
    assert!(stats.jvm_calls >= 5);
    assert!(stats.resolved >= 2 && stats.ranked >= 2, "{stats:?}");
}

#[test]
fn dropped_calls_are_counted_when_nothing_singles_a_candidate_out() {
    let mut files: Vec<(String, String)> = Vec::new();
    for i in 0..30 {
        files.push((
            format!("m{i}/Cls{i}.java"),
            format!("package p{i};\npublic class Cls{i} {{ public void handle() {{}} }}"),
        ));
    }
    files.push((
        "z/Lost.java".to_string(),
        "package z;\nclass Lost { void go() { handle(); unknown(); } }".to_string(),
    ));
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let g = graph_of(&refs);
    assert_eq!(
        g.dropped_calls, 1,
        "handle() is defined 30 times and nothing ranks them"
    );
    assert!(!g.calls.iter().any(|c| c.name == "handle"));
    assert!(
        g.call_stats.as_ref().unwrap().external >= 1,
        "unknown() is external, not dropped"
    );
}

#[test]
fn legacy_resolution_flag_reproduces_name_only_joins() {
    let dir = std::env::temp_dir().join(format!("fg-graph-legacy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("A.java"),
        "class A { void save() {} }\nclass B { void save() {} }",
    )
    .unwrap();
    std::fs::write(
        dir.join("C.java"),
        "class C { A a; void go() { a.save(); b().save(); } B b() { return null; } }",
    )
    .unwrap();
    let new = build_graph(&dir);
    let old = build_graph_with(
        &dir,
        &GraphOptions {
            legacy_resolution: true,
            ..Default::default()
        },
    );
    let _ = std::fs::remove_dir_all(&dir);
    let chain_new = new.calls.iter().find(|c| c.text == "b().save").unwrap();
    assert_eq!(chain_new.receiver_type.as_deref(), Some("B"));
    let chain_old = old.calls.iter().find(|c| c.text == "b().save").unwrap();
    assert_eq!(chain_old.receiver_type, None);
}
