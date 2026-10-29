use super::*;
use crate::user::windows::nt::status::STATUS_ACCESS_DENIED;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn registry() -> Registry {
    Registry::selected(
        (0..=u16::MAX)
            .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
            .collect(),
        vec![],
    )
    .unwrap()
}

fn node(path: &str, access: u32, byte: u8, children: Vec<(&str, CommandTree)>) -> CommandTree {
    CommandTree {
        header: CommandHeader {
            canonical: wide(path),
            children: children.len() as u32,
            values: vec![Value {
                name: wide("Captured"),
                kind: 3,
                data: vec![byte],
            }],
            access: KeyAccess {
                maximum_access: access,
                system_security_status: STATUS_ACCESS_DENIED,
            },
        },
        children: children
            .into_iter()
            .map(|(name, tree)| (wide(name), tree))
            .collect(),
    }
}

fn complete(path: &str, byte: u8) -> CommandTree {
    let child = format!("{path}\\KnownPackageManagers");
    let leaf = format!("{child}\\captured-provider");
    node(
        path,
        0xf003f,
        0,
        vec![(
            "KnownPackageManagers",
            node(
                &child,
                0x20019,
                byte,
                vec![("captured-provider", node(&leaf, 1, byte + 1, vec![]))],
            ),
        )],
    )
}

fn present(result: Lookup) -> Arc<Key> {
    match result {
        Lookup::Present(key) => key,
        _ => panic!("expected captured key"),
    }
}

#[test]
fn complete_command_tree_distinguishes_partial_headers_and_physical_descendants() {
    let partial = registry()
        .with_command_view(
            CommandRoot::Machine,
            &[],
            RegistryView::Native64,
            Ok(complete(COMMAND_PROCESSOR_KEY, 1).header),
        )
        .unwrap();
    assert!(matches!(
        present(partial.lookup_view(&wide(COMMAND_PROCESSOR_KEY), RegistryView::Native64))
            .relative(&wide("KnownPackageManagers")),
        Lookup::Unselected
    ));
    let physical = "\\Registry\\Machine\\Software\\WOW6432Node\\Microsoft\\Command Processor";
    let selected = registry()
        .with_command_tree(
            CommandRoot::Machine,
            &[],
            RegistryView::Wow32,
            Ok(complete(physical, 1)),
        )
        .unwrap();
    let child = present(selected.lookup_view(
        &wide(&format!("{physical}\\KnownPackageManagers")),
        RegistryView::Wow32,
    ));
    assert!(child.command_physical_name(&wide(&format!("{physical}\\KnownPackageManagers"))));
    assert!(child.command_physical_name(&wide(
        "Software\\WOW6432Node\\Microsoft\\Command Processor\\KnownPackageManagers"
    )));
    assert!(!child.command_physical_name(&wide(&format!(
        "{COMMAND_PROCESSOR_KEY}\\KnownPackageManagers"
    ))));
    let nested =
        format!("{COMMAND_PROCESSOR_KEY}\\Software\\WOW6432Node\\Microsoft\\Command Processor");
    let mut subtree = node(&nested, 1, 1, vec![]);
    let mut prefix = nested.as_str();
    for name in ["Command Processor", "Microsoft", "WOW6432Node", "Software"] {
        prefix = prefix.rsplit_once('\\').unwrap().0;
        subtree = node(prefix, 1, 1, vec![(name, subtree)]);
    }
    let selected = registry()
        .with_command_tree(
            CommandRoot::Machine,
            &[],
            RegistryView::Native64,
            Ok(subtree),
        )
        .unwrap();
    let child = present(selected.lookup_view(&wide(&nested), RegistryView::Native64));
    assert!(!child.command_physical_name(&wide(&nested)));
}

#[test]
fn complete_command_tree_retains_descendant_values_grants_and_views_after_namespace_drop() {
    let native = COMMAND_PROCESSOR_KEY;
    let wow = "\\Registry\\Machine\\Software\\WOW6432Node\\Microsoft\\Command Processor";
    let registry = registry()
        .with_command_tree(
            CommandRoot::Machine,
            &[],
            RegistryView::Native64,
            Ok(complete(native, 10)),
        )
        .unwrap()
        .with_command_tree(
            CommandRoot::Machine,
            &[],
            RegistryView::Wow32,
            Ok(complete(wow, 20)),
        )
        .unwrap();
    let first = present(registry.lookup_view(&wide(native), RegistryView::Native64));
    let second = present(registry.lookup_view(&wide(native), RegistryView::Wow32));
    drop(registry);
    for (root, path, byte) in [(first, native, 10), (second, wow, 20)] {
        let child = present(root.relative(&wide("knownpackagemanagers")));
        assert_eq!(child.path, wide(&format!("{path}\\KnownPackageManagers")));
        assert_eq!(child.value(&wide("captured")).unwrap().data, [byte]);
        assert_eq!(child.captured_access().unwrap().grant(0x20019), Ok(0x20019));
        assert_eq!(
            child.captured_access().unwrap().grant(2),
            Err(STATUS_ACCESS_DENIED)
        );
        let leaf = present(child.relative(&wide("CAPTURED-PROVIDER")));
        assert_eq!(leaf.value(&wide("Captured")).unwrap().data, [byte + 1]);
        assert_eq!(leaf.captured_access().unwrap().grant(0x02000000), Ok(1));
        assert!(matches!(root.relative(&wide("Unknown")), Lookup::Missing));
        assert!(matches!(
            child.relative(&wide("Unknown\\More")),
            Lookup::Missing
        ));
        assert!(matches!(leaf.relative(&wide("Unknown")), Lookup::Missing));
    }
}

#[test]
fn complete_command_tree_rejects_count_escape_duplicate_and_access_contradictions() {
    let mut bad_count = complete(COMMAND_PROCESSOR_KEY, 1);
    bad_count.header.children = 0;
    let mut escaped = complete(COMMAND_PROCESSOR_KEY, 1);
    escaped.children[0].1.header.canonical = wide("\\Registry\\Machine\\Outside");
    let mut bad_access = complete(COMMAND_PROCESSOR_KEY, 1);
    bad_access.children[0].1.header.access.maximum_access |= 0x04000000;
    let mut duplicate = complete(COMMAND_PROCESSOR_KEY, 1);
    let mut second = complete(COMMAND_PROCESSOR_KEY, 1).children.remove(0);
    second.0 = wide("KNOWNPACKAGEMANAGERS");
    duplicate.children.push(second);
    duplicate.header.children = 2;
    let mut invalid_name = complete(COMMAND_PROCESSOR_KEY, 1);
    invalid_name.children[0].0 = wide("Bad\\Component");
    for tree in [bad_count, escaped, bad_access, duplicate, invalid_name] {
        assert!(
            registry()
                .with_command_tree(CommandRoot::Machine, &[], RegistryView::Native64, Ok(tree))
                .is_err()
        );
    }
}

#[test]
fn complete_command_tree_compares_shared_physical_descendants_between_views() {
    let first = registry()
        .with_command_tree(
            CommandRoot::Machine,
            &[],
            RegistryView::Native64,
            Ok(complete(COMMAND_PROCESSOR_KEY, 1)),
        )
        .unwrap();
    assert!(
        first
            .clone()
            .with_command_tree(
                CommandRoot::Machine,
                &[],
                RegistryView::Wow32,
                Ok(complete(COMMAND_PROCESSOR_KEY, 2))
            )
            .is_err()
    );
    assert!(
        first
            .with_command_tree(
                CommandRoot::Machine,
                &[],
                RegistryView::Wow32,
                Ok(complete(COMMAND_PROCESSOR_KEY, 1))
            )
            .is_ok()
    );
}

fn chain(path: String, remaining: usize) -> CommandTree {
    let children = if remaining == 0 {
        vec![]
    } else {
        vec![("x", chain(format!("{path}\\x"), remaining - 1))]
    };
    node(&path, 1, 1, children)
}

#[test]
fn complete_command_tree_enforces_depth_and_global_view_node_budgets() {
    for (depth, accepted) in [(32, true), (33, false)] {
        assert_eq!(
            registry()
                .with_command_tree(
                    CommandRoot::Machine,
                    &[],
                    RegistryView::Native64,
                    Ok(chain(COMMAND_PROCESSOR_KEY.into(), depth))
                )
                .is_ok(),
            accepted
        );
    }
    let mut full = node(COMMAND_PROCESSOR_KEY, 1, 1, vec![]);
    full.header.children = 1023;
    full.children = (0..1023)
        .map(|i| {
            let name = format!("n{i:04}");
            (
                wide(&name),
                node(&format!("{COMMAND_PROCESSOR_KEY}\\{name}"), 1, 1, vec![]),
            )
        })
        .collect();
    let selected = registry()
        .with_command_tree(CommandRoot::Machine, &[], RegistryView::Native64, Ok(full))
        .unwrap();
    assert!(
        selected
            .with_command_tree(
                CommandRoot::Machine,
                &[],
                RegistryView::Wow32,
                Ok(node(COMMAND_PROCESSOR_KEY, 1, 1, vec![]))
            )
            .is_err()
    );
}

#[test]
fn complete_command_tree_charges_values_across_all_nodes_and_views() {
    let mut full = node(COMMAND_PROCESSOR_KEY, 1, 1, vec![]);
    full.header.values = (0..4096)
        .map(|i| Value {
            name: wide(&format!("v{i:04}")),
            kind: 3,
            data: vec![1],
        })
        .collect();
    let selected = registry()
        .with_command_tree(CommandRoot::Machine, &[], RegistryView::Native64, Ok(full))
        .unwrap();
    assert_eq!(selected.value_budget().unwrap().count, 4096);
    assert!(
        selected
            .with_command_tree(
                CommandRoot::Machine,
                &[],
                RegistryView::Wow32,
                Ok(node(COMMAND_PROCESSOR_KEY, 1, 1, vec![]))
            )
            .is_err()
    );
}
