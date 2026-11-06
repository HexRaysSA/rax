use super::*;
use std::cell::Cell;
use std::rc::Rc;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn subject() -> Vec<u8> {
    let mut sid = vec![1, 2, 0, 0, 0, 0, 0, 5];
    sid.extend_from_slice(&21u32.to_le_bytes());
    sid.extend_from_slice(&7u32.to_le_bytes());
    sid
}

fn registry(sid: &[u8]) -> Registry {
    Registry::selected(
        (0..=u16::MAX)
            .map(|unit| {
                if (97..=122).contains(&unit) {
                    unit - 32
                } else {
                    unit
                }
            })
            .collect(),
        vec![],
    )
    .unwrap()
    .with_primary_hive(
        sid,
        Some(super::super::super::primary_hive::HiveHeader {
            canonical: wide("\\Registry\\User\\S-1-5-21-7"),
            children: 1,
            values: vec![],
        }),
    )
    .unwrap()
}

struct Key {
    view: RegistryView,
    live: Rc<Cell<usize>>,
}

impl Drop for Key {
    fn drop(&mut self) {
        self.live.set(self.live.get() - 1);
    }
}

struct ChangingSource {
    path: Vec<u16>,
    live: Rc<Cell<usize>>,
    opens: Vec<RegistryView>,
    captures: Vec<RegistryView>,
    errors: [Option<i32>; 2],
    identities: [Option<(Vec<u16>, KeyAccess)>; 2],
    captured_access: Option<KeyAccess>,
}

impl ChangingSource {
    fn new(root: SnapshotRoot, sid: &[u8]) -> Self {
        Self {
            path: root.path(sid).unwrap(),
            live: Rc::new(Cell::new(0)),
            opens: vec![],
            captures: vec![],
            errors: [None, None],
            identities: [None, None],
            captured_access: None,
        }
    }
}

fn index(view: RegistryView) -> usize {
    usize::from(view == RegistryView::Wow32)
}

fn access() -> KeyAccess {
    KeyAccess {
        maximum_access: 0xF003F,
        system_security_status: 0xC0000022,
    }
}

impl Source for ChangingSource {
    type Key = Key;

    fn open(&mut self, view: RegistryView) -> io::Result<Key> {
        self.opens.push(view);
        if let Some(code) = self.errors[index(view)] {
            return Err(io::Error::from_raw_os_error(code));
        }
        self.live.set(self.live.get() + 1);
        Ok(Key {
            view,
            live: self.live.clone(),
        })
    }

    fn identity(&mut self, key: &Key) -> io::Result<(Vec<u16>, KeyAccess)> {
        Ok(self.identities[index(key.view)]
            .clone()
            .unwrap_or_else(|| (self.path.clone(), access())))
    }

    fn tree(
        &mut self,
        _registry: &Registry,
        view: RegistryView,
        key: Key,
    ) -> io::Result<CommandTree> {
        assert_eq!(key.view, view);
        assert_eq!(
            self.live.get(),
            1,
            "other root handle closed before descendants"
        );
        self.captures.push(view);
        let generation = self.captures.len() as u8;
        let (canonical, access) = self.identity(&key)?;
        let access = self.captured_access.unwrap_or(access);
        let child_name = wide("Child");
        let child_path = canonical.iter().copied().chain(wide("\\Child")).collect();
        let child = CommandTree {
            header: CommandHeader {
                canonical: child_path,
                enumeration: Some(vec![]),
                children: 0,
                values: vec![Value {
                    name: wide("ChildGeneration"),
                    kind: 3,
                    data: vec![generation],
                }],
                access,
            },
            children: vec![],
        };
        Ok(CommandTree {
            header: CommandHeader {
                canonical,
                enumeration: Some(vec![BasicChild {
                    name: child_name.clone(),
                    last_write: u64::from(generation),
                }]),
                children: 1,
                values: vec![Value {
                    name: wide("Generation"),
                    kind: 3,
                    data: vec![generation],
                }],
                access,
            },
            children: vec![(child_name, child)],
        })
    }
}

#[test]
fn shared_snapshot_captures_one_physical_generation_for_both_views() {
    let sid = subject();
    for root in [
        SnapshotRoot::Ole,
        SnapshotRoot::Command(CommandRoot::System),
        SnapshotRoot::LocalSettings,
    ] {
        let path = root.path(&sid).unwrap();
        let mut source = ChangingSource::new(root, &sid);
        let selected = capture(registry(&sid), root, &sid, &mut source).unwrap();
        assert_eq!(source.opens, [RegistryView::Native64, RegistryView::Wow32]);
        assert_eq!(source.captures, [RegistryView::Native64]);
        assert_eq!(source.live.get(), 0);
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            let Lookup::Present(key) = selected.lookup_view(&path, view) else {
                panic!("captured view")
            };
            assert_eq!(key.redirected_view, Some(view));
            assert_eq!(key.value(&wide("Generation")).unwrap().data, [1]);
            assert_eq!(key.child_metadata().unwrap()[0].last_write, 1);
            let Lookup::Present(child) = key.relative(&wide("Child")) else {
                panic!("captured child")
            };
            assert_eq!(child.redirected_view, Some(view));
            assert_eq!(child.value(&wide("ChildGeneration")).unwrap().data, [1]);
        }
    }
}

#[test]
fn shared_snapshot_rejects_root_identity_grant_and_capture_changes() {
    let sid = subject();
    let root = SnapshotRoot::LocalSettings;
    for case in 0..4 {
        let mut source = ChangingSource::new(root, &sid);
        let mut identity = (source.path.clone(), access());
        match case {
            0 => identity.0 = wide("\\Registry\\User\\S-1-5-21-7_Classes\\Local Settings"),
            1 => identity.1.maximum_access = 0x20019,
            2 => identity.1.system_security_status = 0xC0000061,
            _ => {
                source.captured_access = Some(KeyAccess {
                    maximum_access: 0x20019,
                    ..access()
                })
            }
        }
        source.identities[1] = Some(identity);
        assert!(capture(registry(&sid), root, &sid, &mut source).is_err());
        assert_eq!(source.captures.len(), usize::from(case == 3));
        assert_eq!(source.live.get(), 0);
    }
    let mut source = ChangingSource::new(root, &sid);
    source.identities[1] = Some((
        wide("\\registry\\user\\s-1-5-21-7\\software\\classes\\local settings"),
        access(),
    ));
    capture(registry(&sid), root, &sid, &mut source).unwrap();
    assert_eq!(source.captures, [RegistryView::Native64]);
    assert_eq!(source.live.get(), 0);
}

#[test]
fn shared_snapshot_preserves_absence_classes_and_native_errors_without_leaking_roots() {
    let sid = subject();
    let root = SnapshotRoot::Ole;
    for code in [2, 3] {
        let mut source = ChangingSource::new(root, &sid);
        source.errors = [Some(code), Some(code)];
        let selected = capture(registry(&sid), root, &sid, &mut source).unwrap();
        for view in [RegistryView::Native64, RegistryView::Wow32] {
            match (code, selected.lookup_view(&source.path, view)) {
                (2, Lookup::Missing) | (3, Lookup::MissingPath) => {}
                _ => panic!("exact absence class"),
            }
        }
        assert!(source.captures.is_empty());
        assert_eq!(source.live.get(), 0);
    }
    for errors in [[Some(2), Some(3)], [Some(2), None], [None, Some(3)]] {
        let mut source = ChangingSource::new(root, &sid);
        source.errors = errors;
        assert!(capture(registry(&sid), root, &sid, &mut source).is_err());
        assert!(source.captures.is_empty());
        assert_eq!(source.live.get(), 0);
    }
    for code in [5, 234, 259] {
        for failure in 0..2 {
            let mut source = ChangingSource::new(root, &sid);
            source.errors[failure] = Some(code);
            let error = capture(registry(&sid), root, &sid, &mut source).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(code));
            assert_eq!(source.opens.len(), failure + 1);
            assert!(source.captures.is_empty());
            assert_eq!(source.live.get(), 0);
        }
    }
}

#[test]
fn shared_snapshot_keeps_redirected_subjects_as_independent_captures() {
    let sid = subject();
    let root = SnapshotRoot::Command(CommandRoot::Machine);
    let mut source = ChangingSource::new(root, &sid);
    source.identities[1] = Some((
        wide("\\Registry\\Machine\\Software\\WOW6432Node\\Microsoft\\Command Processor"),
        access(),
    ));
    let selected = capture(registry(&sid), root, &sid, &mut source).unwrap();
    assert_eq!(
        source.captures,
        [RegistryView::Native64, RegistryView::Wow32]
    );
    assert_eq!(source.live.get(), 0);
    for (view, generation) in [(RegistryView::Native64, 1), (RegistryView::Wow32, 2)] {
        let Lookup::Present(key) = selected.lookup_view(&source.path, view) else {
            panic!("independent captured view")
        };
        assert_eq!(key.value(&wide("Generation")).unwrap().data, [generation]);
        assert_eq!(key.redirected_view, Some(view));
    }
}
