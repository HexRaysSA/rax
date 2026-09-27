//! Infrastructure tests deliberately simulate callback admission; compiled
//! guest fixtures separately exercise the actual x86/x64/ARM64 callback ABIs.

use super::*;
use crate::user::windows::layout::offsets;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

fn fixtures() -> [(&'static str, &'static [u8]); 3] {
    [
        (
            "x86",
            include_bytes!("../../../../tests/fixtures/user/windows/lifecycle/bin/x86/dynamic.exe"),
        ),
        (
            "x64",
            include_bytes!("../../../../tests/fixtures/user/windows/lifecycle/bin/x64/dynamic.exe"),
        ),
        (
            "arm64",
            include_bytes!(
                "../../../../tests/fixtures/user/windows/lifecycle/bin/arm64/dynamic.exe"
            ),
        ),
    ]
}

fn process(arch: &str, bytes: &[u8]) -> WindowsProcess {
    let exe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/user/windows/lifecycle/bin")
        .join(arch)
        .join("dynamic.exe");
    let mut cfg = WindowsConfig::new(exe, Vec::new());
    cfg.seed = Some(1);
    cfg.arena_bytes = 64 << 20;
    WindowsProcess::spawn_image(cfg, bytes.to_vec()).unwrap()
}

fn take_thread(p: &mut Proc) -> Thread {
    let tid = *p.threads.keys().next().unwrap();
    p.threads.remove(&tid).unwrap()
}

fn admit(p: &mut Proc, initialize: &[usize]) {
    for &idx in initialize {
        attach_started(p, idx, false).unwrap();
        attach_started(p, idx, p.modules.list[idx].has_dll_main()).unwrap();
        attach_succeeded(p, idx).unwrap();
    }
}

#[test]
fn references_graph_cycles_and_stable_tombstones_all_abis() {
    for (arch, bytes) in fixtures() {
        let mut process = process(arch, bytes);
        let p = process.state_mut();
        let mut t = take_thread(p);
        let plan = begin_load(p, &mut t, "root.dll").unwrap();
        let root = plan.root;
        let base = p.modules.list[root].base;
        let leaf = p.modules.by_name("leaf.dll").unwrap();
        assert_eq!(p.modules.list[root].load_count, 1);
        assert_eq!(p.modules.list[leaf].load_count, 0);
        assert!(p.modules.dynamic.dependencies[&root].contains(&leaf));
        dependency(p, leaf, root); // A synthetic legal import ownership cycle.
        admit(p, &plan.initialize);
        commit_load(p, plan.id).unwrap();
        let repeated = begin_load(p, &mut t, "ROOT.DLL").unwrap();
        assert_eq!(repeated.root, root);
        assert!(repeated.initialize.is_empty());
        commit_load(p, repeated.id).unwrap();
        assert_eq!(p.modules.list[root].load_count, 2);
        let first = begin_unload(p, base).unwrap();
        assert!(first.detach.is_empty());
        finish_unload(p, &mut t, first.id).unwrap();
        assert!(p.modules.is_live(root));
        let final_close = begin_unload(p, base).unwrap();
        assert_eq!(final_close.detach.first(), Some(&root));
        assert!(final_close.detach.contains(&leaf));
        for idx in &final_close.detach {
            detach_completed(p, *idx).unwrap();
        }
        finish_unload(p, &mut t, final_close.id).unwrap();
        assert!(!p.modules.is_live(root));
        assert!(!p.modules.is_live(leaf));
        assert_eq!(p.modules.by_base(base), None);
        assert_eq!(
            p.vm.query(base).unwrap().state,
            super::super::super::memory::mem::FREE
        );
        let next = begin_load(p, &mut t, "root.dll").unwrap();
        assert!(next.root > root);
        assert_eq!(p.modules.list[next.root].base, base);
        let error = LoadError::new(STATUS_UNSUCCESSFUL, "unit abandoned callback");
        assert!(begin_rollback(p, next.id, error, None).unwrap().is_empty());
        finish_rollback(p, &mut t, next.id).unwrap();
        p.threads.insert(t.tid, t);
    }
}

#[test]
fn rollback_bool_failure_is_distinct_from_exception_and_releases_owned_data() {
    for failing_main in [false, true] {
        for (arch, bytes) in fixtures() {
            let mut process = process(arch, bytes);
            let p = process.state_mut();
            let mut t = take_thread(p);
            let plan = begin_load(p, &mut t, "fail.dll").unwrap();
            let root = plan.root;
            let base = p.modules.list[root].base;
            let leaf = p.modules.by_name("leaf.dll").unwrap();
            let init = plan
                .initialize
                .iter()
                .copied()
                .filter(|i| *i != root)
                .collect::<Vec<_>>();
            admit(p, &init);
            attach_started(p, root, true).unwrap();
            let allocations = p.modules.dynamic.ldr_allocations[&root].clone();
            let blocks = p.modules.dynamic.tls_blocks[&t.tid]
                .values()
                .copied()
                .collect::<Vec<_>>();
            let detach = begin_rollback(
                p,
                plan.id,
                LoadError::new(STATUS_DLL_INIT_FAILED, "unit failed entry"),
                failing_main.then_some(root),
            )
            .unwrap();
            assert_eq!(detach.contains(&root), failing_main);
            assert!(detach.contains(&leaf));
            if failing_main {
                assert_eq!(detach.first(), Some(&root));
            }
            for idx in detach {
                detach_completed(p, idx).unwrap();
            }
            finish_rollback(p, &mut t, plan.id).unwrap();
            assert_eq!(t.tls_array, 0);
            assert_eq!(p.modules.next_tls_index, 0);
            assert!(
                allocations
                    .into_iter()
                    .chain(blocks)
                    .all(|ptr| p.heaps.owner(ptr).is_none())
            );
            assert_eq!(p.modules.by_base(base), None);
            let retry = begin_load(p, &mut t, "fail.dll").unwrap();
            assert!(retry.root > root);
            begin_rollback(
                p,
                retry.id,
                LoadError::new(STATUS_UNSUCCESSFUL, "retry abandoned"),
                None,
            )
            .unwrap();
            finish_rollback(p, &mut t, retry.id).unwrap();
            p.threads.insert(t.tid, t);
        }
    }
}

#[test]
fn dynamic_tls_is_published_for_existing_and_new_threads_then_removed() {
    for (arch, bytes) in fixtures() {
        let mut process = process(arch, bytes);
        let p = process.state_mut();
        let second = thread::create(p, 0, 0, 0x10000, false).unwrap();
        let mut t = take_thread(p);
        let plan = begin_load(p, &mut t, "leaf.dll").unwrap();
        let idx = plan.root;
        let tls = p.modules.list[idx].tls.unwrap();
        let o = offsets(p.arch);
        for target in [&t, &p.threads[&second]] {
            assert_eq!(
                p.space.ptr(target.teb + o.teb_tls_pointer, o.ptr).unwrap(),
                target.tls_array
            );
            let block = p
                .space
                .ptr(target.tls_array + o.ptr * u64::from(tls.index), o.ptr)
                .unwrap();
            let mut template = vec![0; tls.raw_size as usize];
            p.vm.peek(tls.template, &mut template).unwrap();
            let mut actual = vec![0; (tls.raw_size + tls.zero_fill) as usize];
            p.vm.peek(block, &mut actual).unwrap();
            assert_eq!(&actual[..template.len()], template.as_slice());
            assert!(actual[template.len()..].iter().all(|&b| b == 0));
        }
        admit(p, &plan.initialize);
        commit_load(p, plan.id).unwrap();
        let third = thread::create(p, 0, 0, 0x10000, false).unwrap();
        assert!(p.modules.dynamic.tls_blocks[&third].contains_key(&idx));
        let base = p.modules.list[idx].base;
        let close = begin_unload(p, base).unwrap();
        for idx in close.detach {
            detach_completed(p, idx).unwrap();
        }
        finish_unload(p, &mut t, close.id).unwrap();
        assert_eq!(t.tls_array, 0);
        assert_eq!(p.threads[&second].tls_array, 0);
        assert_eq!(p.threads[&third].tls_array, 0);
        assert_eq!(p.modules.next_tls_index, 0);
        p.threads.insert(t.tid, t);
    }
}

#[test]
fn exe_as_data_does_not_resolve_imports_or_allocate_tls() {
    for (arch, bytes) in fixtures() {
        let mut process = process(arch, bytes);
        let p = process.state_mut();
        let mut t = take_thread(p);
        let plan = begin_load(p, &mut t, "data.exe").unwrap();
        assert!(matches!(p.modules.list[plan.root].kind, ModuleKind::Data));
        assert!(plan.initialize.is_empty());
        assert!(p.modules.list[plan.root].tls.is_none());
        assert!(p.modules.by_name("absent-lifecycle.dll").is_none());
        let marker = begin_lookup(
            p,
            &mut t,
            plan.root,
            &SymRef::Name(b"DataMarker".to_vec(), None),
        )
        .unwrap();
        assert!(marker.address.is_some());
        assert!(marker.initialize.is_empty());
        commit_load(p, marker.id).unwrap();
        commit_load(p, plan.id).unwrap();
        let close = begin_unload(p, p.modules.list[plan.root].base).unwrap();
        assert!(close.detach.is_empty());
        finish_unload(p, &mut t, close.id).unwrap();
        p.threads.insert(t.tid, t);
    }
}

#[test]
fn forwarder_lookup_initializes_target_and_owns_its_dependency() {
    for (arch, bytes) in fixtures() {
        let mut process = process(arch, bytes);
        let p = process.state_mut();
        let mut t = take_thread(p);
        let plan = begin_load(p, &mut t, "forward.dll").unwrap();
        admit(p, &plan.initialize);
        commit_load(p, plan.id).unwrap();
        assert!(p.modules.by_name("leaf.dll").is_none());
        let lookup =
            begin_lookup(p, &mut t, plan.root, &SymRef::Name(b"Probe".to_vec(), None)).unwrap();
        let leaf = p.modules.by_name("leaf.dll").unwrap();
        assert!(lookup.initialize.contains(&leaf));
        assert!(lookup.address.is_some());
        assert_eq!(p.modules.list[leaf].load_count, 0);
        assert!(p.modules.dynamic.dependencies[&plan.root].contains(&leaf));
        admit(p, &lookup.initialize);
        commit_load(p, lookup.id).unwrap();
        let close = begin_unload(p, p.modules.list[plan.root].base).unwrap();
        assert!(close.detach.contains(&leaf));
        finish_unload(p, &mut t, close.id).unwrap();
        assert!(!p.modules.is_live(leaf));
        p.threads.insert(t.tid, t);
    }
}

#[test]
fn reference_sentinel_exhaustion_preserves_both_guest_and_host_counters() {
    let (arch, bytes) = fixtures()[1];
    let mut process = process(arch, bytes);
    let p = process.state_mut();
    let mut t = take_thread(p);
    let plan = begin_load(p, &mut t, "forward.dll").unwrap();
    admit(p, &plan.initialize);
    commit_load(p, plan.id).unwrap();
    let idx = plan.root;
    p.modules.list[idx].load_count = u32::MAX - 1;
    ldr::set_count(p, idx, u32::MAX - 1).unwrap();
    let e = p.modules.list[idx].ldr_entry;
    let o = offsets(p.arch);
    let before = (
        p.space.u16(e + o.entry_load_count).unwrap(),
        p.space.u32(e + o.entry_reference_count).unwrap(),
    );
    assert_eq!(
        reference_module(p, idx, false).unwrap_err().status,
        STATUS_NO_MEMORY
    );
    assert_eq!(p.modules.list[idx].load_count, u32::MAX - 1);
    assert_eq!(
        (
            p.space.u16(e + o.entry_load_count).unwrap(),
            p.space.u32(e + o.entry_reference_count).unwrap()
        ),
        before
    );
    assert!(!p.modules.dynamic.pins.contains(&idx));
    reference_module(p, idx, true).unwrap();
    assert_eq!(p.modules.list[idx].load_count, u32::MAX);
    assert_eq!(p.space.u16(e + o.entry_load_count).unwrap(), 0xFFFF);
    p.threads.insert(t.tid, t);
}

#[test]
fn protected_existing_teb_prevents_all_tls_publication_and_releases_images() {
    for (arch, bytes) in fixtures() {
        let mut process = process(arch, bytes);
        let p = process.state_mut();
        let second = thread::create(p, 0, 0, 0x10000, false).unwrap();
        let mut t = take_thread(p);
        let teb = p.threads[&second].teb;
        p.vm.protect(teb, 0x1000, prot::READONLY).unwrap();
        let error = match begin_load(p, &mut t, "leaf.dll") {
            Ok(_) => panic!("protected TEB admitted"),
            Err(e) => e,
        };
        assert_eq!(error.status, STATUS_ACCESS_VIOLATION);
        assert_eq!(t.tls_array, 0);
        assert_eq!(p.threads[&second].tls_array, 0);
        assert_eq!(p.modules.next_tls_index, 0);
        assert!(p.modules.by_name("leaf.dll").is_none());
        assert!(
            p.modules
                .dynamic
                .ldr_allocations
                .keys()
                .all(|&idx| p.modules.is_live(idx))
        );
        assert!(p.failure.is_none(), "{:?}", p.failure);
        p.vm.protect(teb, 0x1000, prot::READWRITE).unwrap();
        p.threads.insert(t.tid, t);
    }
}

#[test]
fn partial_ldr_name_allocation_failure_is_recoverable_without_panic() {
    for (arch, bytes) in fixtures() {
        let mut process = process(arch, bytes);
        let p = process.state_mut();
        let heap = p.heaps.create(&mut p.vm, 0, 0x1000, 0x2000).unwrap();
        p.process_heap = heap;
        let filler_size = 0x2000 - 0x100 - offsets(p.arch).entry_size - 16;
        let filler = p.heaps.alloc(&mut p.vm, heap, filler_size, false).unwrap();
        let mut t = take_thread(p);
        let first = p.modules.list.len();
        let error = match begin_load(p, &mut t, "leaf.dll") {
            Ok(_) => panic!("exhausted LDR heap admitted"),
            Err(e) => e,
        };
        assert_eq!(error.status, STATUS_NO_MEMORY);
        assert!(p.modules.list.len() > first); // Image and entry were allocated.
        assert!(p.modules.dynamic.ldr_allocations.get(&first).is_none());
        assert_eq!(p.modules.list[first].ldr_entry, 0);
        assert!(!p.modules.is_live(first));
        assert!(p.failure.is_none(), "{:?}", p.failure);
        p.heaps.free(heap, filler).unwrap();
        let retry = begin_load(p, &mut t, "leaf.dll").unwrap();
        begin_rollback(
            p,
            retry.id,
            LoadError::new(STATUS_UNSUCCESSFUL, "unit retry abandoned"),
            None,
        )
        .unwrap();
        finish_rollback(p, &mut t, retry.id).unwrap();
        p.threads.insert(t.tid, t);
    }
}

#[test]
fn detaching_entry_is_not_referenced_or_recursively_unloaded() {
    let (arch, bytes) = fixtures()[1];
    let mut process = process(arch, bytes);
    let p = process.state_mut();
    let mut t = take_thread(p);
    let plan = begin_load(p, &mut t, "leaf.dll").unwrap();
    admit(p, &plan.initialize);
    commit_load(p, plan.id).unwrap();
    let base = p.modules.list[plan.root].base;
    detach_started(p, plan.root).unwrap();
    assert!(reference_module(p, plan.root, false).is_err());
    assert!(begin_unload(p, base).is_err());
    assert_eq!(p.modules.by_base(base), Some(plan.root));
    detach_completed(p, plan.root).unwrap();
    assert!(!p.modules.ready_order().contains(&plan.root));
    p.threads.insert(t.tid, t);
}

#[test]
fn independent_nested_reference_retains_successful_dependency_after_outer_failure() {
    let (arch, bytes) = fixtures()[1];
    let mut process = process(arch, bytes);
    let p = process.state_mut();
    let mut t = take_thread(p);
    let outer = begin_load(p, &mut t, "root.dll").unwrap();
    let nested = begin_load(p, &mut t, "leaf.dll").unwrap();
    let leaf = nested.root;
    admit(p, &nested.initialize);
    commit_load(p, nested.id).unwrap();
    assert_eq!(p.modules.list[leaf].load_count, 1);
    let detach = begin_rollback(
        p,
        outer.id,
        LoadError::new(STATUS_DLL_INIT_FAILED, "outer failed"),
        None,
    )
    .unwrap();
    assert!(!detach.contains(&leaf));
    finish_rollback(p, &mut t, outer.id).unwrap();
    assert!(p.modules.is_live(leaf));
    let observer = p.modules.by_name("observer.dll").unwrap();
    assert!(p.modules.dynamic.dependencies[&leaf].contains(&observer));
    let close = begin_unload(p, p.modules.list[leaf].base).unwrap();
    assert!(close.detach.contains(&leaf));
    finish_unload(p, &mut t, close.id).unwrap();
    assert!(!p.modules.is_live(leaf));
    // The executable statically imports the observer; that root remains live.
    assert!(p.modules.is_live(observer));
    p.threads.insert(t.tid, t);
}

#[test]
fn absent_forwarded_export_rollback_removes_target_tls_and_owner_edge() {
    for (arch, bytes) in fixtures() {
        let mut process = process(arch, bytes);
        let p = process.state_mut();
        let mut t = take_thread(p);
        let plan = begin_load(p, &mut t, "forward.dll").unwrap();
        admit(p, &plan.initialize);
        commit_load(p, plan.id).unwrap();
        let owner = plan.root;
        let m = &p.modules.list[owner];
        let image = GuestImage {
            mem: &p.space,
            base: m.base,
            size: m.size,
        };
        let exports = ExportDirectory::read(&image, m.exports).unwrap().unwrap();
        let (index, _) = exports.by_name(&image, b"Probe", None).unwrap().unwrap();
        let rva = image
            .u32_at(u64::from(exports.functions_rva) + u64::from(index) * 4)
            .unwrap();
        let string = m.base + u64::from(rva);
        // Both strings contain 10 ASCII bytes plus NUL; no directory extents
        // or tables are changed, and no absent fixture path is assumed.
        p.vm.poke(string, b"leaf.NoFun\0").unwrap();
        assert!(p.modules.by_name("leaf.dll").is_none());
        let missing =
            begin_lookup(p, &mut t, owner, &SymRef::Name(b"Probe".to_vec(), None)).unwrap();
        assert_eq!(missing.address, None);
        let leaf = p.modules.by_name("leaf.dll").unwrap();
        assert!(missing.initialize.contains(&leaf));
        assert!(p.modules.dynamic.dependencies[&owner].contains(&leaf));
        assert_ne!(t.tls_array, 0);
        let array = t.tls_array;
        let block = p.modules.dynamic.tls_blocks[&t.tid][&leaf];
        let base = p.modules.list[leaf].base;
        let detach = begin_rollback(
            p,
            missing.id,
            LoadError::new(STATUS_ENTRYPOINT_NOT_FOUND, "absent forwarded export"),
            None,
        )
        .unwrap();
        assert!(detach.is_empty());
        finish_rollback(p, &mut t, missing.id).unwrap();
        assert!(!p.modules.is_live(leaf));
        assert!(p.modules.is_live(owner));
        assert!(!p.modules.dynamic.dependencies[&owner].contains(&leaf));
        assert_eq!(t.tls_array, 0);
        assert_eq!(p.modules.next_tls_index, 0);
        assert!(!p.modules.dynamic.journals.contains_key(&missing.id));
        assert!(!p.modules.dynamic.ldr_allocations.contains_key(&leaf));
        assert!(!p.modules.dynamic.tls_blocks[&t.tid].contains_key(&leaf));
        assert_eq!(p.heaps.owner(array), None);
        assert_eq!(p.heaps.owner(block), None);
        assert_eq!(
            p.vm.query(base).unwrap().state,
            super::super::super::memory::mem::FREE
        );
        p.threads.insert(t.tid, t);
    }
}

#[test]
fn forced_shutdown_discards_host_receipts_without_guest_cleanup_or_tls_loss() {
    let (arch, bytes) = fixtures()[1];
    let mut process = process(arch, bytes);
    let p = process.state_mut();
    let mut t = take_thread(p);
    let plan = begin_load(p, &mut t, "leaf.dll").unwrap();
    let idx = plan.root;
    let array = t.tls_array;
    let block = p.modules.dynamic.tls_blocks[&t.tid][&idx];
    let base = p.modules.list[idx].base;
    let image = p.vm.query(base).unwrap();
    assert!(p.modules.dynamic.journals.contains_key(&plan.id));
    p.modules.dynamic.active.push(plan.id);
    discard_transactions(p);
    assert!(p.modules.dynamic.journals.is_empty());
    assert!(p.modules.dynamic.active.is_empty());
    assert_eq!(t.tls_array, array);
    assert_eq!(p.modules.dynamic.tls_blocks[&t.tid][&idx], block);
    assert_eq!(p.heaps.owner(array), Some(p.process_heap));
    assert_eq!(p.heaps.owner(block), Some(p.process_heap));
    assert_eq!(p.vm.query(base).unwrap(), image);
    assert!(p.modules.is_live(idx));
    let tid = t.tid;
    thread::destroy(p, t, 0xDEAD);
    assert!(p.modules.dynamic.tls_blocks.get(&tid).is_none());
    assert_eq!(p.heaps.owner(array), None);
    assert_eq!(p.heaps.owner(block), None);
}

#[test]
fn historical_slot_cap_rejects_new_images_before_allocation_but_reuses_live_modules() {
    let (arch, bytes) = fixtures()[1];
    let mut process = process(arch, bytes);
    let p = process.state_mut();
    let first = p.modules.list.len();
    p.modules.list.resize_with(MAX_MODULE_HISTORY, || Module {
        name: String::new(),
        path: String::new(),
        host_path: None,
        base: 0,
        size: 0,
        entry: 0,
        kind: ModuleKind::Data,
        timestamp: 0,
        exports: DataDirectory::default(),
        pdata: DataDirectory::default(),
        no_seh: false,
        safe_seh: None,
        tls: None,
        ldr_entry: 0,
        load_count: 0,
        thread_calls: false,
        initialized: false,
        builtin_symbols: HashMap::new(),
        builtin_ordinals: Vec::new(),
        text: 0,
        stubs: HashMap::new(),
    });
    p.modules.dynamic.unloaded.extend(first..MAX_MODULE_HISTORY);
    let mut t = take_thread(p);
    let committed = p.vm.committed_bytes();
    let next_builtin = p.modules.next_builtin;
    let tls_index = p.modules.next_tls_index;
    let allocations = p.modules.dynamic.ldr_allocations.len();
    let error = match begin_load(p, &mut t, "leaf.dll") {
        Ok(_) => panic!("history cap admitted native"),
        Err(e) => e,
    };
    assert_eq!(error.status, STATUS_NO_MEMORY);
    static EXTRA: BuiltinDll = BuiltinDll {
        name: "cap-test.dll",
        display: "cap-test.dll",
        subsystem: 3,
        exports: &[],
    };
    assert!(p.modules.by_name(EXTRA.name).is_none());
    assert_eq!(
        load_builtin(p, &EXTRA).unwrap_err().status,
        STATUS_NO_MEMORY
    );
    assert_eq!(p.modules.list.len(), MAX_MODULE_HISTORY);
    assert_eq!(p.vm.committed_bytes(), committed);
    assert_eq!(p.modules.next_builtin, next_builtin);
    assert_eq!(p.modules.next_tls_index, tls_index);
    assert_eq!(p.modules.dynamic.ldr_allocations.len(), allocations);
    assert!(p.modules.dynamic.journals.is_empty());
    assert!(p.failure.is_none());
    let existing = p.modules.by_name("observer.dll").unwrap();
    let count = p.modules.list[existing].load_count;
    let reused = begin_load(p, &mut t, "observer.dll").unwrap();
    assert_eq!(reused.root, existing);
    admit(p, &reused.initialize);
    commit_load(p, reused.id).unwrap();
    assert_eq!(p.modules.list[existing].load_count, count + 1);
    assert_eq!(p.modules.list.len(), MAX_MODULE_HISTORY);
    assert_eq!(p.vm.committed_bytes(), committed);
    p.threads.insert(t.tid, t);
}
