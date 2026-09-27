//! Local data-install receipts versus process-pinned runtime ownership.

use super::*;
use crate::error::MemoryAccessKind;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::hle::{DataSize, Export, Item};
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::mem;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

static FORWARD_EXPORTS: &[Export] = &[Export::forward("RuntimeAllocate", "msvcrt.malloc")];
static FORWARD_DLL: BuiltinDll = BuiltinDll {
    name: "crt-data-forward-test.dll",
    display: "crt-data-forward-test.dll",
    subsystem: 3,
    exports: &[FORWARD_EXPORTS],
};

fn process(arch: WinArch) -> WindowsProcess {
    let bytes: &[u8] = match arch {
        WinArch::X86 => include_bytes!("../../../../tests/fixtures/user/windows/bin/x86/smoke.exe"),
        WinArch::X64 => include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe"),
        WinArch::Arm64 => {
            include_bytes!("../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
        }
    };
    let mut cfg = WindowsConfig::new("crt-data-install-test.exe", Vec::new());
    cfg.seed = Some(1);
    cfg.arena_bytes = 64 << 20;
    WindowsProcess::spawn_image(cfg, bytes.to_vec()).unwrap()
}

fn cell(p: &Proc, index: usize, name: &str) -> u64 {
    match p.modules.list[index].builtin_symbols.get(name).unwrap() {
        BuiltinSym::Rva(rva) => p.modules.list[index].base + u64::from(*rva),
        BuiltinSym::Forward(_) => panic!("a data cell must not be a forwarder"),
    }
}

fn warm_loader_heap(p: &mut Proc) {
    // HeapFree preserves heap commitment. Warm it before the snapshot so
    // later LDR allocation/free does not obscure exact VM-blob rollback.
    let heap = p.process_heap;
    let block = p
        .heaps
        .alloc_checked(&mut p.vm, heap, 8 * PAGE_SIZE, true)
        .unwrap();
    p.heaps.free(heap, block).unwrap();
}

#[test]
fn startup_data_installs_without_a_thread_and_repeated_load_preserves_cells_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        assert!(p.modules.by_name("msvcrt.dll").is_none());
        assert_ne!(p.process_heap, 0);
        assert_ne!(p.params, 0);
        let _threads = std::mem::take(&mut p.threads);
        assert!(p.threads.is_empty());

        let index = load_dll(p, "msvcrt.dll").unwrap();
        let dll = dll::find("msvcrt.dll").unwrap();
        let mut data_count = 0;
        for export in dll.exports.iter().flat_map(|table| table.iter()) {
            if !export.archs.has(arch) {
                continue;
            }
            let Item::Data(size) = &export.item else {
                continue;
            };
            let bytes = match size {
                DataSize::Bytes(bytes) => u64::from(*bytes),
                DataSize::Ptrs(words) => u64::from(*words) * arch.ptr_size(),
            };
            let address = cell(p, index, export.name);
            assert_eq!(p.vm.query(address).unwrap().protect, prot::READWRITE);
            p.space
                .probe(address, bytes as usize, MemoryAccessKind::Write)
                .unwrap();
            assert!(p.traps.lookup(address).is_none());
            data_count += 1;
        }
        assert_ne!(data_count, 0, "legacy direct data exports must exist");
        let argc = cell(p, index, "__argc");
        p.space.w32(argc, 0x7FFF_1234).unwrap();
        let committed = p.vm.committed_bytes();
        #[allow(deprecated)]
        {
            // The historical public hook stays a no-op. Loading owns the
            // fallible transaction; compatibility callers cannot reset cells.
            dll::init_data_exports(p, index);
        }
        assert_eq!(p.space.u32(argc).unwrap(), 0x7FFF_1234);
        assert_eq!(p.vm.committed_bytes(), committed);
        let repeated = load_dll(p, "MSVCRT.DLL").unwrap();
        assert_eq!(repeated, index);
        assert_eq!(cell(p, repeated, "__argc"), argc);
        assert_eq!(p.space.u32(argc).unwrap(), 0x7FFF_1234);
        assert_eq!(p.vm.committed_bytes(), committed);
        assert_eq!(p.modules.list[index].load_count, u32::MAX);
        assert!(p.failure.is_none());
    }
}

#[test]
fn early_source_fault_releases_image_without_publishing_module_traps_or_runtime_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        assert!(p.modules.by_name("msvcrt.dll").is_none());
        let o = offsets(arch);
        let descriptor = p.params + o.pp_command_line;
        assert_ne!(p.space.u16(descriptor).unwrap(), 0);
        let source_cell = descriptor + o.ptr;
        let original_source = p.space.ptr(source_cell, o.ptr).unwrap();
        let bad_source = 0x8000;
        assert!(p.space.u16(bad_source).is_err());

        let dll = dll::find("msvcrt.dll").unwrap();
        let image = builtin::build(dll, arch, 0, &[]);
        let candidate = p.modules.next_builtin;
        assert!(p.vm.is_free(candidate, image.bytes.len() as u64));
        let text = candidate + u64::from(image.text_rva);
        let before_modules = p.modules.list.len();
        let before_init_order = p.modules.init_order.clone();
        let before_commit = p.vm.committed_bytes();
        let before_blocks = p.heaps.blocks(p.process_heap);
        p.space.wptr(source_cell, o.ptr, bad_source).unwrap();

        let error = load_builtin(p, dll).unwrap_err();
        assert_eq!(error.status, STATUS_ACCESS_VIOLATION);
        assert!(error.message.contains("read fault at 0x8000"));
        assert_eq!(p.modules.list.len(), before_modules);
        assert_eq!(p.modules.init_order, before_init_order);
        assert!(p.modules.by_name("msvcrt.dll").is_none());
        assert!(p.traps.lookup(text).is_none());
        assert!(!p.traps.contains(text));
        assert_eq!(p.vm.query(candidate).unwrap().state, mem::FREE);
        assert_eq!(p.vm.committed_bytes(), before_commit);
        assert_eq!(p.heaps.blocks(p.process_heap), before_blocks);
        assert!(p.failure.is_none());

        p.space.wptr(source_cell, o.ptr, original_source).unwrap();
        // A successful retry also establishes that preparation did not
        // install process CRT state: a second install is explicitly rejected.
        let index = load_builtin(p, dll).unwrap();
        assert_eq!(index, before_modules);
        assert!(p.modules.is_live(index));
        assert_eq!(p.modules.by_name("msvcrt.dll"), Some(index));
        assert!(p.traps.lookup(p.modules.list[index].text).is_some());
        assert_eq!(p.space.u32(cell(p, index, "__argc")).unwrap(), 0);
        assert!(p.failure.is_none());
    }
}

#[test]
fn late_ldr_failure_aborts_data_before_module_or_trap_success_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        warm_loader_heap(p);
        let o = offsets(arch);
        let tail = p.modules.ldr_data + o.ldr_in_load_order + o.ptr;
        let old_tail = p.space.ptr(tail, o.ptr).unwrap();
        let before_commit = p.vm.committed_bytes();
        let before_blocks = p.heaps.blocks(p.process_heap);
        let first = p.modules.list.len();
        p.space.wptr(tail, o.ptr, 0).unwrap();

        let error = load_dll(p, "msvcrt.dll").unwrap_err();
        assert_eq!(error.status, STATUS_ACCESS_VIOLATION);
        assert_eq!(p.modules.list.len(), first + 1);
        let failed = &p.modules.list[first];
        assert!(!p.modules.is_live(first));
        assert!(p.modules.by_name("msvcrt.dll").is_none());
        assert!(p.traps.lookup(failed.text).is_none());
        assert!(!p.traps.contains(failed.text));
        assert_eq!(p.vm.query(failed.base).unwrap().state, mem::FREE);
        assert_eq!(p.vm.committed_bytes(), before_commit);
        assert_eq!(p.heaps.blocks(p.process_heap), before_blocks);
        assert!(
            p.failure.is_none(),
            "owned cleanup must not depend on the bad tail"
        );

        p.space.wptr(tail, o.ptr, old_tail).unwrap();
        let next = load_dll(p, "msvcrt.dll").unwrap();
        assert!(next > first); // Historical module slots are not reused.
        assert!(p.modules.is_live(next));
        assert_eq!(p.modules.by_name("msvcrt.dll"), Some(next));
        assert!(p.traps.lookup(p.modules.list[next].text).is_some());
        assert!(p.failure.is_none());
    }
}

#[test]
fn successfully_installed_runtime_is_not_owned_by_forwarder_rollback_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        assert!(p.modules.by_name("msvcrt.dll").is_none());
        let forward = load_builtin(p, &FORWARD_DLL).unwrap();
        let tid = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&tid).unwrap();
        let plan = begin_lookup(
            p,
            &mut thread,
            forward,
            &SymRef::Name(b"RuntimeAllocate".to_vec(), None),
        )
        .unwrap();
        assert!(plan.address.is_some());
        let runtime = p.modules.by_name("msvcrt.dll").unwrap();
        let argc = cell(p, runtime, "__argc");
        p.space.w32(argc, 73).unwrap();
        let committed = p.vm.committed_bytes();

        let failure = LoadError::new(STATUS_DLL_INIT_FAILED, "unit importer failed after lookup");
        assert!(
            begin_rollback(p, plan.id, failure, None)
                .unwrap()
                .is_empty()
        );
        finish_rollback(p, &mut thread, plan.id).unwrap();
        assert!(p.modules.is_live(runtime));
        assert_eq!(p.modules.by_name("msvcrt.dll"), Some(runtime));
        assert_eq!(p.modules.list[runtime].load_count, u32::MAX);
        assert_eq!(p.space.u32(argc).unwrap(), 73);
        assert_eq!(p.vm.committed_bytes(), committed);

        let base = p.modules.list[runtime].base;
        let unload = begin_unload(p, base).unwrap();
        assert!(unload.detach.is_empty());
        finish_unload(p, &mut thread, unload.id).unwrap();
        assert!(p.modules.is_live(runtime));
        assert_eq!(p.space.u32(argc).unwrap(), 73);
        assert!(p.failure.is_none());
        p.threads.insert(tid, thread);
    }
}
