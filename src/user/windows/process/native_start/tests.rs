use super::*;
use crate::user::windows::layout::offsets;
use crate::user::windows::loader::apiset_schema::ApiSetSchema;
use crate::user::windows::memory::prot;
use crate::user::windows::native::NativeRuntime;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

fn image(arch: WinArch) -> &'static [u8] {
    match arch {
        WinArch::X86 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
        }
        WinArch::X64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
        }
        WinArch::Arm64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
        }
    }
}

pub(in crate::user::windows::process) fn fixture(arch: WinArch) -> (WindowsProcess, Thread) {
    let mut config = WindowsConfig::embedded("C:\\startup.exe", vec![], vec![], 4096).unwrap();
    config.arena_bytes = 64 << 20;
    let mut process = WindowsProcess::spawn_image(config, image(arch).to_vec()).unwrap();
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let thread = p.threads.remove(&tid).unwrap();
    (process, thread)
}

fn entries() -> EntryPoints {
    EntryPoints {
        loader: 0x50000,
        thread: 0x51000,
        module: 0x40000,
        callback: Some(0x52000),
    }
}

pub(in crate::user::windows::process) fn runtime(entries: Option<EntryPoints>) -> NativeRuntime {
    // Empty, valid version6 namespace; no host DLL/kernel acquisition.
    let schema: Vec<u8> = [6u32, 28, 0, 0, 28, 28, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    NativeRuntime {
        directory: Default::default(),
        guest_root: "C:\\Windows".into(),
        guest_directory: "C:\\Windows\\System32".into(),
        version: Default::default(),
        apisets: ApiSetSchema::parse(&schema).unwrap(),
        registry: Default::default(),
        object_namespace: Default::default(),
        nls: None,
        appcompat: Default::default(),
        wnf_catalog: Default::default(),
        startup: entries,
        code_integrity: Err("controlled absent code integrity metadata".into()),
        code_integrity_policy: Err("code integrity policy not captured in this fixture".into()),
        policy_catalog: Err("software policy not captured in this fixture".into()),
        code_integrity_policies: Err("code integrity policies not captured in this fixture".into()),
        gui: Default::default(),
    }
}

fn context_address(p: &Proc, t: &Thread) -> u64 {
    match p.arch {
        WinArch::X86 => u64::from(p.space.u32(t.cpu.sp() + 4).unwrap()),
        WinArch::X64 => t.cpu.gpr(1),
        WinArch::Arm64 => t.cpu.gpr(0),
    }
}

#[test]
fn arm64_loader_context_selects_native_kernel_groups_without_x18() {
    for logical_arch in [WinArch::Arm64, WinArch::X64] {
        let (mut process, mut t) = fixture(logical_arch);
        let p = process.state_mut();
        let mut native = runtime(None);
        native.object_namespace.native_machine = Some(0xaa64);
        p.native = Some(native);
        let address = enter(p, &mut t.cpu, false, entries()).unwrap();
        let context = RegContext::read(&p.space, WinArch::Arm64, address).unwrap();
        assert_eq!(context.flags(), 0x0040_000f, "{logical_arch}");
        assert_eq!(context.gpr(18), t.teb);
        assert_eq!(context.flags_register(), 0x40);
    }
}

#[test]
fn native_start_restore_preserves_debug_set_after_suspended_thread_creation() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch);
        let p = process.state_mut();
        enter(p, &mut t.cpu, false, entries()).unwrap();
        let address = context_address(p, &t);
        t.native_start_context = Some(StartupContext { arch, address });
        let target = entries().thread;
        let mut debug = vec![
            0u8;
            if arch == WinArch::Arm64 {
                120
            } else {
                6 * arch.ptr_size() as usize
            }
        ];
        if arch == WinArch::Arm64 {
            debug[..4].copy_from_slice(&0x1e5u32.to_le_bytes());
            debug[32..40].copy_from_slice(&target.to_le_bytes());
        } else {
            let width = arch.ptr_size() as usize;
            debug[..width].copy_from_slice(&target.to_le_bytes()[..width]);
            debug[5 * width..6 * width].copy_from_slice(&0x401u64.to_le_bytes()[..width]);
        }
        t.cpu
            .apply_kernel_debug_context(arch, &debug, p.vm.high())
            .unwrap();
        let armed = t.cpu.kernel_debug_context(arch).unwrap();
        // A parent can arm a suspended child after the loader's initial
        // context was allocated. LdrInitializeThunk's NtContinue must retain
        // that kernel-owned bank, as the native own-child control does.
        refresh_startup_debug(p, &mut t).unwrap();
        assert!(t.native_start_context.is_none());
        let saved = RegContext::read(&p.space, arch, address).unwrap();
        t.cpu.apply_kernel_context(&saved).unwrap();
        assert_eq!(t.cpu.kernel_debug_context(arch).unwrap(), armed, "{arch}");
        let mask = if arch == WinArch::Arm64 {
            crate::user::windows::context::DEBUG_ARM64
        } else {
            crate::user::windows::context::DEBUG_X86
        };
        assert_eq!(saved.flags() & mask, mask, "{arch}");
    }
}

#[test]
fn native_start_debug_refresh_is_once_and_preserves_other_context_bytes() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch);
        let p = process.state_mut();
        let address = enter(p, &mut t.cpu, false, entries()).unwrap();
        t.native_start_context = Some(StartupContext { arch, address });
        let original = RegContext::read(&p.space, arch, address).unwrap();
        let range = crate::user::windows::context::debug::context_range(arch);
        let location = address + range.start as u64;
        p.space.wr(location, &vec![0xa5; range.len()]).unwrap();
        refresh_startup_debug(p, &mut t).unwrap();
        assert!(t.native_start_context.is_none());
        assert_eq!(RegContext::read(&p.space, arch, address).unwrap(), original);
        // Once the loader has started, its saved context belongs to user code.
        // A later scheduling turn must not rewrite that memory again.
        let marker = vec![0x5a; range.len()];
        p.space.wr(location, &marker).unwrap();
        refresh_startup_debug(p, &mut t).unwrap();
        assert_eq!(p.space.bytes(location, range.len()).unwrap(), marker);
    }
}

#[test]
fn native_start_debug_refresh_failure_retains_pending_context_and_live_cpu() {
    use crate::user::windows::memory::prot;
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch);
        let p = process.state_mut();
        let address = enter(p, &mut t.cpu, false, entries()).unwrap();
        t.native_start_context = Some(StartupContext { arch, address });
        let before = RegContext::capture(&t.cpu);
        let saved = RegContext::read(&p.space, arch, address).unwrap();
        let page = address & !4095;
        p.vm.protect(page, 4096, prot::READONLY).unwrap();
        assert_eq!(
            refresh_startup_debug(p, &mut t),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(RegContext::capture(&t.cpu), before);
        assert_eq!(RegContext::read(&p.space, arch, address).unwrap(), saved);
        assert!(
            matches!(t.native_start_context, Some(pending) if pending.address == address && pending.arch == arch)
        );
        p.vm.protect(page, 4096, prot::READWRITE).unwrap();
        refresh_startup_debug(p, &mut t).unwrap();
        assert!(t.native_start_context.is_none());
    }
}

#[test]
fn native_start_context_preserves_thread_state_and_selects_native_entries_all_abis() {
    for arch in WinArch::ALL {
        for main in [false, true] {
            let (mut process, mut t) = fixture(arch);
            let p = process.state_mut();
            let before = RegContext::capture(&t.cpu);
            let heap = p.process_heap;
            let committed = p.vm.committed_bytes();
            enter(p, &mut t.cpu, main, entries()).unwrap();
            let address = context_address(p, &t);
            let saved = RegContext::read(&p.space, arch, address).unwrap();
            let mut expected = before.clone();
            if arch == WinArch::Arm64 {
                expected.set_flags(0x0040_000f);
            }
            expected.set_pc(entries().thread);
            if main {
                expected.set_gpr(
                    match arch {
                        WinArch::X86 => 3,
                        WinArch::X64 => 2,
                        WinArch::Arm64 => 1,
                    },
                    p.peb,
                );
            }
            if arch == WinArch::X64 {
                expected.set_sp(before.sp() - 8);
            }
            assert_eq!(saved.bytes(), expected.bytes(), "{arch}/{main}");
            assert_eq!(t.cpu.pc(), entries().loader);
            assert_eq!(t.cpu.teb(), t.teb);
            assert!(address % RegContext::align(arch) == 0);
            assert!(t.cpu.sp() < address && address + RegContext::size(arch) as u64 <= saved.sp());
            match arch {
                WinArch::X86 => {
                    assert_eq!(p.space.u32(t.cpu.sp()).unwrap(), 0);
                    assert_eq!(
                        p.space.u32(t.cpu.sp() + 8).unwrap(),
                        entries().module as u32
                    );
                }
                WinArch::X64 => {
                    assert_eq!(t.cpu.sp() % 16, 8);
                    assert_eq!(t.cpu.gpr(2), entries().module);
                    assert_eq!(p.space.bytes(t.cpu.sp(), 40).unwrap(), [0; 40]);
                }
                WinArch::Arm64 => {
                    assert_eq!(t.cpu.sp() % 16, 0);
                    assert_eq!(t.cpu.gpr(1), entries().module);
                    assert_eq!(t.cpu.gpr(30), 0);
                }
            }
            assert_eq!(p.process_heap, heap);
            assert_eq!(p.vm.committed_bytes(), committed);
            assert!(t.frames.is_empty());
        }
    }
}

#[test]
fn native_start_scratch_write_failure_changes_neither_context_bytes_nor_cpu_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch);
        let p = process.state_mut();
        let page = t.stack_base - 4096;
        p.space.wr(page, &[0xA5; 4096]).unwrap();
        p.vm.protect(page, 4096, prot::READONLY).unwrap();
        let before = RegContext::capture(&t.cpu);
        assert_eq!(enter(p, &mut t.cpu, true, entries()), Err(STATUS_NO_MEMORY));
        assert_eq!(RegContext::capture(&t.cpu).bytes(), before.bytes());
        assert_eq!(p.space.bytes(page, 4096).unwrap(), [0xA5; 4096]);
    }
}

#[test]
fn native_start_stack_underflow_is_rejected_before_memory_or_cpu_publication_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch);
        let p = process.state_mut();
        t.cpu.set_sp(0x100);
        let before = RegContext::capture(&t.cpu);
        let committed = p.vm.committed_bytes();
        assert_eq!(enter(p, &mut t.cpu, true, entries()), Err(STATUS_NO_MEMORY));
        assert_eq!(RegContext::capture(&t.cpu).bytes(), before.bytes());
        assert_eq!(p.vm.committed_bytes(), committed);
    }
}

#[test]
fn native_start_private_loader_lists_are_not_published_in_native_peb_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, _) = fixture(arch);
        let p = process.state_mut();
        let heap = p.process_heap;
        p.native = Some(runtime(None));
        loader::ldr::init(p).unwrap();
        let o = offsets(arch);
        assert_eq!(p.space.ptr(p.peb + o.peb_ldr, o.ptr).unwrap(), 0);
        assert_ne!(p.modules.ldr_data, 0);
        assert_eq!(p.process_heap, heap);
        assert!(p.heaps.alloc(&mut p.vm, heap, 32, true).is_some());
    }
}

#[test]
fn native_start_static_tls_is_owned_by_installed_loader_with_builtin_control_all_abis() {
    for arch in WinArch::ALL {
        for native in [false, true] {
            let (mut process, _) = fixture(arch);
            let p = process.state_mut();
            p.modules.next_tls_index = 1;
            p.modules.list[0].tls = Some(loader::ModuleTls {
                index: 0,
                template: 0,
                raw_size: 0,
                zero_fill: 16,
                callbacks: 0,
            });
            if native {
                p.native = Some(runtime(Some(entries())));
            }
            let tid = super::super::thread::create(p, 0x52000, 0x1234, 0, false).unwrap();
            let t = &p.threads[&tid];
            let o = offsets(arch);
            let published = p.space.ptr(t.teb + o.teb_tls_pointer, o.ptr).unwrap();
            assert_eq!(published, t.tls_array);
            if native {
                assert_eq!(published, 0);
                assert!(t.tls_blocks.is_empty());
                assert!(p.modules.dynamic.tls_blocks[&tid].is_empty());
            } else {
                assert_ne!(published, 0);
                assert_eq!(t.tls_blocks.len(), 1);
                assert_eq!(p.space.ptr(published, o.ptr).unwrap(), t.tls_blocks[0]);
                assert_eq!(p.space.bytes(t.tls_blocks[0], 16).unwrap(), [0; 16]);
            }
        }
    }
}

#[test]
fn native_start_requires_selected_native_ntdll_and_both_export_entries_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, _) = fixture(arch);
        let p = process.state_mut();
        p.native = Some(runtime(None));
        let index = p.modules.by_name("ntdll.dll").unwrap();
        assert!(matches!(entry_points(p), Err(STATUS_INVALID_IMAGE_FORMAT)));
        p.modules.list[index].kind = ModuleKind::Native;
        assert!(matches!(entry_points(p), Err(STATUS_ENTRYPOINT_NOT_FOUND)));
        assert!(p.native.as_ref().unwrap().startup.is_none());
        p.modules.list[index].name = "missing-ntdll.dll".into();
        assert!(matches!(entry_points(p), Err(STATUS_DLL_NOT_FOUND)));
    }
}

#[test]
fn native_start_attachment_boundary_requires_exact_resumed_native_entry_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch);
        let p = process.state_mut();
        p.native = Some(runtime(Some(entries())));
        for pc in [
            entries().loader,
            entries().thread - 1,
            entries().thread + 1,
            p.traps.thread_start(),
        ] {
            t.cpu.set_pc(pc);
            observe_resume(p, &mut t);
            assert!(!t.attached);
        }
        t.cpu.set_pc(entries().thread);
        let before = RegContext::capture(&t.cpu);
        observe_resume(p, &mut t);
        assert!(t.attached && t.frames.is_empty());
        assert_eq!(RegContext::capture(&t.cpu).bytes(), before.bytes());
        p.native = None;
        t.attached = false;
        observe_resume(p, &mut t);
        assert!(!t.attached);
    }
}

#[test]
fn native_start_only_skip_loader_init_bypasses_the_initial_process_gate_all_abis() {
    for arch in WinArch::ALL {
        for flags in [0, 2, 4, 6, 0x20, 0x22, 0x24, 0x26] {
            let (mut process, mut main) = fixture(arch);
            let p = process.state_mut();
            let peer =
                super::super::thread::create_sized(p, 0x52000, 0x1234, 0, 0, 0, flags).unwrap();
            let tid = main.tid;
            main.cpu.set_pc(entries().loader);
            p.native = Some(runtime(Some(entries())));
            p.threads.insert(tid, main);
            assert_eq!(
                super::super::sched::test_startup_selection(p, tid),
                Some(if flags & 0x20 != 0 { peer } else { tid }),
                "{arch}/{flags:#x}"
            );
            assert!(!p.threads[&peer].attached);
            assert!(!p.threads[&tid].attached);
        }
    }
}

#[test]
fn native_start_resume_releases_initial_process_gate_without_attaching_peers_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut main) = fixture(arch);
        let p = process.state_mut();
        let peer = super::super::thread::create(p, 0x52000, 0x1234, 0, false).unwrap();
        let tid = main.tid;
        main.cpu.set_pc(entries().loader);
        p.native = Some(runtime(Some(entries())));
        p.threads.insert(tid, main);
        assert_eq!(
            super::super::sched::test_startup_selection(p, tid),
            Some(tid)
        );
        let mut main = p.threads.remove(&tid).unwrap();
        main.cpu.set_pc(entries().thread);
        observe_resume(p, &mut main);
        p.threads.insert(tid, main);
        assert_eq!(
            super::super::sched::test_startup_selection(p, tid),
            Some(peer)
        );
        assert!(!p.threads[&peer].attached);
        assert!(p.threads.values().all(|t| t.frames.is_empty()));
    }
}

#[cfg(windows)]
#[test]
fn native_start_installed_process_has_cold_peb_and_loader_entry_before_first_instruction() {
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let arches = match host {
        WinArch::Arm64 => vec![host, WinArch::X64, WinArch::X86],
        WinArch::X64 => vec![host, WinArch::X86],
        WinArch::X86 => vec![host],
    };
    for arch in arches {
        let mut config =
            WindowsConfig::embedded("C:\\native-startup.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let process = WindowsProcess::spawn_image(config, image(arch).to_vec()).unwrap();
        let p = process.state();
        let o = offsets(arch);
        let t = p.threads.values().next().unwrap();
        if arch == WinArch::X64
            && p.native.as_ref().unwrap().object_namespace.native_machine == Some(0xaa64)
        {
            use crate::isa::x86_64::X86UserSegment;
            let cpu = t.cpu.x86().unwrap().vcpu();
            for (segment, expected) in [
                (X86UserSegment::Cs, 0x33),
                (X86UserSegment::Ss, 0x2b),
                (X86UserSegment::Ds, 0x2b),
                (X86UserSegment::Es, 0x2b),
                (X86UserSegment::Fs, 0x53),
                (X86UserSegment::Gs, 0x2b),
            ] {
                assert_eq!(cpu.user_selector(segment), expected);
            }
            assert_eq!(cpu.fs_base(), 0);
            assert_eq!(cpu.gs_base(), t.teb);
            assert_eq!(p.space.u64(p.peb + 0x338).unwrap(), p.peb + 0x7d8);
            assert_eq!(
                p.space.bytes(p.peb + 0x7d8, 32).unwrap(),
                [
                    0, 0, 0, 0, 0x64, 0xaa, 0x64, 0x86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]
            );
        }
        assert_eq!(p.space.ptr(p.peb + o.peb_process_heap, o.ptr).unwrap(), 0);
        assert_eq!(p.space.ptr(p.peb + o.peb_ldr, o.ptr).unwrap(), 0);
        assert_eq!(p.space.ptr(t.teb + o.teb_tls_pointer, o.ptr).unwrap(), 0);
        assert!(t.tls_blocks.is_empty());
        assert_ne!(p.process_heap, 0);
        let entries = p.native.as_ref().unwrap().startup.unwrap();
        assert_eq!(t.cpu.pc(), entries.loader);
        assert!(!t.attached && t.frames.is_empty());
        let context_arch = kernel_arch(p);
        let saved = RegContext::read(&p.space, context_arch, context_address(p, t)).unwrap();
        assert_eq!(saved.pc(), entries.thread);
        assert_eq!(
            saved.gpr(match context_arch {
                WinArch::X86 => 3,
                WinArch::X64 => 2,
                WinArch::Arm64 => 1,
            }),
            p.peb
        );
    }
}

#[test]
fn arm64_kernel_start_uses_native_context_and_instruction_entry_for_amd64() {
    for main in [false, true] {
        let (mut process, mut t) = fixture(WinArch::X64);
        let p = process.state_mut();
        let mut native = runtime(None);
        native.object_namespace.native_machine = Some(0xaa64);
        p.native = Some(native);
        t.cpu.enable_arm64ec().unwrap();
        let before = RegContext::capture(&t.cpu);
        enter(p, &mut t.cpu, main, entries()).unwrap();
        let address = t.cpu.gpr(1);
        let saved = RegContext::read(&p.space, WinArch::Arm64, address).unwrap();
        assert_eq!(saved.flags(), 0x0040_000f);
        assert_eq!(saved.pc(), entries().thread);
        assert_eq!(saved.sp(), before.sp());
        assert_eq!(saved.gpr(0), before.gpr(1));
        assert_eq!(saved.gpr(1), if main { p.peb } else { before.gpr(2) });
        assert_eq!(saved.gpr(18), t.teb);
        assert_eq!(t.cpu.instruction_arch(), WinArch::Arm64);
        assert_eq!(t.cpu.sp() % 16, 0);
        assert_eq!(t.cpu.pc(), entries().loader);
        assert_eq!(t.cpu.call_gpr(0), address);
        assert_eq!(t.cpu.call_gpr(1), entries().module);
        assert_eq!(t.cpu.call_gpr(30), 0);
        assert!(address + RegContext::size(WinArch::Arm64) as u64 <= saved.sp());
    }
}

#[test]
fn native_kernel_entry_uses_owned_redirection_and_rejects_changed_or_wrong_isa_targets() {
    use crate::user::image::pe::hybrid::{CodeKind, CodeRange, HybridMetadata, Redirection};
    use std::sync::Arc;
    let (mut process, _) = fixture(WinArch::X64);
    let p = process.state_mut();
    let index = p.modules.by_name("ntdll.dll").unwrap();
    let module = &mut p.modules.list[index];
    assert!(module.size > 0x2100);
    module.kind = ModuleKind::Native;
    let base = module.base;
    let mut metadata = HybridMetadata {
        version: 2,
        code: vec![
            CodeRange {
                start: 0x1000,
                end: 0x1100,
                kind: CodeKind::Amd64,
            },
            CodeRange {
                start: 0x2000,
                end: 0x2100,
                kind: CodeKind::Arm64Ec,
            },
        ],
        entries: Vec::new(),
        redirections: vec![Redirection {
            source: 0x1000,
            destination: 0x2000,
        }],
        dispatch_slots: [0; 8],
        alternate_entry: 0,
    };
    module.hybrid = Some(Arc::new(metadata.clone()));
    let mut bytes = vec![0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x20, 0x55, 0x5d, 0xe9];
    bytes.extend_from_slice(&(0x2000i32 - 0x1000 - 14).to_le_bytes());
    p.vm.poke(base + 0x1000, &bytes).unwrap();
    assert_eq!(kernel_entry(p, base + 0x1000), Ok(base + 0x2000));
    assert_eq!(kernel_entry(p, base + 0x2000), Ok(base + 0x2000));
    bytes[0] = 0x90;
    p.vm.poke(base + 0x1000, &bytes).unwrap();
    assert_eq!(
        kernel_entry(p, base + 0x1000),
        Err(STATUS_INVALID_IMAGE_FORMAT)
    );
    bytes[0] = 0x48;
    p.vm.poke(base + 0x1000, &bytes).unwrap();
    metadata.code[1].kind = CodeKind::Amd64;
    p.modules.list[index].hybrid = Some(Arc::new(metadata));
    assert_eq!(
        kernel_entry(p, base + 0x1000),
        Err(STATUS_INVALID_IMAGE_FORMAT)
    );
}

#[test]
fn exception_kernel_metadata_entry_accepts_noncanonical_wrappers_and_rejects_invalid_targets() {
    use crate::user::image::pe::hybrid::{CodeKind, CodeRange, HybridMetadata, Redirection};
    use std::sync::Arc;
    let (mut process, _) = fixture(WinArch::X64);
    let p = process.state_mut();
    let index = p.modules.by_name("ntdll.dll").unwrap();
    let module = &mut p.modules.list[index];
    module.kind = ModuleKind::Native;
    let base = module.base;
    let size = module.size;
    let mut metadata = HybridMetadata {
        version: 2,
        code: vec![
            CodeRange {
                start: 0x1000,
                end: 0x1100,
                kind: CodeKind::Amd64,
            },
            CodeRange {
                start: 0x2000,
                end: 0x2100,
                kind: CodeKind::Arm64Ec,
            },
        ],
        entries: vec![],
        redirections: vec![Redirection {
            source: 0x1000,
            destination: 0x2000,
        }],
        dispatch_slots: [0; 8],
        alternate_entry: 0,
    };
    p.modules.list[index].hybrid = Some(Arc::new(metadata.clone()));
    p.vm.poke(base + 0x1000, &[0xfc; 14]).unwrap();
    assert_eq!(kernel_export_entry(p, base + 0x1000), Ok(base + 0x2000));
    assert_eq!(
        kernel_entry(p, base + 0x1000),
        Err(STATUS_INVALID_IMAGE_FORMAT)
    );
    assert_eq!(
        kernel_export_entry(p, base + 0x1001),
        Err(STATUS_INVALID_IMAGE_FORMAT)
    );
    metadata.code[1].kind = CodeKind::Amd64;
    p.modules.list[index].hybrid = Some(Arc::new(metadata.clone()));
    assert_eq!(
        kernel_export_entry(p, base + 0x1000),
        Err(STATUS_INVALID_IMAGE_FORMAT)
    );
    metadata.code[1].kind = CodeKind::Arm64Ec;
    metadata.redirections[0].destination = 0x2001;
    p.modules.list[index].hybrid = Some(Arc::new(metadata.clone()));
    assert_eq!(
        kernel_export_entry(p, base + 0x1000),
        Err(STATUS_INVALID_IMAGE_FORMAT)
    );
    metadata.redirections[0].destination = size as u32;
    p.modules.list[index].hybrid = Some(Arc::new(metadata.clone()));
    assert_eq!(
        kernel_export_entry(p, base + 0x1000),
        Err(STATUS_INVALID_IMAGE_FORMAT)
    );
    metadata.redirections[0].destination = 0x2000;
    p.modules.list[index].hybrid = Some(Arc::new(metadata));
    p.vm.protect(base + 0x2000, 4096, prot::READONLY).unwrap();
    assert_eq!(
        kernel_export_entry(p, base + 0x1000),
        Err(STATUS_INVALID_IMAGE_FORMAT)
    );
    p.modules.list[index].hybrid = None;
    assert_eq!(
        kernel_export_entry(p, base + 0x1000),
        Err(STATUS_INVALID_IMAGE_FORMAT)
    );
}
