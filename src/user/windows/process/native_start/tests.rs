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

fn fixture(arch: WinArch) -> (WindowsProcess, Thread) {
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
    }
}

fn runtime(entries: Option<EntryPoints>) -> NativeRuntime {
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
        nls: None,
        startup: entries,
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
    let arches = if host == WinArch::X86 {
        vec![host]
    } else {
        vec![host, WinArch::X86]
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
        assert_eq!(p.space.ptr(p.peb + o.peb_process_heap, o.ptr).unwrap(), 0);
        assert_eq!(p.space.ptr(p.peb + o.peb_ldr, o.ptr).unwrap(), 0);
        assert_eq!(p.space.ptr(t.teb + o.teb_tls_pointer, o.ptr).unwrap(), 0);
        assert!(t.tls_blocks.is_empty());
        assert_ne!(p.process_heap, 0);
        let entries = p.native.as_ref().unwrap().startup.unwrap();
        assert_eq!(t.cpu.pc(), entries.loader);
        assert!(!t.attached && t.frames.is_empty());
        let saved = RegContext::read(&p.space, arch, context_address(p, t)).unwrap();
        assert_eq!(saved.pc(), entries.thread);
        assert_eq!(
            saved.gpr(match arch {
                WinArch::X86 => 3,
                WinArch::X64 => 2,
                WinArch::Arm64 => 1,
            }),
            p.peb
        );
    }
}
