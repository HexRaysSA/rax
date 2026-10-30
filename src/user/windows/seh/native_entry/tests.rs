use super::*;
use crate::user::image::pe::DataDirectory;
use crate::user::windows::loader::{ModuleKind, apiset_schema::ApiSetSchema};
use crate::user::windows::memory::{mem, prot};
use crate::user::windows::native::NativeRuntime;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

fn fixture(arch: WinArch) -> (WindowsProcess, Thread) {
    let image: &[u8] = match arch {
        WinArch::X86 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
        }
        WinArch::X64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
        }
        WinArch::Arm64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
        }
    };
    let mut config = WindowsConfig::embedded("C:\\exception.exe", vec![], vec![], 4096).unwrap();
    config.arena_bytes = 64 << 20;
    let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let thread = p.threads.remove(&tid).unwrap();
    (process, thread)
}

fn native_runtime() -> NativeRuntime {
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
        startup: None,
        gui: Default::default(),
        code_integrity: Err("controlled fixture".into()),
        code_integrity_policy: Err("code integrity policy not captured in this fixture".into()),
    }
}

// A small independent PE export directory exercises the production resolver.
// It contains no implementation of exception dispatch or host-derived metadata.
fn dispatcher(p: &mut Proc) -> u64 {
    let base =
        p.vm.allocate(
            None,
            4096,
            mem::RESERVE | mem::COMMIT,
            prot::EXECUTE_READWRITE,
        )
        .unwrap()
        .0;
    let fields = [
        (0x50, 1),
        (0x54, 1),
        (0x58, 1),
        (0x5c, 0x100),
        (0x60, 0x104),
        (0x64, 0x108),
        (0x100, 0x400),
        (0x104, 0x120),
    ];
    for (offset, value) in fields {
        p.space.w32(base + offset, value).unwrap();
    }
    p.space.w16(base + 0x108, 0).unwrap();
    p.space
        .wr(base + 0x120, b"KiUserExceptionDispatcher\0")
        .unwrap();
    if p.arch == WinArch::X64 {
        p.space.w32(base + 0x300, 0x400).unwrap();
        p.space.w32(base + 0x304, 0x500).unwrap();
        p.space.w32(base + 0x308, 0x340).unwrap();
        p.space
            .wr(base + 0x340, &[1, 0, 3, 0, 0, 1, 178, 0, 0, 10])
            .unwrap();
    }
    let index = p.modules.by_name("ntdll.dll").unwrap();
    let module = &mut p.modules.list[index];
    module.kind = ModuleKind::Native;
    module.base = base;
    module.size = 4096;
    module.exports = DataDirectory {
        rva: 0x40,
        size: 0x100,
    };
    if p.arch == WinArch::X64 {
        module.pdata = DataDirectory {
            rva: 0x300,
            size: 12,
        };
    }
    base + 0x400
}

#[test]
fn native_entry_matches_measured_frame_geometry_and_preserves_legacy_context() {
    for arch in WinArch::ALL {
        let (_process, thread) = fixture(arch);
        let mut context = RegContext::capture(&thread.cpu);
        let original_sp = context.sp();
        let record = ExceptionRecord::new(0xC000_0005, context.pc(), vec![1, 0x8765_4000]);
        for residue in 0..16 {
            context.set_sp((original_sp & !15) + residue);
            let frame = Frame::new(&record, &context).unwrap();
            let (context_offset, record_offset, length, expected_residue) = match arch {
                WinArch::X86 => (88, 8, 828, 12),
                WinArch::X64 => (0, 1264, 1472, 0),
                WinArch::Arm64 => (0, 944, 1104, 0),
            };
            assert_eq!(frame.sp % 16, expected_residue);
            assert_eq!(frame.bytes.len(), length);
            assert!(
                frame.sp + length as u64
                    <= context.sp() - if arch == WinArch::Arm64 { 16 } else { 0 }
            );
            assert_eq!(
                &frame.bytes[context_offset..context_offset + RegContext::size(arch)],
                context.bytes()
            );
            assert_eq!(
                &frame.bytes[record_offset..record_offset + 4],
                &0xC000_0005u32.to_le_bytes()
            );
            let extension = context_offset + RegContext::size(arch);
            let word = |at| u32::from_le_bytes(frame.bytes[at..at + 4].try_into().unwrap());
            assert_eq!(word(extension) as i32, -(RegContext::size(arch) as i32));
            assert_eq!(word(extension + 4) as usize, length - context_offset);
            assert_eq!(word(extension + 12) as usize, RegContext::size(arch));
            assert_eq!(word(extension + 20), 0);
            if arch == WinArch::X86 {
                assert_eq!(u64::from(word(0)), frame.sp + 8);
                assert_eq!(u64::from(word(4)), frame.sp + 88);
                assert_eq!((frame.sp + 88 + 0xcc) % 16, 0);
            }
            if arch == WinArch::X64 {
                let machine: Vec<u64> = frame.bytes[1424..1464]
                    .chunks_exact(8)
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                    .collect();
                assert_eq!(machine[0], context.pc());
                assert_eq!(machine[2], u64::from(context.flags_register()));
                assert_eq!(machine[3], context.sp());
                assert_eq!(
                    machine[1],
                    u64::from(u16::from_le_bytes(
                        context.bytes()[0x38..0x3a].try_into().unwrap()
                    ))
                );
                assert_eq!(
                    machine[4],
                    u64::from(u16::from_le_bytes(
                        context.bytes()[0x42..0x44].try_into().unwrap()
                    ))
                );
            }
        }
    }
}

#[test]
fn native_entry_routes_through_selected_executable_ntdll_without_a_synthetic_frame() {
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch);
        let p = process.state_mut();
        let entry = dispatcher(p);
        p.native = Some(native_runtime());
        p.seh.veh.push((1, 1));
        let before = RegContext::capture(&thread.cpu);
        let record = ExceptionRecord::new(0xC000_0005, before.pc(), vec![0, 1]);
        assert_eq!(
            super::super::raise(p, &mut thread, record, before.clone()),
            Outcome::Continue
        );
        assert_eq!(thread.cpu.pc(), entry);
        assert!(thread.frames.is_empty());
        let mut after = RegContext::capture(&thread.cpu);
        after.set_sp(before.sp());
        after.set_pc(before.pc());
        assert_eq!(after, before);
    }
}

#[test]
fn native_entry_preflights_complete_stack_before_writing_or_changing_cpu() {
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch);
        let p = process.state_mut();
        let entry = dispatcher(p);
        let page = thread.stack_base - 4096;
        p.space.wr(page, &[0xa5; 4096]).unwrap();
        p.vm.protect(page, 4096, prot::READONLY).unwrap();
        let before = RegContext::capture(&thread.cpu);
        let record = ExceptionRecord::new(0xC000_0005, before.pc(), vec![]);
        let frame = Frame::new(&record, &before).unwrap();
        assert_eq!(
            publish(p, &mut thread, &frame, entry),
            Err(STATUS_BAD_STACK)
        );
        assert_eq!(RegContext::capture(&thread.cpu), before);
        assert_eq!(p.space.bytes(page, 4096).unwrap(), [0xa5; 4096]);
    }
}

#[test]
fn native_entry_rejects_underflow_and_uncaptured_xstate() {
    for arch in WinArch::ALL {
        let (_, thread) = fixture(arch);
        let mut context = RegContext::capture(&thread.cpu);
        let record = ExceptionRecord::new(0xC000_0005, context.pc(), vec![]);
        context.set_sp(0);
        assert!(matches!(
            Frame::new(&record, &context),
            Err(STATUS_BAD_STACK)
        ));
        context.set_sp(0x10000);
        context.set_flags(context.flags() | 0x40);
        assert!(matches!(
            Frame::new(&record, &context),
            Err(STATUS_NOT_SUPPORTED)
        ));
    }
}

#[test]
fn native_entry_rejects_nonexecutable_or_builtin_dispatcher() {
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch);
        let p = process.state_mut();
        let before = RegContext::capture(&thread.cpu);
        let record = ExceptionRecord::new(0xC000_0005, before.pc(), vec![]);
        assert!(matches!(
            raise(p, &mut thread, record.clone(), before.clone()),
            Outcome::Fail(_)
        ));
        let entry = dispatcher(p);
        p.vm.protect(entry & !4095, 4096, prot::READWRITE).unwrap();
        assert!(matches!(
            raise(p, &mut thread, record, before.clone()),
            Outcome::Fail(_)
        ));
        assert_eq!(RegContext::capture(&thread.cpu), before);
    }
}

#[test]
fn native_entry_rejects_wrapper_and_wrong_machine_frame_without_publication() {
    let (mut process, mut thread) = fixture(WinArch::X64);
    let p = process.state_mut();
    let entry = dispatcher(p);
    let base = entry - 0x400;
    let before = RegContext::capture(&thread.cpu);
    let record = ExceptionRecord::new(0xC000_0005, before.pc(), vec![]);
    let scratch = before.sp() - 2048;
    p.space.wr(scratch, &[0xa5; 2048]).unwrap();
    for (offset, bad, original) in [(0x342, 0, 3), (0x346, 177, 178), (0x349, 26, 10)] {
        p.space.w8(base + offset, bad).unwrap();
        assert!(matches!(
            raise(p, &mut thread, record.clone(), before.clone()),
            Outcome::Fail(_)
        ));
        assert_eq!(RegContext::capture(&thread.cpu), before);
        assert_eq!(p.space.bytes(scratch, 2048).unwrap(), [0xa5; 2048]);
        p.space.w8(base + offset, original).unwrap();
    }
}

#[cfg(windows)]
#[test]
fn native_entry_installed_ntdll_runs_hardware_fault_veh_and_context_continuation() {
    use crate::user::windows::process::{ExitStatus, RunStatus};
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

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
        let image: &[u8] = match arch {
            WinArch::X86 => include_bytes!(
                "../../../../../tests/fixtures/user/windows/native_exception_entry/bin/x86/fault.exe"
            ),
            WinArch::X64 => include_bytes!(
                "../../../../../tests/fixtures/user/windows/native_exception_entry/bin/x64/fault.exe"
            ),
            WinArch::Arm64 => include_bytes!(
                "../../../../../tests/fixtures/user/windows/native_exception_entry/bin/arm64/fault.exe"
            ),
        };
        let mut config =
            WindowsConfig::embedded("C:\\native-fault.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        config.slice_insns = 4096;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let cancelled = AtomicBool::new(false);
        let mut completed = false;
        // At most 2^14 turns of 2^12 instructions: 2^26 guest attempts.
        for _ in 0..16384 {
            assert!(
                Instant::now() < deadline,
                "{arch}: native fault fixture deadline"
            );
            match process.run_slice(1, &cancelled) {
                RunStatus::Complete(status) => {
                    assert_eq!(
                        status,
                        ExitStatus::Exited(0),
                        "{arch}: native fault fixture"
                    );
                    completed = true;
                    break;
                }
                RunStatus::BudgetExhausted => {}
                status => panic!("{arch}: native fault fixture stopped: {status:?}"),
            }
        }
        assert!(completed, "{arch}: native fault fixture instruction budget");
        assert!(
            process.state().seh.veh.is_empty(),
            "native registration must remain owned by RTL"
        );
    }
}
