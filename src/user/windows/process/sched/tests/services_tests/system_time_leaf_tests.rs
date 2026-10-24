//! Execute the selected installed NTDLL leaf, including x86 RET 4 cleanup.
use super::*;
use crate::user::windows::{
    arch::CpuStop,
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemTime(output: *mut i64) -> i32;
}

fn native_time() -> u64 {
    let mut ticks = 0i64;
    // SAFETY: one initialized, aligned, private host LARGE_INTEGER.
    assert_eq!(unsafe { NtQuerySystemTime(&mut ticks) }, 0);
    u64::try_from(ticks).unwrap()
}

fn native_unaligned_status() -> u32 {
    #[repr(align(8))]
    struct Scratch([u8; 24]);
    let mut scratch = Scratch([0xa5; 24]);
    // SAFETY: eight writable bytes in owned scratch, deliberately unaligned;
    // no Rust reference or guest operand crosses the native ABI.
    let status = unsafe { NtQuerySystemTime(scratch.0.as_mut_ptr().add(1).cast()) } as u32;
    assert!(matches!(
        status,
        STATUS_SUCCESS | STATUS_DATATYPE_MISALIGNMENT
    ));
    assert_eq!(scratch.0[0], 0xa5);
    assert_eq!(scratch.0[9..], [0xa5; 15]);
    if status != STATUS_SUCCESS {
        assert_eq!(scratch.0, [0xa5; 24]);
    }
    status
}
fn location(p: &Proc, pc: u64, resume: u64) -> String {
    if pc == resume {
        return "return-trap".into();
    }
    match p.modules.by_address(pc) {
        Some((_, module)) => format!("{}+{:#x}", module.name, pc - module.base),
        None => "outside-module".into(),
    }
}

fn stop_kind(stop: &CpuStop) -> &'static str {
    match stop {
        CpuStop::Fault(_) => "fault",
        CpuStop::X86Event(_) => "x86-event",
        CpuStop::X86Syscall { .. } => "x86-syscall",
        CpuStop::Svc { .. } => "svc",
        CpuStop::Brk { .. } => "brk",
        CpuStop::Undefined { .. } => "undefined",
        CpuStop::Yield => "yield",
        CpuStop::Internal(_) => "internal",
    }
}

fn outcome_kind(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Continue => "continue",
        Outcome::Yield => "yield",
        Outcome::Park => "park",
        Outcome::ThreadExit(_) => "thread-exit",
        Outcome::ProcessExit(_) => "process-exit",
        Outcome::ThreadTerminate(_) => "thread-terminate",
        Outcome::ProcessTerminate(_) => "process-terminate",
        Outcome::Fail(_) => "fail",
    }
}

fn stop_detail(p: &Proc, t: &Thread, stop: &CpuStop) -> String {
    let number = match stop {
        CpuStop::X86Syscall { .. } => t.cpu.gpr(0) as u32,
        CpuStop::Svc { imm, .. } => u32::from(*imm),
        CpuStop::Fault(fault) => {
            return format!("fault/{:?}/{:?}", fault.access, fault.kind);
        }
        _ => return stop_kind(stop).into(),
    };
    let name = p
        .modules
        .nt_services
        .as_ref()
        .and_then(|(_, table)| table.name(p.arch, number))
        .unwrap_or("unadmitted");
    format!("{}/{name}/{number:#x}", stop_kind(stop))
}

/// A failed fixture stays failed. This bounded continuation only measures the
/// exception path beyond its original 32 slices; it cannot accept that call.
fn failed_return_probe(p: &mut Proc, t: &mut Thread, sp: u64, resume: u64, argc: usize) -> String {
    const SLICES: usize = 512;
    const RECORDS: usize = 64;
    let expected_sp = sp
        + match p.arch {
            WinArch::X86 => 4 + argc as u64 * 4,
            WinArch::X64 => 8,
            WinArch::Arm64 => 0,
        };
    let mut trace = std::collections::VecDeque::new();
    let mut internal_returns = 0;
    for slice in 0..SLICES {
        let start = location(p, t.cpu.pc(), resume);
        let boundary = t.cpu.run(64);
        if t.cpu.pc() == resume && t.frames.is_empty() && t.cpu.sp() == expected_sp {
            return format!(
                "completed_after_extra_slices={} status={:#010x} internal_callback_returns={internal_returns} frames=0 sp_delta={} trace={trace:#?}",
                slice + 1,
                t.cpu.gpr(0) as u32,
                i128::from(t.cpu.sp()) - i128::from(sp),
            );
        }
        if t.cpu.pc() == resume {
            internal_returns += 1;
        }
        let stopped = location(p, t.cpu.pc(), resume);
        let detail = stop_detail(p, t, &boundary);
        let code = p
            .modules
            .by_address(t.cpu.pc())
            .filter(|(_, module)| {
                t.cpu.pc().checked_add(8).is_some_and(|end| {
                    module
                        .base
                        .checked_add(module.size)
                        .is_some_and(|limit| end <= limit)
                })
            })
            .and_then(|_| p.space.bytes(t.cpu.pc(), 8).ok());
        let outcome = handle_stop(p, t, boundary);
        // Keep the first half and a rolling final half. Intermediate execution
        // cannot make diagnostics grow beyond 64 records.
        if trace.len() == RECORDS {
            trace.remove(RECORDS / 2);
        }
        trace.push_back(format!(
            "extra_slice={slice} start={start} stop={stopped}/{detail} code={code:02x?} next={} outcome={} frames={} sp_delta={}",
            location(p, t.cpu.pc(), resume),
            outcome_kind(&outcome),
            t.frames.len(),
            i128::from(t.cpu.sp()) - i128::from(sp),
        ));
        if !matches!(outcome, Outcome::Continue | Outcome::Yield) {
            return format!(
                "stopped_after_extra_slices={} internal_callback_returns={internal_returns} trace={trace:#?}",
                slice + 1,
            );
        }
    }
    format!(
        "exhausted_extra_slices={SLICES} internal_callback_returns={internal_returns} trace={trace:#?}"
    )
}

fn leaf(p: &mut Proc, t: &mut Thread, library: &str, name: &str, case: &str, args: &[u64]) -> u32 {
    let m = loader::load_dll(p, library).unwrap();
    let entry = loader::lookup(p, m, &SymRef::Name(name.as_bytes().to_vec(), None))
        .unwrap()
        .unwrap();
    let saved_sp = t.cpu.sp();
    let sp = saved_sp - 128;
    let resume = p.traps.callback_return();
    t.cpu.set_sp(sp);
    t.cpu.set_pc(entry);
    for (i, &value) in args.iter().enumerate() {
        match p.arch {
            WinArch::X86 => p.space.w32(sp + 4 + i as u64 * 4, value as u32).unwrap(),
            WinArch::X64 if i < 4 => t.cpu.set_gpr([1, 2, 8, 9][i], value),
            WinArch::X64 => p.space.w64(sp + 40 + (i - 4) as u64 * 8, value).unwrap(),
            WinArch::Arm64 if i < 8 => t.cpu.set_gpr(i, value),
            WinArch::Arm64 => p.space.w32(sp + (i - 8) as u64 * 8, value as u32).unwrap(),
        }
    }
    match p.arch {
        WinArch::X86 => p.space.w32(sp, resume as u32).unwrap(),
        WinArch::X64 => p.space.w64(sp, resume).unwrap(),
        WinArch::Arm64 => t.cpu.set_gpr(30, resume),
    }
    let mut returned = false;
    let mut trace = Vec::new();
    for slice in 0..32 {
        let start = location(p, t.cpu.pc(), resume);
        let boundary = t.cpu.run(64);
        let stopped = location(p, t.cpu.pc(), resume);
        let stop = stop_kind(&boundary);
        if t.cpu.pc() == resume {
            returned = true;
            break;
        }
        let outcome = handle_stop(p, t, boundary);
        trace.push(format!(
            "slice={slice} start={start} stop={stopped}/{stop} next={} outcome={} frames={} sp_delta={}",
            location(p, t.cpu.pc(), resume),
            outcome_kind(&outcome),
            t.frames.len(),
            i128::from(t.cpu.sp()) - i128::from(sp),
        ));
        assert!(
            matches!(outcome, Outcome::Continue | Outcome::Yield),
            "{name} {} guest_build{} case={case} entry_sp_mod16={} trace={trace:#?}",
            p.arch,
            p.cfg.version.build,
            sp % 16,
        );
    }
    if !returned {
        let probe = failed_return_probe(p, t, sp, resume, args.len());
        panic!(
            "{name} {} guest_build{} case={case} entry_sp_mod16={} exceeded32slicesof64instructions trace={trace:#?} diagnostic_continuation={probe}",
            p.arch,
            p.cfg.version.build,
            sp % 16,
        );
    }
    assert!(t.frames.is_empty());
    assert_eq!(
        t.cpu.sp(),
        sp + match p.arch {
            WinArch::X86 => 4 + args.len() as u64 * 4,
            WinArch::X64 => 8,
            WinArch::Arm64 => 0,
        }
    );
    t.cpu.set_sp(saved_sp);
    t.cpu.gpr(0) as u32
}
#[test]
fn native_system_time_installed_leaf_uses_host_clock_and_preserves_guards() {
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
        let bytes: &[u8] = match arch {
            WinArch::Arm64 => include_bytes!(
                "../../../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe"
            ),
            WinArch::X64 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::X86 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
        };
        let mut config =
            WindowsConfig::embedded("C:\\system-time.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, bytes.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&tid).unwrap();
        let base = scratch(p);
        let last_error = thread.teb + layout::offsets(arch).teb_last_error;
        p.space.w32(last_error, 0x4A2E19F7).unwrap();
        let before = native_time();
        assert_eq!(
            leaf(
                p,
                &mut thread,
                "ntdll.dll",
                "NtQuerySystemTime",
                "aligned4",
                &[base + 4]
            ),
            STATUS_SUCCESS
        );
        let after = native_time();
        let observed = p.space.u64(base + 4).unwrap();
        let module = p.modules.by_name("ntdll.dll").unwrap();
        let entry = loader::lookup(
            p,
            module,
            &SymRef::Name(b"NtQuerySystemTime".to_vec(), None),
        )
        .unwrap()
        .unwrap();
        assert!(
            (before..=after).contains(&observed),
            "{arch}/build{}: FILETIME ticks before={before} observed={observed} after={after}; installed leaf={:02x?}",
            p.cfg.version.build,
            p.space.bytes(entry, 48).unwrap()
        );
        assert_eq!(p.space.u32(last_error).unwrap(), 0x4A2E19F7);
        p.vm.poke(base + 4092, &[0xA5; 8]).unwrap();
        p.vm.protect(base + 4096, 4096, prot::READWRITE | prot::GUARD)
            .unwrap();
        let expected_unaligned = native_unaligned_status();
        assert_eq!(
            leaf(
                p,
                &mut thread,
                "ntdll.dll",
                "NtQuerySystemTime",
                "split-guard4",
                &[base + 4092]
            ),
            STATUS_GUARD_PAGE_VIOLATION
        );
        assert_eq!(p.vm.query(base + 4096).unwrap().protect, prot::READWRITE);
        assert_eq!(p.space.bytes(base + 4092, 8).unwrap(), [0xA5; 8]);
        assert_eq!(
            leaf(
                p,
                &mut thread,
                "ntdll.dll",
                "NtQuerySystemTime",
                "unaligned1",
                &[base + 1]
            ),
            expected_unaligned
        );
        assert_eq!(native_unaligned_status(), expected_unaligned);
    }
}
