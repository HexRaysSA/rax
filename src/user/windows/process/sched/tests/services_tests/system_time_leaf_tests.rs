//! Execute the selected installed NTDLL leaf, including x86 RET 4 cleanup.
use super::*;
use crate::user::windows::{
    arch::CpuStop,
    context::{ExceptionRecord, RegContext},
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

fn outcome_detail(outcome: &Outcome) -> String {
    match outcome {
        Outcome::ThreadExit(code)
        | Outcome::ProcessExit(code)
        | Outcome::ThreadTerminate(code)
        | Outcome::ProcessTerminate(code) => {
            format!("{}({code:#010x})", outcome_kind(outcome))
        }
        Outcome::Fail(reason) => format!("fail({reason})"),
        _ => outcome_kind(outcome).into(),
    }
}

/// Extra state around a stop that the raw kind does not carry: the faulting
/// access and region, or the record a native raise carries.
fn stop_extra(p: &Proc, t: &Thread, stop: &CpuStop, sp: u64, resume: u64) -> String {
    if let CpuStop::Fault(fault) = stop {
        let region =
            p.vm.query(fault.addr)
                .map(|region| format!("{:#x}", region.protect))
                .unwrap_or_else(|| "unmapped".into());
        let bytes = p
            .space
            .bytes(fault.pc, 16)
            .map(|bytes| format!("{bytes:02x?}"))
            .unwrap_or_else(|_| "unreadable".into());
        return format!(
            " fault_addr={:#x} region={region} fault_pc_bytes={bytes}",
            fault.addr
        );
    }
    if p.arch == WinArch::X64
        && matches!(stop, CpuStop::X86Syscall { .. })
        && p.modules
            .nt_services
            .as_ref()
            .and_then(|(_, table)| table.name(p.arch, t.cpu.gpr(0) as u32))
            .is_some_and(|name| name == "NtRaiseException")
    {
        return format!(
            " first_chance_low8={} {}",
            t.cpu.gpr(8) as u8,
            exception_detail(p, t.cpu.gpr(10), t.cpu.gpr(2), sp, resume),
        );
    }
    String::new()
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

fn exception_detail(p: &Proc, record: u64, context: u64, sp: u64, resume: u64) -> String {
    let record = match ExceptionRecord::read(&p.space, p.arch, record) {
        Ok(record) => format!(
            "code={:#010x} flags={:#x} address={} nested={} parameters={}",
            record.code,
            record.flags,
            location(p, record.address, resume),
            record.nested != 0,
            record.params.len(),
        ),
        Err(_) => "unreadable-record".into(),
    };
    let context = match RegContext::read(&p.space, p.arch, context) {
        Ok(context) => format!(
            "pc={} sp_delta={}",
            location(p, context.pc(), resume),
            i128::from(context.sp()) - i128::from(sp),
        ),
        Err(_) => "unreadable-context".into(),
    };
    format!("record({record}) context({context})")
}

fn unwind_entry_detail(p: &Proc, t: &Thread, name: &str, sp: u64, resume: u64) -> String {
    if p.arch != WinArch::X64 {
        return name.into();
    }
    let stack_context = || {
        t.cpu
            .sp()
            .checked_add(40)
            .and_then(|address| p.space.u64(address).ok())
            .unwrap_or(0)
    };
    match name {
        "RtlUnwindEx" => format!(
            "{name} target_sp_delta={} target={} return_low32={:#010x} {}",
            i128::from(t.cpu.gpr(1)) - i128::from(sp),
            location(p, t.cpu.gpr(2), resume),
            t.cpu.gpr(9) as u32,
            exception_detail(p, t.cpu.gpr(8), stack_context(), sp, resume),
        ),
        "RtlVirtualUnwind" => format!(
            "{name} control_pc={} {}",
            location(p, t.cpu.gpr(8), resume),
            exception_detail(p, 0, stack_context(), sp, resume),
        ),
        "RtlRestoreContext" => format!(
            "{name} {}",
            exception_detail(p, t.cpu.gpr(2), t.cpu.gpr(1), sp, resume),
        ),
        _ => name.into(),
    }
}

/// A failed fixture stays failed. This bounded continuation measures the
/// exception path beyond the leaf's slice budget; it cannot accept that call.
fn failed_return_probe(p: &mut Proc, t: &mut Thread, sp: u64, resume: u64, argc: usize) -> String {
    const ATTEMPTS: usize = 512 * 64;
    const RECORDS: usize = 64;
    let expected_sp = sp
        + match p.arch {
            WinArch::X86 => 4 + argc as u64 * 4,
            WinArch::X64 => 8,
            WinArch::Arm64 => 0,
        };
    let mut trace = std::collections::VecDeque::new();
    let mut internal_returns = 0;
    let mut entries = Vec::new();
    if let Some(module) = p.modules.by_name("ntdll.dll") {
        for name in ["RtlUnwindEx", "RtlVirtualUnwind", "RtlRestoreContext"] {
            if let Ok(Some(entry)) =
                loader::lookup(p, module, &SymRef::Name(name.as_bytes().to_vec(), None))
            {
                entries.push((entry, name));
            }
        }
    }
    for attempt in 0..ATTEMPTS {
        let entry = entries
            .iter()
            .find(|(entry, _)| *entry == t.cpu.pc())
            .map(|(_, name)| unwind_entry_detail(p, t, name, sp, resume));
        let start = location(p, t.cpu.pc(), resume);
        let boundary = t.cpu.run(1);
        if t.cpu.pc() == resume && t.frames.is_empty() && t.cpu.sp() == expected_sp {
            return format!(
                "completed_after_extra_attempts={} status={:#010x} internal_callback_returns={internal_returns} frames=0 sp_delta={} trace={trace:#?}",
                attempt + 1,
                t.cpu.gpr(0) as u32,
                i128::from(t.cpu.sp()) - i128::from(sp),
            );
        }
        if t.cpu.pc() == resume {
            internal_returns += 1;
        }
        let stopped = location(p, t.cpu.pc(), resume);
        let detail = stop_detail(p, t, &boundary);
        let raised = if p.arch == WinArch::X64 && detail.contains("/NtRaiseException/") {
            format!(
                "first_chance_low8={} {}",
                t.cpu.gpr(8) as u8,
                exception_detail(p, t.cpu.gpr(10), t.cpu.gpr(2), sp, resume),
            )
        } else {
            String::new()
        };
        let record = attempt % 64 == 0 || entry.is_some() || !matches!(&boundary, CpuStop::Yield);
        let code = if record {
            p.modules
                .by_address(t.cpu.pc())
                .filter(|(_, module)| {
                    t.cpu.pc().checked_add(8).is_some_and(|end| {
                        module
                            .base
                            .checked_add(module.size)
                            .is_some_and(|limit| end <= limit)
                    })
                })
                .and_then(|_| p.space.bytes(t.cpu.pc(), 8).ok())
        } else {
            None
        };
        let outcome = handle_stop(p, t, boundary);
        // Keep the first half and a rolling final half. Intermediate execution
        // cannot make diagnostics grow beyond 64 records.
        if record {
            if trace.len() == RECORDS {
                trace.remove(RECORDS / 2);
            }
            trace.push_back(format!(
                "extra_attempt={attempt} entry={entry:?} start={start} stop={stopped}/{detail} {raised} code={code:02x?} next={} outcome={} frames={} sp_delta={}",
                location(p, t.cpu.pc(), resume),
                outcome_kind(&outcome),
                t.frames.len(),
                i128::from(t.cpu.sp()) - i128::from(sp),
            ));
        }
        if !matches!(outcome, Outcome::Continue | Outcome::Yield) {
            return format!(
                "stopped_after_extra_attempts={} internal_callback_returns={internal_returns} trace={trace:#?}",
                attempt + 1,
            );
        }
    }
    format!(
        "exhausted_extra_attempts={ATTEMPTS} internal_callback_returns={internal_returns} trace={trace:#?}"
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
    // A guard-page violation is dispatched through the installed NTDLL's own
    // exception path before the leaf returns, which costs thousands of
    // instructions; the ordinary leaf path completes in a few slices. The
    // budget still fails a runaway loop.
    const SLICES: usize = 512;
    for slice in 0..SLICES {
        let start = location(p, t.cpu.pc(), resume);
        let boundary = t.cpu.run(64);
        let stopped = location(p, t.cpu.pc(), resume);
        let detail = stop_detail(p, t, &boundary);
        let extra = stop_extra(p, t, &boundary, sp, resume);
        if t.cpu.pc() == resume {
            // This harness enters the leaf itself, without an HLE call site.
            // A guest language handler that unwinds to the fault frame resumes
            // it directly (through its own RtlUnwindEx), abandoning the
            // dispatcher's waiting frame. A real callback return prunes such
            // abandoned owners at the trap, so do the same here.
            crate::user::windows::hle::dispatch::prune(t, t.cpu.sp());
            returned = true;
            break;
        }
        let outcome = handle_stop(p, t, boundary);
        trace.push(format!(
            "slice={slice} start={start} stop={stopped}/{detail}{extra} next={} outcome={} frames={} sp_delta={}",
            location(p, t.cpu.pc(), resume),
            outcome_detail(&outcome),
            t.frames.len(),
            i128::from(t.cpu.sp()) - i128::from(sp),
        ));
        if !matches!(outcome, Outcome::Continue | Outcome::Yield) {
            let probe = failed_return_probe(p, t, sp, resume, args.len());
            panic!(
                "{name} {} guest_build{} case={case} entry_sp_mod16={} outcome={} trace={trace:#?} diagnostic_continuation={probe}",
                p.arch,
                p.cfg.version.build,
                sp % 16,
                outcome_detail(&outcome),
            );
        }
    }
    if !returned {
        let probe = failed_return_probe(p, t, sp, resume, args.len());
        panic!(
            "{name} {} guest_build{} case={case} entry_sp_mod16={} exceeded{SLICES}slicesof64instructions trace={trace:#?} diagnostic_continuation={probe}",
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
    // libtest captures this dispatch trace and prints it only on failure.
    // SAFETY: no test reads the variable concurrently.
    unsafe { std::env::set_var("RAX_SEH_TRACE", "1") };
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
