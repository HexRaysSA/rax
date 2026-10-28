//! Mach debug-state stepping is independent of BSD PT_STEP.

use super::*;
use crate::user::darwin::mach::suspend::Hold;
use crate::user::darwin::thread_status;

fn arm(process: &mut DarwinProcess, enabled: bool) -> u64 {
    let (&tid, thread) = process.proc.threads.iter_mut().next().unwrap();
    let mut debug = vec![0; thread_status::arm::DEBUG_STATE64_COUNT as usize];
    debug[128] = u32::from(enabled);
    thread_status::set(
        &mut thread.cpu,
        &mut thread.mach.debug_state,
        thread_status::arm::DEBUG_STATE64,
        &debug,
    )
    .unwrap();
    tid
}

fn assert_step(process: &mut DarwinProcess, tid: u64, pc: u64) {
    assert!(matches!(
        process.run_slice(16, &AtomicBool::new(false)),
        RunStatus::Complete(ExitStatus::Signaled { signo: signal::SIGTRAP, pc: stopped, .. })
            if stopped == pc + 4
    ));
    let thread = &process.proc.threads[&tid];
    // The static fixture starts with MOVZ X16,#1; MOVZ X0,#37; SVC.
    assert_eq!(thread.cpu.pc(), pc + 4);
    assert_eq!(thread.cpu.reg(16), 1);
    assert_eq!(thread.cpu.reg(0), 0);
    assert_eq!(
        thread.mach.debug_state.get(128).copied().unwrap_or(0) & 1,
        0
    );
    assert_eq!(thread.sig.entry.esr >> 26, 0x32);
    assert_eq!((thread.sig.entry.esr >> 25) & 1, 1);
}

#[test]
fn arm_mach_debug_state_steps_one_instruction_without_a_bsd_tracer() {
    let mut process = bounded_tests::process(DarwinAbi::Arm64);
    let tid = arm(&mut process, true);
    let pc = process.proc.threads[&tid].cpu.pc();
    assert!(process.proc.tracing.tracer.is_none());
    assert_step(&mut process, tid, pc);
}

#[test]
fn clearing_the_mach_step_before_resume_restores_ordinary_execution() {
    let mut process = bounded_tests::process(DarwinAbi::Arm64);
    arm(&mut process, true);
    arm(&mut process, false);
    assert_eq!(
        process.run_slice(16, &AtomicBool::new(false)),
        RunStatus::Complete(ExitStatus::Exited(37))
    );
}

#[test]
fn mach_step_does_not_bypass_task_or_thread_holds() {
    for task_hold in [false, true] {
        let mut process = bounded_tests::process(DarwinAbi::Arm64);
        let tid = arm(&mut process, true);
        let pc = process.proc.threads[&tid].cpu.pc();
        if task_hold {
            process.proc.task.suspension.place(Hold::Normal).unwrap();
        } else {
            process
                .proc
                .threads
                .get_mut(&tid)
                .unwrap()
                .mach
                .suspend_count = 1;
        }
        assert_eq!(
            process.run_slice(16, &AtomicBool::new(false)),
            RunStatus::Blocked
        );
        assert_eq!(process.proc.threads[&tid].cpu.pc(), pc);
        assert_eq!(process.proc.threads[&tid].mach.debug_state[128] & 1, 1);
        if task_hold {
            process.proc.task.suspension.release(Hold::Normal).unwrap();
        } else {
            process
                .proc
                .threads
                .get_mut(&tid)
                .unwrap()
                .mach
                .suspend_count = 0;
        }
        assert_step(&mut process, tid, pc);
    }
}

#[test]
fn an_instruction_fault_has_priority_over_a_mach_step_trap() {
    let mut process = bounded_tests::process(DarwinAbi::Arm64);
    let tid = arm(&mut process, true);
    let pc = process.proc.threads[&tid].cpu.pc();
    // All-zero A64 encoding is unallocated, not a retired instruction.
    process
        .proc
        .space
        .write_raw(pc, &0u32.to_le_bytes())
        .unwrap();
    assert!(matches!(
        process.run_slice(16, &AtomicBool::new(false)),
        RunStatus::Complete(ExitStatus::Signaled { signo: signal::SIGILL, pc: fault, .. })
            if fault == pc
    ));
    assert_eq!(process.proc.threads[&tid].cpu.reg(16), 0);
    let thread = &process.proc.threads[&tid];
    let DarwinCpu::Arm64(cpu) = &thread.cpu else {
        unreachable!()
    };
    assert_ne!(cpu.core().el0_spsr() & (1 << 21), 0);
    assert!(thread_status::arm_step_enabled(&thread.mach.debug_state));
}

#[test]
fn a_mach_step_reports_the_branch_target_and_preserves_nzcv() {
    let mut process = bounded_tests::process(DarwinAbi::Arm64);
    let tid = arm(&mut process, true);
    let pc = process.proc.threads[&tid].cpu.pc();
    // B +8 bytes: signed imm26=2, scaled by 4 bytes per instruction.
    process
        .proc
        .space
        .write_raw(pc, &0x1400_0002u32.to_le_bytes())
        .unwrap();
    let thread = process.proc.threads.get_mut(&tid).unwrap();
    let DarwinCpu::Arm64(cpu) = &mut thread.cpu else {
        unreachable!()
    };
    cpu.core_mut().set_el0_spsr(0xa000_0000 | 0x20_03c0);
    assert!(matches!(
        process.run_slice(16, &AtomicBool::new(false)),
        RunStatus::Complete(ExitStatus::Signaled { signo: signal::SIGTRAP, pc: stopped, .. })
            if stopped == pc + 8
    ));
    let thread = &process.proc.threads[&tid];
    let DarwinCpu::Arm64(cpu) = &thread.cpu else {
        unreachable!()
    };
    assert_eq!(cpu.core().el0_spsr(), 0xa000_0000);
    assert!(!thread_status::arm_step_enabled(&thread.mach.debug_state));
    assert_eq!(thread.sig.entry.esr, 0xcb00_0022);
}

fn x86_tf(process: &mut DarwinProcess, enabled: bool) -> u64 {
    let (&tid, thread) = process.proc.threads.iter_mut().next().unwrap();
    let mut state = thread_status::get(
        &thread_status::View {
            cpu: &thread.cpu,
            entry: &thread.sig.entry,
            debug: &thread.mach.debug_state,
            ptrauth: false,
        },
        thread_status::x86::THREAD_STATE64,
        thread_status::x86::THREAD_STATE64_COUNT,
    )
    .unwrap();
    // x86_thread_state64.__rflags is its eighteenth 64-bit field.
    state[34] = (state[34] & !(1 << 8)) | (u32::from(enabled) << 8);
    thread_status::set(
        &mut thread.cpu,
        &mut thread.mach.debug_state,
        thread_status::x86::THREAD_STATE64,
        &state,
    )
    .unwrap();
    tid
}

#[test]
fn x86_mach_tf_traces_one_instruction_and_updates_only_an_existing_debug_image() {
    for has_debug_image in [false, true] {
        let mut process = bounded_tests::process(DarwinAbi::X86_64);
        let tid = x86_tf(&mut process, true);
        let thread = process.proc.threads.get_mut(&tid).unwrap();
        let pc = thread.cpu.pc();
        if has_debug_image {
            let debug = vec![0; thread_status::x86::DEBUG_STATE64_COUNT as usize];
            thread_status::set(
                &mut thread.cpu,
                &mut thread.mach.debug_state,
                thread_status::x86::DEBUG_STATE64,
                &debug,
            )
            .unwrap();
        }
        assert!(matches!(
            process.run_slice(16, &AtomicBool::new(false)),
            RunStatus::Complete(ExitStatus::Signaled { signo: signal::SIGTRAP, pc: stopped, .. })
                if stopped == pc + 5
        ));
        let thread = &process.proc.threads[&tid];
        assert_eq!(thread.cpu.pc(), pc + 5);
        assert_eq!(thread.sig.entry.trapno, 1);
        if has_debug_image {
            assert_ne!(thread.mach.debug_state[12] & (1 << 14), 0);
        } else {
            assert!(thread.mach.debug_state.is_empty());
        }
    }
}

#[test]
fn x86_mach_tf_clear_restores_untraced_execution() {
    let mut process = bounded_tests::process(DarwinAbi::X86_64);
    x86_tf(&mut process, true);
    x86_tf(&mut process, false);
    assert_eq!(
        process.run_slice(16, &AtomicBool::new(false)),
        RunStatus::Complete(ExitStatus::Exited(37))
    );
}
