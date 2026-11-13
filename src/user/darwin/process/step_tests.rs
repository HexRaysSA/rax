//! Mach debug-state stepping is independent of BSD PT_STEP.

use super::*;
use crate::user::darwin::mach::suspend::Hold;
use crate::user::darwin::thread_status;

#[test]
fn arm_instruction_debug_state_enters_mach_breakpoint_before_execution() {
    for enabled in [false, true] {
        let mut process = bounded_tests::process(DarwinAbi::Arm64);
        let (&tid, thread) = process.proc.threads.iter_mut().next().unwrap();
        let pc = thread.cpu.pc();
        let mut debug = vec![0; thread_status::arm::DEBUG_STATE64_COUNT as usize];
        debug[0] = pc as u32;
        debug[1] = (pc >> 32) as u32;
        debug[32] = if enabled { 0x1e5 } else { 0x1e4 };
        thread_status::set(
            &mut thread.cpu,
            &mut thread.mach.debug_state,
            thread_status::arm::DEBUG_STATE64,
            &debug,
        )
        .unwrap();
        let result = process.run_slice(16, &AtomicBool::new(false));
        if enabled {
            assert!(matches!(result, RunStatus::Complete(ExitStatus::Signaled {
                signo: signal::SIGTRAP, pc: at, ..
            }) if at == pc));
            let thread = &process.proc.threads[&tid];
            assert_eq!((thread.cpu.pc(), thread.cpu.reg(16)), (pc, 0));
            assert_eq!(thread.sig.entry.esr, 0xc2000022);
        } else {
            assert_eq!(result, RunStatus::Complete(ExitStatus::Exited(37)));
        }
    }
}

#[test]
fn clearing_arm_instruction_debug_state_removes_the_live_comparator() {
    let mut process = bounded_tests::process(DarwinAbi::Arm64);
    let (_, thread) = process.proc.threads.iter_mut().next().unwrap();
    let pc = thread.cpu.pc();
    let mut debug = vec![0; thread_status::arm::DEBUG_STATE64_COUNT as usize];
    debug[0] = pc as u32;
    debug[1] = (pc >> 32) as u32;
    debug[32] = 0x1e5;
    thread_status::set(
        &mut thread.cpu,
        &mut thread.mach.debug_state,
        thread_status::arm::DEBUG_STATE64,
        &debug,
    )
    .unwrap();
    debug[32] = 0;
    thread_status::set(
        &mut thread.cpu,
        &mut thread.mach.debug_state,
        thread_status::arm::DEBUG_STATE64,
        &debug,
    )
    .unwrap();
    assert!(thread.mach.debug_state.is_empty());
    assert_eq!(
        process.run_slice(16, &AtomicBool::new(false)),
        RunStatus::Complete(ExitStatus::Exited(37))
    );
}

#[test]
fn arm_general_context_write_preserves_an_unselected_live_instruction_comparator() {
    let mut process = bounded_tests::process(DarwinAbi::Arm64);
    let (&tid, thread) = process.proc.threads.iter_mut().next().unwrap();
    let pc = thread.cpu.pc();
    let mut debug = vec![0; thread_status::arm::DEBUG_STATE64_COUNT as usize];
    debug[0] = pc as u32;
    debug[1] = (pc >> 32) as u32;
    debug[32] = 0x1e5;
    thread_status::set(
        &mut thread.cpu,
        &mut thread.mach.debug_state,
        thread_status::arm::DEBUG_STATE64,
        &debug,
    )
    .unwrap();
    let state = thread_status::get(
        &thread_status::View {
            cpu: &thread.cpu,
            entry: &thread.sig.entry,
            debug: &thread.mach.debug_state,
            ptrauth: false,
        },
        thread_status::arm::THREAD_STATE64,
        thread_status::arm::THREAD_STATE64_COUNT,
    )
    .unwrap();
    assert!(thread_status::set_general_context(thread, &state[..1]).is_err());
    thread_status::set_general_context(thread, &state).unwrap();
    let DarwinCpu::Arm64(cpu) = &thread.cpu else {
        unreachable!()
    };
    assert_eq!(
        cpu.core().user_debug_registers().breakpoint_control[0],
        0x1e5
    );
    assert_eq!(cpu.core().user_debug_registers().breakpoint_value[0], pc);
    assert_eq!(thread.mach.debug_state[32], 0x1e5);
    assert!(matches!(process.run_slice(16, &AtomicBool::new(false)),
        RunStatus::Complete(ExitStatus::Signaled { signo: signal::SIGTRAP, pc: at, .. }) if at == pc));
    assert_eq!(process.proc.threads[&tid].cpu.pc(), pc);
}

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

fn x86_debug_bank(thread: &Thread) -> [u64; 6] {
    use crate::vm::vcpu::{CpuState, VCpu};
    let DarwinCpu::X86_64(cpu) = &thread.cpu else {
        unreachable!()
    };
    let CpuState::X86_64(state) = cpu.vcpu().get_state().unwrap() else {
        unreachable!()
    };
    [
        state.sregs.dr0,
        state.sregs.dr1,
        state.sregs.dr2,
        state.sregs.dr3,
        state.sregs.dr6,
        state.sregs.dr7,
    ]
}

fn x86_breakpoint(process: &mut DarwinProcess, slot: usize, unified: bool) -> (u64, u64) {
    let (&tid, thread) = process.proc.threads.iter_mut().next().unwrap();
    let pc = thread.cpu.pc();
    let mut state = vec![0; thread_status::x86::DEBUG_STATE64_COUNT as usize];
    state[slot * 2] = pc as u32;
    state[slot * 2 + 1] = (pc >> 32) as u32;
    // The PCB status is deliberately stale. return_to_user does not load DR6.
    state[12] = 15;
    state[14] = 1 << (slot * 2);
    let flavor = if unified {
        state.splice(
            ..0,
            [
                thread_status::x86::DEBUG_STATE64 as u32,
                thread_status::x86::DEBUG_STATE64_COUNT,
            ],
        );
        thread_status::x86::DEBUG_STATE
    } else {
        thread_status::x86::DEBUG_STATE64
    };
    thread_status::set(
        &mut thread.cpu,
        &mut thread.mach.debug_state,
        flavor,
        &state,
    )
    .unwrap();
    (tid, pc)
}

#[test]
fn x86_instruction_debug_installs_every_slot_in_both_mach_flavors() {
    for slot in 0..4 {
        for unified in [false, true] {
            let mut process = bounded_tests::process(DarwinAbi::X86_64);
            let (tid, pc) = x86_breakpoint(&mut process, slot, unified);
            assert!(matches!(process.run_slice(16, &AtomicBool::new(false)),
                RunStatus::Complete(ExitStatus::Signaled { signo: signal::SIGTRAP, pc: at, .. }) if at == pc));
            let thread = &process.proc.threads[&tid];
            assert_eq!((thread.cpu.pc(), thread.cpu.reg(0)), (pc, 0));
            assert_eq!(thread.sig.entry.trapno, 1);
            assert_eq!(thread.mach.debug_state[12] & 15, 1 << slot);
            assert_eq!(x86_debug_bank(thread)[4], 0, "kernel entry clears live DR6");
        }
    }
}

#[test]
fn x86_instruction_debug_clear_and_rejected_updates_keep_live_state_coherent() {
    let mut process = bounded_tests::process(DarwinAbi::X86_64);
    let (tid, pc) = x86_breakpoint(&mut process, 0, false);
    let thread = process.proc.threads.get_mut(&tid).unwrap();
    let before = x86_debug_bank(thread);
    assert_eq!(before[0], pc);
    let pcb = thread.mach.debug_state.clone();
    let mut invalid = pcb.clone();
    invalid[14] = 2; // Global enable is not admitted by XNU.
    assert!(
        thread_status::set(
            &mut thread.cpu,
            &mut thread.mach.debug_state,
            thread_status::x86::DEBUG_STATE64,
            &invalid
        )
        .is_err()
    );
    assert_eq!(thread.mach.debug_state, pcb);
    assert_eq!(x86_debug_bank(thread), before);
    let mut cleared = pcb;
    cleared[14] = 0;
    thread_status::set(
        &mut thread.cpu,
        &mut thread.mach.debug_state,
        thread_status::x86::DEBUG_STATE64,
        &cleared,
    )
    .unwrap();
    let after = x86_debug_bank(thread);
    assert_eq!(after[0], pc);
    assert_eq!(after[4], before[4], "PCB DR6 is not a hardware write");
    assert_eq!(after[5], 0x400);
    assert_eq!(
        process.run_slice(16, &AtomicBool::new(false)),
        RunStatus::Complete(ExitStatus::Exited(37))
    );
}

#[test]
fn x86_instruction_debug_general_context_retains_comparators_and_raw_status() {
    let mut process = bounded_tests::process(DarwinAbi::X86_64);
    let (tid, pc) = x86_breakpoint(&mut process, 3, false);
    let thread = process.proc.threads.get_mut(&tid).unwrap();
    let DarwinCpu::X86_64(cpu) = &mut thread.cpu else {
        unreachable!()
    };
    // Model the kernel's already-consumed status. It differs from both the
    // fresh CPU's reserved-bit reset value and the stale PCB DR6 request.
    cpu.vcpu_mut().capture_user_debug_status();
    let before = x86_debug_bank(thread);
    assert_eq!(before[3], pc);
    assert_eq!(before[4], 0);
    let state = thread_status::get(
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
    thread_status::set_general_context(thread, &state).unwrap();
    assert_eq!(x86_debug_bank(thread), before);
    assert!(matches!(process.run_slice(16, &AtomicBool::new(false)),
        RunStatus::Complete(ExitStatus::Signaled { signo: signal::SIGTRAP, pc: at, .. }) if at == pc));
}

#[test]
fn x86_instruction_debug_ignores_reserved_dr4_dr5_inputs() {
    let mut process = bounded_tests::process(DarwinAbi::X86_64);
    let (_, thread) = process.proc.threads.iter_mut().next().unwrap();
    let mut state = vec![0; thread_status::x86::DEBUG_STATE64_COUNT as usize];
    state[8..12].fill(0x12345678);
    thread_status::set(
        &mut thread.cpu,
        &mut thread.mach.debug_state,
        thread_status::x86::DEBUG_STATE64,
        &state,
    )
    .unwrap();
    assert_eq!(&thread.mach.debug_state[8..12], &[0; 4]);
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
