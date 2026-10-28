//! Mach debug control can disarm previously requested BSD steps.

use super::*;
use crate::user::darwin::abi::DarwinAbi;
use crate::user::darwin::process::{RunStatus, bounded_tests::process};
use crate::user::darwin::thread_status;
use std::sync::atomic::AtomicBool;

#[test]
fn mach_disarm_overrides_the_bsd_arm_step_bookkeeping() {
    let mut process = process(DarwinAbi::Arm64);
    let (&tid, thread) = process.proc.threads.iter_mut().next().unwrap();
    set_step_state(thread, true);
    process.proc.tracing.stepping = Some(tid);
    let clear = vec![0; thread_status::arm::DEBUG_STATE64_COUNT as usize];
    thread_status::set(
        &mut thread.cpu,
        &mut thread.mach.debug_state,
        thread_status::arm::DEBUG_STATE64,
        &clear,
    )
    .unwrap();
    assert_eq!(
        process.run_slice(16, &AtomicBool::new(false)),
        RunStatus::Complete(ExitStatus::Exited(37))
    );
}

#[test]
fn mach_disarm_overrides_the_bsd_x86_step_bookkeeping() {
    let mut process = process(DarwinAbi::X86_64);
    let (&tid, thread) = process.proc.threads.iter_mut().next().unwrap();
    set_step_state(thread, true);
    process.proc.tracing.stepping = Some(tid);
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
    state[34] &= !(1 << 8);
    thread_status::set(
        &mut thread.cpu,
        &mut thread.mach.debug_state,
        thread_status::x86::THREAD_STATE64,
        &state,
    )
    .unwrap();
    assert_eq!(
        process.run_slice(16, &AtomicBool::new(false)),
        RunStatus::Complete(ExitStatus::Exited(37))
    );
}
