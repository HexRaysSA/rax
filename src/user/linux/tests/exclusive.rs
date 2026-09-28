//! AArch64 local-monitor lifetime across Linux scheduling and exceptions.

use super::harness::{CODE, Harness};
use super::ptrace_stops::{resume, traced};
use crate::isa::arm::common::cpu::ArmCpu;
use crate::user::cpu::aarch64::A64Exit;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::arch::GuestCpu;
use crate::user::linux::process::Threads;
use crate::user::linux::ptrace::req;
use crate::user::linux::sched::clear_exclusive_on_switch;
use crate::user::linux::signal::deliver::{Dest, send_signal};
use crate::user::linux::signal::{SIGUSR1, SigInfo};
use crate::user::linux::syscall::thread::cf::*;

const LOAD: u64 = CODE + 0x1000;
const STORE: u64 = LOAD + 4;
const HANDLER: u64 = CODE + 0x1100;
const OTHER: u64 = CODE + 0x1200;
const LDXR_X0_X1: u32 = 0xc85f_7c20;
const STXR_W2_X0_X1: u32 = 0xc802_7c20;
const NOP: u32 = 0xd503_201f;

fn code(h: &Harness, addr: u64, words: &[u32]) {
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    h.proc.state.space.write_raw(addr, &bytes).unwrap();
}

fn data(h: &Harness) -> u64 {
    h.scratch + 0x80
}

fn set_data(h: &Harness) {
    h.proc
        .state
        .space
        .write_raw(data(h), &0x55u64.to_le_bytes())
        .unwrap();
}

fn data_value(h: &Harness) -> u64 {
    let mut bytes = [0; 8];
    h.proc.state.space.read(data(h), &mut bytes).unwrap();
    u64::from_le_bytes(bytes)
}

fn load(h: &mut Harness) {
    let address = data(h);
    let GuestCpu::Aarch64(cpu) = &mut h.proc.threads[0].cpu else {
        unreachable!()
    };
    cpu.core_mut().set_x(1, address);
    cpu.core_mut().set_pc(LOAD);
    assert_eq!(cpu.run(1), A64Exit::Yield);
    assert_eq!(cpu.pc(), STORE);
}

fn store(h: &mut Harness, pc: u64) -> u64 {
    let GuestCpu::Aarch64(cpu) = &mut h.proc.threads[0].cpu else {
        unreachable!()
    };
    cpu.core_mut().set_pc(pc);
    assert_eq!(cpu.run(1), A64Exit::Yield);
    cpu.core().get_x(2)
}

#[test]
fn aarch64_same_thread_budget_preserves_but_guest_thread_switch_clears_exclusive() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    code(&h, LOAD, &[LDXR_X0_X1, STXR_W2_X0_X1]);
    code(&h, OTHER, &[NOP]);
    set_data(&h);
    let flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
    let other_tid = h.ok(Sysno::Clone, &[flags, 0, 0, 0, 0]) as i32;
    let mine = h.proc.threads[0].tid;
    let other = h
        .proc
        .threads
        .iter()
        .position(|t| t.tid == other_tid)
        .unwrap();

    load(&mut h);
    assert!(!clear_exclusive_on_switch(
        &mut h.proc.threads[0],
        Some(mine)
    ));
    assert_eq!(store(&mut h, STORE), 0);
    assert_eq!(data_value(&h), 0x55);

    load(&mut h);
    let GuestCpu::Aarch64(cpu) = &mut h.proc.threads[other].cpu else {
        unreachable!()
    };
    cpu.core_mut().set_pc(OTHER);
    assert_eq!(cpu.run(1), A64Exit::Yield);
    assert!(clear_exclusive_on_switch(
        &mut h.proc.threads[other],
        Some(mine)
    ));
    assert!(clear_exclusive_on_switch(
        &mut h.proc.threads[0],
        Some(other_tid)
    ));
    assert_eq!(store(&mut h, STORE), 1);
    assert_eq!(data_value(&h), 0x55);
}

#[test]
fn aarch64_peer_blocked_syscall_continuation_counts_as_guest_thread_switch() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    code(&h, LOAD, &[LDXR_X0_X1, STXR_W2_X0_X1]);
    set_data(&h);
    let flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
    let other_tid = h.ok(Sysno::Clone, &[flags, 0, 0, 0, 0]) as i32;
    let other = h
        .proc
        .threads
        .iter()
        .position(|t| t.tid == other_tid)
        .unwrap();
    let mine = h.proc.threads[0].tid;
    let request = h.scratch + 0x200;
    let timespec: Vec<u8> = [0u64, 50_000_000]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    h.proc.state.space.write_raw(request, &timespec).unwrap();
    assert_eq!(h.start(other, Sysno::Nanosleep, &[request, 0]), None);

    load(&mut h);
    h.proc.state.last_user = Some(mine);
    // The peer is selected to finish a sleep; its AArch64 CPU never runs.
    assert!(clear_exclusive_on_switch(
        &mut h.proc.threads[other],
        Some(mine)
    ));
    std::thread::sleep(std::time::Duration::from_millis(60));
    assert_eq!(h.proc.wake_sleepers(), 1);
    assert_eq!(h.proc.state.last_user, Some(mine));
    assert!(clear_exclusive_on_switch(
        &mut h.proc.threads[0],
        Some(other_tid)
    ));
    assert_eq!(store(&mut h, STORE), 1);
    assert_eq!(data_value(&h), 0x55);
}

#[test]
fn aarch64_async_signal_handler_entry_clears_exclusive_after_budget_yield() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    code(&h, LOAD, &[LDXR_X0_X1]);
    code(&h, HANDLER, &[STXR_W2_X0_X1]);
    set_data(&h);
    let action = h.scratch + 0xe00;
    let bytes: Vec<u8> = [HANDLER, 0, 0]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    h.proc.state.space.write_raw(action, &bytes).unwrap();
    h.ok(Sysno::RtSigaction, &[SIGUSR1 as u64, action, 0, 8]);

    load(&mut h);
    let tid = h.proc.threads[0].tid;
    let mut threads = Threads::split(&mut h.proc.threads, None);
    assert!(send_signal(
        &mut h.proc.state,
        &mut threads,
        SigInfo::kernel(SIGUSR1),
        Dest::Thread(tid),
        false,
    ));
    h.proc.deliver_signals(0);
    assert_eq!(h.proc.threads[0].cpu.pc(), HANDLER);
    assert_eq!(store(&mut h, HANDLER), 1);
    assert_eq!(data_value(&h), 0x55);
}

#[test]
fn aarch64_ptrace_single_step_trap_clears_exclusive_after_budget_yield() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    code(&h, LOAD, &[LDXR_X0_X1, STXR_W2_X0_X1]);
    set_data(&h);
    let mut tracer = traced(&mut h, 0);
    let address = data(&h);
    let GuestCpu::Aarch64(cpu) = &mut h.proc.threads[0].cpu else {
        unreachable!()
    };
    cpu.core_mut().set_x(1, address);
    cpu.core_mut().set_pc(LOAD);
    assert_eq!(resume(&mut h, &mut tracer, req::SINGLESTEP, 0), 0);
    load(&mut h);
    h.proc.step_trap(0);
    assert_eq!(store(&mut h, STORE), 1);
    assert_eq!(data_value(&h), 0x55);
}
