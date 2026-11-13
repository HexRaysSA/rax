//! ARM64 ptrace comparator regsets against own-child native kernel controls.

use super::harness::{CODE, Harness};
use super::ptrace_stops::{ask, resume, traced};
use crate::user::linux::abi::LinuxAbi;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::arch::{CpuEvent, GuestCpu};
use crate::user::linux::ptrace::{regs, req};
use crate::user::linux::signal::{SIGTRAP, code};

const HW_BREAK: u64 = 0x402;

fn image(address: u64, control: u32, size: usize) -> Vec<u8> {
    let mut b = vec![0; size];
    if size >= 16 {
        b[8..16].copy_from_slice(&address.to_le_bytes());
    }
    if size >= 20 {
        b[16..20].copy_from_slice(&control.to_le_bytes());
    }
    b
}

fn slot(bytes: &[u8], n: usize) -> (u64, u32) {
    let i = 8 + 16 * n;
    (
        u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap()),
        u32::from_le_bytes(bytes[i + 8..i + 12].try_into().unwrap()),
    )
}

#[test]
fn arm64_debug_regset_has_word_units_and_a_complete_zeroed_initial_bank() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    assert_eq!(
        regs::layout(&h.proc.threads[0].cpu, false, false, HW_BREAK),
        Ok((4, 264))
    );
    let mut tr = traced(&mut h, 0);
    let (ret, b) = ask(&mut h, &mut tr, req::GETREGSET, HW_BREAK, 264, &[]);
    assert_eq!(ret, 0);
    assert_eq!(b.len(), 264);
    // Default core profile: DebugVer=6, six breakpoint pairs.
    assert_eq!(u32::from_le_bytes(b[..4].try_into().unwrap()), 0x606);
    assert!(b[4..].iter().all(|&v| v == 0));
}

#[test]
fn arm64_partial_debug_writes_retain_committed_address_and_default_object() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let mut tr = traced(&mut h, 0);
    let pc = CODE + 0x1000;
    let bad = image(pc, 0xa5, 24); // Non-contiguous byte selection.
    assert_eq!(
        ask(&mut h, &mut tr, req::SETREGSET, HW_BREAK, 24, &bad).0,
        -(EINVAL as i64)
    );
    let (_, b) = ask(&mut h, &mut tr, req::GETREGSET, HW_BREAK, 264, &[]);
    assert_eq!(slot(&b, 0), (pc, 0x1e4));
    // Disabled writes ignore their non-enable fields.
    let disabled = image(pc, 0xffff_fffe, 24);
    assert_eq!(
        ask(&mut h, &mut tr, req::SETREGSET, HW_BREAK, 24, &disabled).0,
        0
    );
    let (_, b) = ask(&mut h, &mut tr, req::GETREGSET, HW_BREAK, 264, &[]);
    assert_eq!(slot(&b, 0), (pc, 0x1e4));
    // Native A64 execution comparator length is normalized to four bytes.
    let half = image(pc, 0x65, 20);
    assert_eq!(
        ask(&mut h, &mut tr, req::SETREGSET, HW_BREAK, 20, &half).0,
        0
    );
    let (_, b) = ask(&mut h, &mut tr, req::GETREGSET, HW_BREAK, 264, &[]);
    assert_eq!(slot(&b, 0), (pc, 0x1e5));
}

#[test]
fn arm64_ptrace_executes_every_slot_and_retriggers_until_disarmed() {
    for n in 0..6 {
        let mut h = Harness::new(LinuxAbi::Aarch64);
        let pc = CODE + 0x1000;
        h.proc
            .state
            .space
            .write_raw(pc, &0x91000400u32.to_le_bytes())
            .unwrap();
        h.proc.threads[0].cpu.set_pc(pc);
        let GuestCpu::Aarch64(cpu) = &mut h.proc.threads[0].cpu else {
            unreachable!()
        };
        cpu.core_mut().set_x(0, 41);
        let mut tr = traced(&mut h, 0);
        let mut b = vec![0; 8 + 16 * (n + 1)];
        b[8 + 16 * n..16 + 16 * n].copy_from_slice(&pc.to_le_bytes());
        b[16 + 16 * n..20 + 16 * n].copy_from_slice(&0x1e5u32.to_le_bytes());
        assert_eq!(
            ask(
                &mut h,
                &mut tr,
                req::SETREGSET,
                HW_BREAK,
                b.len() as u64,
                &b
            )
            .0,
            0
        );
        assert_eq!(resume(&mut h, &mut tr, req::CONT, 0), 0);
        for _ in 0..2 {
            let CpuEvent::Signal(info, _) = h.proc.threads[0].cpu.step() else {
                panic!("hardware breakpoint")
            };
            assert_eq!(
                (info.signo, info.code, info.addr()),
                (SIGTRAP, code::TRAP_HWBKPT, pc)
            );
            let GuestCpu::Aarch64(cpu) = &h.proc.threads[0].cpu else {
                unreachable!()
            };
            assert_eq!((cpu.pc(), cpu.core().get_x(0)), (pc, 41));
        }
        // Stop again, as the scheduler does for the reported signal.
        let mut tr = traced(&mut h, 0);
        b[16 + 16 * n..20 + 16 * n].fill(0);
        assert_eq!(
            ask(
                &mut h,
                &mut tr,
                req::SETREGSET,
                HW_BREAK,
                b.len() as u64,
                &b
            )
            .0,
            0
        );
        assert_eq!(resume(&mut h, &mut tr, req::CONT, 0), 0);
        assert_eq!(h.proc.threads[0].cpu.step(), CpuEvent::Yield);
        let GuestCpu::Aarch64(cpu) = &h.proc.threads[0].cpu else {
            unreachable!()
        };
        assert_eq!((cpu.pc(), cpu.core().get_x(0)), (pc + 4, 42));
    }
}

#[test]
fn arm64_debug_resources_and_short_address_writes_follow_kernel_commit_order() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let mut tr = traced(&mut h, 0);
    let short = image(CODE, 0, 12);
    assert_eq!(
        ask(&mut h, &mut tr, req::SETREGSET, HW_BREAK, 12, &short).0,
        -(EINVAL as i64)
    );
    let (_, b) = ask(&mut h, &mut tr, req::GETREGSET, HW_BREAK, 264, &[]);
    assert_eq!(slot(&b, 0), (0, 0));
    let all = vec![0; 264];
    assert_eq!(
        ask(&mut h, &mut tr, req::SETREGSET, HW_BREAK, 264, &all).0,
        -(ENOSPC as i64)
    );
    let (_, b) = ask(&mut h, &mut tr, req::GETREGSET, HW_BREAK, 264, &[]);
    for n in 0..16 {
        assert_eq!(slot(&b, n), (0, if n < 6 { 0x1e4 } else { 0 }));
    }
}
