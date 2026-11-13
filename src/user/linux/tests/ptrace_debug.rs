//! Linux ptrace debug registers through the stopped tracee's real link.

use super::harness::{CODE, Harness};
use super::ptrace_stops::{Tracer, resume, traced};
use crate::user::linux::abi::LinuxAbi;
use crate::user::linux::abi::Sysno;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::arch::{CpuEvent, GuestCpu};
use crate::user::linux::ptrace::{Msg, req};
use crate::user::linux::signal::{SIGTRAP, code};

const DR6_RESET: u64 = 0xffff_0ff0;

fn request(
    h: &mut Harness,
    tr: &mut Tracer,
    compat: bool,
    n: u64,
    value: Option<u64>,
) -> (i64, u64) {
    let (base, size) = if compat { (252, 4) } else { (848, 8) };
    assert!(tr.link.send(&Msg::Request {
        tid: h.proc.threads[0].tid,
        req: if value.is_some() {
            req::POKEUSR
        } else {
            req::PEEKUSR
        },
        addr: base + n * size,
        data: value.unwrap_or(0),
        compat,
        payload: vec![],
    }));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "ptrace reply deadline"
        );
        h.proc.collect_async(None);
        for m in tr.link.recv() {
            if let Msg::Reply { ret, payload } = m {
                let mut word = [0; 8];
                assert!(payload.is_empty() || payload.len() == size as usize);
                word[..payload.len()].copy_from_slice(&payload);
                return (ret, u64::from_le_bytes(word));
            }
        }
    }
}

#[test]
fn ptrace_installs_each_execution_slot_in_both_word_views() {
    for abi in [LinuxAbi::X86_64, LinuxAbi::I386] {
        for compat in [false, true] {
            for slot in 0..4 {
                let mut h = Harness::new(abi);
                let pc = CODE + 0x1000;
                h.proc.state.space.write_raw(pc, &[0x90, 0x90]).unwrap();
                h.proc.threads[0].cpu.set_pc(pc);
                let mut tr = traced(&mut h, 0);
                assert_eq!(request(&mut h, &mut tr, compat, slot, Some(pc)).0, 0);
                // Local and global enables are both accepted by Linux.
                let dr7 = (1 + (slot & 1)) << (slot * 2);
                assert_eq!(request(&mut h, &mut tr, compat, 7, Some(dr7)).0, 0);
                assert_eq!(request(&mut h, &mut tr, compat, slot, None), (0, pc));
                assert_eq!(request(&mut h, &mut tr, compat, 7, None), (0, dr7));
                assert_eq!(resume(&mut h, &mut tr, req::CONT, 0), 0);
                let cpu = &mut h.proc.threads[0].cpu;
                let CpuEvent::Signal(info, _) = cpu.step() else {
                    panic!("execution breakpoint")
                };
                assert_eq!(
                    (info.signo, info.code, info.addr()),
                    (SIGTRAP, code::TRAP_HWBKPT, pc)
                );
                assert_eq!(cpu.pc(), pc);
                let GuestCpu::X86_64(x) = cpu else {
                    unreachable!()
                };
                assert_eq!(x.vcpu().last_user_debug_status() & 0x400f, 1 << slot);
                // hw_breakpoint_handler adds RF to permit one retry.
                assert_ne!(x.vcpu().user_rflags() & (1 << 16), 0);
                assert_eq!(cpu.step(), CpuEvent::Yield);
                assert_eq!(cpu.pc(), pc + 1);
            }
        }
    }
}

#[test]
fn ptrace_debug_status_roundtrips_without_becoming_live_hardware_status() {
    for compat in [false, true] {
        let mut h = Harness::new(LinuxAbi::X86_64);
        let mut tr = traced(&mut h, 0);
        assert_eq!(request(&mut h, &mut tr, compat, 6, None), (0, DR6_RESET));
        for value in [0, 0x4001, u32::MAX as u64] {
            assert_eq!(request(&mut h, &mut tr, compat, 6, Some(value)).0, 0);
            assert_eq!(request(&mut h, &mut tr, compat, 6, None), (0, value));
        }
        let pc = CODE + 0x1000;
        h.proc.state.space.write_raw(pc, &[0xf1]).unwrap();
        h.proc.threads[0].cpu.set_pc(pc);
        assert_eq!(resume(&mut h, &mut tr, req::CONT, 0), 0);
        let CpuEvent::Signal(info, _) = h.proc.threads[0].cpu.step() else {
            panic!("ICEBP")
        };
        assert_eq!((info.signo, info.code), (SIGTRAP, code::TRAP_BRKPT));
        let mut tr = traced(&mut h, 0);
        assert_eq!(request(&mut h, &mut tr, compat, 6, None), (0, DR6_RESET));
    }
}

#[test]
fn ptrace_rejects_dr4_dr5_and_rolls_back_invalid_controls() {
    for compat in [false, true] {
        let mut h = Harness::new(LinuxAbi::X86_64);
        let mut tr = traced(&mut h, 0);
        for n in [4, 5] {
            assert_eq!(request(&mut h, &mut tr, compat, n, None), (0, 0));
            for value in [0, 1] {
                assert_eq!(
                    request(&mut h, &mut tr, compat, n, Some(value)).0,
                    -(EIO as i64)
                );
            }
        }
        let pc = CODE + 0x1000;
        assert_eq!(request(&mut h, &mut tr, compat, 0, Some(pc)).0, 0);
        assert_eq!(request(&mut h, &mut tr, compat, 7, Some(1)).0, 0);
        for bad in [1 | (4 << 16), 1 | (2 << 16)] {
            assert_eq!(
                request(&mut h, &mut tr, compat, 7, Some(bad)).0,
                -(EINVAL as i64)
            );
            assert_eq!(request(&mut h, &mut tr, compat, 7, None), (0, 1));
            assert_eq!(request(&mut h, &mut tr, compat, 0, None), (0, pc));
        }
        // Requested reserved DR7 bits are visible but are not installed.
        let requested = if compat {
            0xfc01
        } else {
            0xffff_ffff_0000_fc01
        };
        assert_eq!(request(&mut h, &mut tr, compat, 7, Some(requested)).0, 0);
        assert_eq!(request(&mut h, &mut tr, compat, 7, None), (0, requested));
        let GuestCpu::X86_64(x) = &h.proc.threads[0].cpu else {
            unreachable!()
        };
        assert_eq!(x.vcpu().user_debug_registers()[5], 0x602);
    }
}

#[test]
fn a_failed_dr7_update_keeps_newly_allocated_disabled_objects() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let mut tr = traced(&mut h, 0);
    // Slot zero is created before slot one's invalid execution length fails.
    let bad = 1 | 4 | (4 << 20);
    assert_eq!(
        request(&mut h, &mut tr, false, 7, Some(bad)).0,
        -(EINVAL as i64)
    );
    assert_eq!(request(&mut h, &mut tr, false, 7, None), (0, 0));
    // An absent disabled slot ignores its type. The retained object does not.
    assert_eq!(
        request(&mut h, &mut tr, false, 7, Some(2 << 16)).0,
        -(EINVAL as i64)
    );
}

#[test]
fn clone_clears_comparators_and_keeps_virtual_dr6_and_dr7() {
    use crate::user::linux::syscall::thread::cf::*;
    for abi in [LinuxAbi::X86_64, LinuxAbi::I386] {
        let mut h = Harness::embedded(abi);
        let t = &mut h.proc.threads[0];
        let GuestCpu::X86_64(cpu) = &mut t.cpu else {
            unreachable!()
        };
        t.debug.write(cpu, 0, CODE + 0x1000).unwrap();
        t.debug.write(cpu, 7, 1).unwrap();
        t.debug.write(cpu, 6, 0x4001).unwrap();
        const THREAD: u64 =
            CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
        h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]);
        assert_eq!(h.proc.threads.len(), 2);
        let child = &mut h.proc.threads[1];
        let GuestCpu::X86_64(cpu) = &mut child.cpu else {
            unreachable!()
        };
        assert_eq!(child.debug.read(cpu, 0), 0);
        assert_eq!(child.debug.read(cpu, 6), 0x4001);
        assert_eq!(child.debug.read(cpu, 7), 1);
        assert_eq!(cpu.vcpu().user_debug_registers()[5] & 0xff, 0);
        // The process-fork path operates in place on an inherited thread.
        let parent = &mut h.proc.threads[0];
        parent.debug.clear_breakpoints(&mut parent.cpu);
        let GuestCpu::X86_64(cpu) = &parent.cpu else {
            unreachable!()
        };
        assert_eq!(parent.debug.read(cpu, 0), 0);
        assert_eq!(parent.debug.read(cpu, 6), 0x4001);
        assert_eq!(parent.debug.read(cpu, 7), 1);
        assert_eq!(cpu.vcpu().user_debug_registers()[5] & 0xff, 0);
    }
}
