//! Dynamic retirement through the actual public native execution path.
use super::*;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

fn cpu(code: &[u8]) -> X86_64Vcpu {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
    memory.write_slice(code, GuestAddress(0x100)).unwrap();
    let mut cpu = X86_64Vcpu::new(0, memory);
    cpu.regs.rip = 0x100;
    cpu.regs.rsp = 0x7000;
    cpu.regs.rflags = 2;
    cpu.sregs.cr0 = 1;
    cpu.sregs.efer = 1 << 10;
    cpu.sregs.cs.base = 0;
    cpu.sregs.cs.l = true;
    #[cfg(target_arch = "x86_64")]
    {
        cpu.set_jit_call(false);
        cpu.set_jit_mem(false);
    }
    cpu
}

#[cfg(target_arch = "x86_64")]
#[test]
fn public_native_loop_counts_nops_and_every_dynamic_branch_once() {
    // NOP; NOP; MOV ECX,3; again: INC EBX; DEC ECX; JNZ again; HLT.
    for start in [0, 7, u64::MAX - 5] {
        let mut cpu = cpu(&[
            0x90, 0x90, 0xb9, 3, 0, 0, 0, 0xff, 0xc3, 0xff, 0xc9, 0x75, 0xfa, 0xf4,
        ]);
        cpu.insn_count = start;
        assert!(cpu.jit_try_block().unwrap());
        assert_eq!(cpu.regs.rip, 0x10d);
        assert_eq!(cpu.regs.rbx, 3);
        assert_eq!(cpu.insn_count, start.wrapping_add(12));
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn faulting_native_load_counts_only_the_completed_prefix() {
    let mut cpu = cpu(&[0x90, 0x8b, 0x03, 0xf4]);
    cpu.regs.rbx = 0x20000;
    cpu.set_jit_mem(true);
    assert!(cpu.jit_try_block().unwrap());
    assert_eq!(cpu.regs.rip, 0x101);
    assert_eq!(cpu.insn_count, 1);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn native_call_and_interpreted_callee_contribute_once() {
    let mut cpu = cpu(&[
        0xff, 0xc3, 0xe8, 3, 0, 0, 0, 0xff, 0xc1, 0xf4, 0xff, 0xc2, 0xc3,
    ]);
    cpu.set_jit_call(true);
    assert!(cpu.jit_try_block().unwrap());
    assert_eq!(cpu.regs.rip, 0x109);
    assert_eq!((cpu.regs.rbx, cpu.regs.rcx, cpu.regs.rdx), (1, 1, 1));
    assert_eq!(cpu.insn_count, 5);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn failed_call_push_does_not_retire_the_call() {
    let mut cpu = cpu(&[0x90, 0xe8, 2, 0, 0, 0, 0x90, 0xf4, 0xc3]);
    cpu.regs.rsp = 0;
    cpu.set_jit_call(true);
    assert!(cpu.jit_try_block().unwrap());
    assert_eq!(cpu.regs.rip, 0x101);
    assert_eq!(cpu.regs.rsp, 0);
    assert_eq!(cpu.insn_count, 1);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn successful_control_exit_counts_the_native_prefix_and_instruction() {
    let mut cpu = cpu(&[0x90, 0xfa, 0x90, 0xf4]);
    cpu.regs.rflags |= flags::bits::IF;
    assert!(cpu.jit_try_block().unwrap());
    assert_eq!(cpu.regs.rip, 0x102);
    assert_eq!(cpu.insn_count, 2);
    assert_eq!(cpu.regs.rflags & flags::bits::IF, 0);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn callee_exit_clears_active_host_region_and_keeps_one_deferred_exit() {
    let mut cpu = cpu(&[0xff, 0xc3, 0xe8, 3, 0, 0, 0, 0xff, 0xc1, 0xf4, 0xf4]);
    cpu.set_jit_call(true);
    assert!(cpu.jit_try_block().unwrap());
    assert_eq!(cpu.regs.rip, 0x10b);
    assert_eq!(cpu.insn_count, 3);
    assert!(cpu.jit_active_source_range.is_none());
    assert!(!cpu.jit_active_region_stale);
    assert!(matches!(cpu.step_insn().unwrap(), Some(VcpuExit::Hlt)));
    assert_eq!(cpu.insn_count, 3);
    assert!(cpu.jit_callout_exit.is_none());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn verifier_replay_preserves_the_single_native_retirement_total() {
    let mut cpu = cpu(&[0x90, 0x83, 0xc3, 1, 0xf4]);
    cpu.insn_count = 7;
    let region = cpu
        .jit_compile_region()
        .unwrap()
        .expect("native scalar admission");
    cpu.jit_run_region_verified(&region);
    assert_eq!(cpu.regs.rip, 0x104);
    assert_eq!(cpu.regs.rbx, 1);
    assert_eq!(cpu.insn_count, 9);
}

// AArch64-specific admission and retirement fixtures.
#[cfg(target_arch = "aarch64")]
#[test]
fn aarch64_rejects_unrepresentable_flag_loop_before_guest_execution() {
    let mut cpu = cpu(&[
        0x90, 0x90, 0xb9, 3, 0, 0, 0, 0xff, 0xc3, 0xff, 0xc9, 0x75, 0xfa, 0xf4,
    ]);
    cpu.insn_count = 7;
    let before = crate::codec::serialize(&cpu.regs).unwrap();
    assert!(!cpu.jit_try_block().unwrap());
    assert_eq!(crate::codec::serialize(&cpu.regs).unwrap(), before);
    assert_eq!(cpu.insn_count, 7);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn aarch64_native_loop_counts_nops_nf_arithmetic_and_dynamic_branches_once() {
    // NOP; NOP; MOV ECX,3; loop: {nf} INC RBX; {nf} DEC RCX;
    // BLSI RDX,RCX; JNZ loop; HLT. The admitted NF/BLSI profile preserves
    // PF/AF while exposing the loop's ZF through the native NZCV bridge.
    let code = [
        0x90, 0x90, 0xb9, 3, 0, 0, 0, 0x62, 0xf4, 0xfc, 0x0c, 0xff, 0xc3, 0x62, 0xf4, 0xfc, 0x0c,
        0xff, 0xc9, 0xc4, 0xe2, 0xe8, 0xf3, 0xd9, 0x75, 0xed, 0xf4,
    ];
    for start in [0, 7, u64::MAX - 5] {
        let mut cpu = cpu(&code);
        cpu.set_apx_enabled(true);
        cpu.insn_count = start;
        assert!(cpu.jit_try_block().unwrap());
        assert_eq!(cpu.regs.rip, 0x11a);
        assert_eq!(cpu.regs.rbx, 3);
        assert_eq!(cpu.regs.rcx, 0);
        assert_eq!(cpu.insn_count, start.wrapping_add(15));
    }
}
