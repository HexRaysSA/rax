//! Native x86-64 JIT differentials for MOV-from-control-register state.

use super::*;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const RFLAGS_VM: u64 = 1 << 17;

fn memory_with_code(code: &[u8]) -> Arc<GuestMemoryMmap> {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
    memory.write_slice(code, GuestAddress(0)).unwrap();
    memory
}

fn test_vcpu(memory: Arc<GuestMemoryMmap>) -> X86_64Vcpu {
    let mut vcpu = X86_64Vcpu::new(0, memory);
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.sregs.cs.selector = 0;
    vcpu.sregs.cr0 = 0x0005_0033;
    vcpu.sregs.cr2 = 0x2222_3333_4444_5555;
    vcpu.sregs.cr3 = 0x0000_1234_5000_0ABC;
    vcpu.sregs.cr4 = 0x0000_0000_0044_06F0;
    vcpu.sregs.cr8 = 0xD;
    vcpu.mmu.set_task_priority((0xD << 4) as u32).unwrap();
    vcpu.regs.rip = 0;
    vcpu.regs.rsp = 0x8000;
    vcpu.regs.rbp = 0x7000;
    vcpu.regs.rflags = 0x2 | 0x08D5 | (1 << 10);
    vcpu.set_jit_mem(false);
    vcpu.set_jit_call(false);
    vcpu
}

fn run_direct_to(vcpu: &mut X86_64Vcpu, target: u64) {
    for _ in 0..32 {
        if vcpu.regs.rip == target {
            return;
        }
        assert!(
            vcpu.step().expect("direct MOV-from-CR sequence").is_none(),
            "unexpected direct exit at {:#x}",
            vcpu.regs.rip
        );
    }
    panic!("direct execution did not reach {target:#x}");
}

#[test]
fn jit_mov_from_control_registers_matches_direct_for_every_control_register() {
    let memory = memory_with_code(&[
        0x0F, 0x20, 0xC0, // mov rax,cr0
        0x0F, 0x20, 0xD1, // mov rcx,cr2
        0x0F, 0x20, 0xDA, // mov rdx,cr3
        0x0F, 0x20, 0xE3, // mov rbx,cr4
        0x44, 0x0F, 0x20, 0xC7, // mov rdi,cr8
        0xEB, 0x00, // jmp hlt
        0xF4,
    ]);
    let mut direct = test_vcpu(memory.clone());
    let mut native = test_vcpu(memory);

    run_direct_to(&mut direct, 18);
    let region = native
        .jit_compile_region()
        .expect("compile MOV-from-CR region")
        .expect("MOV-from-CR region must be native eligible");
    native.jit_run_region_native(&region);

    assert_eq!(
        [
            native.regs.rax,
            native.regs.rcx,
            native.regs.rdx,
            native.regs.rbx,
            native.regs.rdi,
            native.regs.rsp,
            native.regs.rbp,
            native.regs.rflags,
            native.regs.rip,
        ],
        [
            direct.regs.rax,
            direct.regs.rcx,
            direct.regs.rdx,
            direct.regs.rbx,
            direct.regs.rdi,
            direct.regs.rsp,
            direct.regs.rbp,
            direct.regs.rflags,
            direct.regs.rip,
        ]
    );
}

#[test]
fn jit_mov_from_control_register_handles_rsp_rbp_destinations() {
    let memory = memory_with_code(&[
        0x0F, 0x20, 0xD4, // mov rsp,cr2
        0x0F, 0x20, 0xDD, // mov rbp,cr3
        0xEB, 0x00, 0xF4,
    ]);
    let mut direct = test_vcpu(memory.clone());
    let mut native = test_vcpu(memory);

    run_direct_to(&mut direct, 8);
    let region = native
        .jit_compile_region()
        .expect("compile stack-register MOV-from-CR region")
        .expect("state-backed RSP/RBP destinations must be native eligible");
    native.jit_run_region_native(&region);

    assert_eq!(native.regs.rsp, direct.regs.rsp);
    assert_eq!(native.regs.rbp, direct.regs.rbp);
    assert_eq!(native.regs.rflags, direct.regs.rflags);
    assert_eq!(native.regs.rip, 8);
}

#[test]
fn jit_verify_snapshots_compares_and_adopts_all_readable_control_state() {
    let memory = memory_with_code(&[0x0F, 0x20, 0xD8, 0xEB, 0x00, 0xF4]);
    let mut vcpu = test_vcpu(memory);
    let expected_cr3 = vcpu.sregs.cr3;
    let region = vcpu
        .jit_compile_region()
        .expect("compile verified MOV-from-CR region")
        .expect("verified MOV-from-CR region must be native eligible");

    vcpu.jit_run_region_verified(&region);

    assert_eq!(vcpu.regs.rax, expected_cr3);
    assert_eq!(vcpu.sregs.cr3, expected_cr3);
    assert_eq!(vcpu.regs.rip, 5);
}

#[test]
fn jit_mov_from_control_register_privilege_faults_are_precise_and_noncommitting() {
    for (name, selector, vm) in [
        ("protected-cpl3", 3u16, false),
        ("virtual-8086-cs-rpl0", 0u16, true),
    ] {
        let memory = memory_with_code(&[0x0F, 0x20, 0xD8, 0xEB, 0x00, 0xF4]);
        let mut vcpu = test_vcpu(memory);
        vcpu.sregs.cs.selector = selector;
        vcpu.regs.rax = 0xA5A5_5A5A_DEAD_BEEF;
        if vm {
            vcpu.regs.rflags |= RFLAGS_VM;
        }
        let before = (vcpu.regs.rax, vcpu.regs.rflags, vcpu.sregs.cr3);

        let region = vcpu
            .jit_compile_region()
            .expect("compile guarded MOV-from-CR region")
            .expect("dynamic privilege must not block admission");
        vcpu.jit_run_region_native(&region);

        assert_eq!(vcpu.regs.rip, 0, "{name}: precise fault PC");
        assert_eq!(
            (vcpu.regs.rax, vcpu.regs.rflags, vcpu.sregs.cr3),
            before,
            "{name}: fault must not commit"
        );
        assert!(
            vcpu.step().is_err(),
            "{name}: direct path must deliver #GP(0)"
        );
    }
}

#[test]
fn jit_rejects_mov_from_control_register_outside_cs_l() {
    let memory = memory_with_code(&[0x66, 0x0F, 0x20, 0xD0, 0xEB, 0x00, 0xF4]);
    let mut long_mode = test_vcpu(memory.clone());
    assert!(
        long_mode.jit_compile_region().unwrap().is_some(),
        "64-bit MOV-from-CR baseline must compile"
    );

    let mut compatibility = test_vcpu(memory);
    compatibility.sregs.cs.l = false;
    compatibility.sregs.cs.db = true;
    compatibility.sregs.cr2 = 0xFFFF_AAAA_8765_4321;
    compatibility.regs.rax = u64::MAX;
    assert!(
        compatibility.jit_compile_region().unwrap().is_none(),
        "compatibility-mode MOV-from-CR must remain on the 32-bit direct path"
    );
    assert!(compatibility.step().unwrap().is_none());
    assert_eq!(compatibility.regs.rax, 0x8765_4321);
}

#[test]
fn jit_mov_from_control_register_observes_direct_callout_writes() {
    let memory = memory_with_code(&[
        0xE8, 0xFB, 0x00, 0x00, 0x00, // call 100h
        0x0F, 0x20, 0xD3, // mov rbx,cr2
        0xEB, 0x00, // jmp hlt
        0xF4,
    ]);
    // mov cr2,rax; ret
    memory
        .write_slice(&[0x0F, 0x22, 0xD0, 0xC3], GuestAddress(0x100))
        .unwrap();
    let mut direct = test_vcpu(memory.clone());
    let mut native = test_vcpu(memory);
    for vcpu in [&mut direct, &mut native] {
        vcpu.set_jit_call(true);
        vcpu.regs.rax = 0xCAFE_BABE_1234_5678;
        vcpu.regs.rbx = 0;
    }

    run_direct_to(&mut direct, 10);
    let region = native
        .jit_compile_region()
        .expect("compile control-register callout region")
        .expect("callout followed by MOV-from-CR must be native eligible");
    native.jit_run_region_native(&region);

    assert_eq!(native.sregs.cr2, direct.sregs.cr2);
    assert_eq!(native.regs.rbx, direct.regs.rbx);
    assert_eq!(native.regs.rbx, 0xCAFE_BABE_1234_5678);
    assert_eq!(native.regs.rsp, direct.regs.rsp);
    assert_eq!(native.regs.rflags, direct.regs.rflags);
    assert_eq!(native.regs.rip, 10);
}
