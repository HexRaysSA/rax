//! Native x86-64 JIT differentials for MOV-to-control-register state.

use super::*;
use crate::smir::lower::runtime::GuestRegs;
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
    vcpu.sregs.efer = (1 << 8) | (1 << 10);
    vcpu.sregs.cs.l = true;
    vcpu.sregs.cs.selector = 0;
    vcpu.sregs.tr.type_ = 9;
    vcpu.sregs.cr0 = 0x0005_0033;
    vcpu.sregs.cr2 = 0x2222_3333_4444_5555;
    vcpu.sregs.cr3 = 0x0000_1234_5000_0018;
    vcpu.sregs.cr4 = 1 << 5;
    vcpu.sregs.cr8 = 1;
    vcpu.mmu.set_task_priority((1 << 4) as u32).unwrap();
    vcpu.regs.rip = 0;
    vcpu.regs.rsp = 0x8000;
    vcpu.regs.rbp = 0x7000;
    vcpu.regs.rflags = 0x2 | 0x08D5 | (1 << 10);
    vcpu.set_jit_mem(false);
    vcpu.set_jit_call(false);
    vcpu
}

fn control_state(vcpu: &X86_64Vcpu) -> [u64; 6] {
    [
        vcpu.sregs.cr0,
        vcpu.sregs.cr2,
        vcpu.sregs.cr3,
        vcpu.sregs.cr4,
        vcpu.sregs.cr8,
        vcpu.sregs.efer,
    ]
}

fn scalar_state(vcpu: &X86_64Vcpu) -> [u64; 34] {
    [
        vcpu.regs.rax,
        vcpu.regs.rbx,
        vcpu.regs.rcx,
        vcpu.regs.rdx,
        vcpu.regs.rsi,
        vcpu.regs.rdi,
        vcpu.regs.rsp,
        vcpu.regs.rbp,
        vcpu.regs.r8,
        vcpu.regs.r9,
        vcpu.regs.r10,
        vcpu.regs.r11,
        vcpu.regs.r12,
        vcpu.regs.r13,
        vcpu.regs.r14,
        vcpu.regs.r15,
        vcpu.regs.r16,
        vcpu.regs.r17,
        vcpu.regs.r18,
        vcpu.regs.r19,
        vcpu.regs.r20,
        vcpu.regs.r21,
        vcpu.regs.r22,
        vcpu.regs.r23,
        vcpu.regs.r24,
        vcpu.regs.r25,
        vcpu.regs.r26,
        vcpu.regs.r27,
        vcpu.regs.r28,
        vcpu.regs.r29,
        vcpu.regs.r30,
        vcpu.regs.r31,
        vcpu.regs.rip,
        vcpu.regs.rflags,
    ]
}

#[test]
fn jit_mov_to_control_register_matches_direct_for_every_selector() {
    let cases: &[(&[u8], fn(&mut X86_64Vcpu))] = &[
        (&[0x0F, 0x22, 0xC0], |vcpu| vcpu.regs.rax = 0x0005_003B),
        (&[0x0F, 0x22, 0xD1], |vcpu| {
            vcpu.regs.rcx = 0xAAAA_BBBB_CCCC_DDDD
        }),
        (&[0x0F, 0x22, 0xDA], |vcpu| {
            vcpu.regs.rdx = 0x0000_1234_5678_9018
        }),
        (&[0x0F, 0x22, 0xE3], |vcpu| {
            vcpu.regs.rbx = (1 << 5) | (1 << 18)
        }),
        (&[0x45, 0x0F, 0x22, 0xC7], |vcpu| vcpu.regs.r15 = 0xD),
    ];

    for (bytes, configure) in cases {
        let mut code = bytes.to_vec();
        code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
        let memory = memory_with_code(&code);
        let mut direct = test_vcpu(memory.clone());
        let mut native = test_vcpu(memory);
        configure(&mut direct);
        configure(&mut native);
        let mut expected_regs = scalar_state(&native);
        expected_regs[32] = bytes.len() as u64;

        assert!(direct.step().expect("direct MOV-to-CR").is_none());
        let region = native
            .jit_compile_region()
            .expect("compile MOV-to-CR region")
            .expect("MOV-to-CR region must be native eligible");
        native.jit_run_region_native(&region);

        assert_eq!(
            control_state(&native),
            control_state(&direct),
            "{bytes:02X?}"
        );
        assert_eq!(scalar_state(&native), scalar_state(&direct), "{bytes:02X?}");
        assert_eq!(
            scalar_state(&native),
            expected_regs,
            "MOV-to-CR preserves GPR/RFLAGS"
        );
        assert_eq!(native.regs.rip, bytes.len() as u64);
    }
}

#[test]
fn jit_mov_to_control_register_handles_rsp_and_rbp_sources() {
    for (bytes, expected) in [
        (&[0x0F, 0x22, 0xD4][..], 0x8000), // mov cr2,rsp
        (&[0x44, 0x0F, 0x22, 0xC5], 0xF),  // mov cr8,rbp
    ] {
        let mut code = bytes.to_vec();
        code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
        let memory = memory_with_code(&code);
        let mut direct = test_vcpu(memory.clone());
        let mut native = test_vcpu(memory);
        if bytes.len() == 4 {
            direct.regs.rbp = expected;
            native.regs.rbp = expected;
        }

        assert!(direct.step().unwrap().is_none());
        let region = native
            .jit_compile_region()
            .expect("compile stack-source MOV-to-CR")
            .expect("state-backed RSP/RBP sources must be native eligible");
        native.jit_run_region_native(&region);

        assert_eq!(control_state(&native), control_state(&direct));
        if bytes.len() == 3 {
            assert_eq!(native.sregs.cr2, expected);
        } else {
            assert_eq!(native.sregs.cr8, expected);
        }
        assert_eq!(native.regs.rsp, direct.regs.rsp);
        assert_eq!(native.regs.rbp, direct.regs.rbp);
        assert_eq!(native.regs.rflags, direct.regs.rflags);
        assert_eq!(native.regs.rip, bytes.len() as u64);
    }
}

#[test]
fn jit_verify_compares_and_adopts_control_and_efer_state() {
    let memory = memory_with_code(&[0x0F, 0x22, 0xD0, 0xEB, 0x00, 0xF4]);
    let mut vcpu = test_vcpu(memory);
    vcpu.regs.rax = 0x0123_4567_89AB_CDEF;
    let expected_efer = vcpu.sregs.efer;
    let region = vcpu
        .jit_compile_region()
        .expect("compile verified MOV-to-CR region")
        .expect("verified MOV-to-CR region must be native eligible");

    vcpu.jit_run_region_verified(&region);

    assert_eq!(vcpu.sregs.cr2, 0x0123_4567_89AB_CDEF);
    assert_eq!(vcpu.sregs.efer, expected_efer);
    assert_eq!(vcpu.regs.rip, 3);
}

#[test]
fn jit_mov_to_control_register_faults_are_dynamic_precise_and_noncommitting() {
    let privilege_cases: [(&str, fn(&mut X86_64Vcpu)); 2] = [
        ("protected-cpl3", |vcpu| vcpu.sregs.cs.selector = 3),
        ("virtual-8086-cs-rpl0", |vcpu| vcpu.regs.rflags |= RFLAGS_VM),
    ];
    for (name, configure) in privilege_cases {
        let memory = memory_with_code(&[0x0F, 0x22, 0xD0, 0xEB, 0x00, 0xF4]);
        let mut vcpu = test_vcpu(memory);
        vcpu.regs.rax = 0xAAAA_BBBB_CCCC_DDDD;
        configure(&mut vcpu);
        let before = (control_state(&vcpu), scalar_state(&vcpu));

        let region = vcpu
            .jit_compile_region()
            .expect("compile privilege-guarded MOV-to-CR")
            .expect("dynamic privilege must not block admission");
        vcpu.jit_run_region_native(&region);

        assert_eq!(vcpu.regs.rip, 0, "{name}: precise fault PC");
        assert_eq!(
            (control_state(&vcpu), scalar_state(&vcpu)),
            before,
            "{name}"
        );
        assert!(vcpu.step().is_err(), "{name}: direct replay must #GP(0)");
    }

    for (name, bytes, value) in [
        ("CR0.PG without PE", &[0x0F, 0x22, 0xC0][..], 1 << 31),
        ("CR3 above MAXPHYADDR", &[0x0F, 0x22, 0xD8], 1 << 48),
        ("reserved CR4", &[0x0F, 0x22, 0xE0], 1 << 15),
        ("wide CR8", &[0x44, 0x0F, 0x22, 0xC0], 0x10),
    ] {
        let mut code = bytes.to_vec();
        code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
        let memory = memory_with_code(&code);
        let mut vcpu = test_vcpu(memory);
        vcpu.regs.rax = value;
        let before = (control_state(&vcpu), scalar_state(&vcpu));
        let region = vcpu
            .jit_compile_region()
            .expect("compile value-guarded MOV-to-CR")
            .expect("dynamic source value must not block admission");
        vcpu.jit_run_region_native(&region);

        assert_eq!(vcpu.regs.rip, 0, "{name}: precise fault PC");
        assert_eq!(
            (control_state(&vcpu), scalar_state(&vcpu)),
            before,
            "{name}"
        );
        assert!(vcpu.step().is_err(), "{name}: direct replay must #GP(0)");
    }
}

#[test]
fn jit_mov_to_control_register_real_mode_bypasses_cpl_guard() {
    let memory = memory_with_code(&[0x0F, 0x22, 0xD0, 0xEB, 0x00, 0xF4]);
    let mut direct = test_vcpu(memory.clone());
    let mut native = test_vcpu(memory);
    for vcpu in [&mut direct, &mut native] {
        vcpu.sregs.cr0 = 0;
        vcpu.sregs.cs.selector = 3;
        vcpu.regs.rax = 0xAAAA_BBBB_CCCC_DDDD;
    }

    assert!(direct.step().unwrap().is_none());
    let region = native
        .jit_compile_region()
        .expect("compile real-mode MOV-to-CR")
        .expect("real-mode write must be native eligible");
    native.jit_run_region_native(&region);

    assert_eq!(native.sregs.cr2, direct.sregs.cr2);
    assert_eq!(native.sregs.cr2, 0xAAAA_BBBB_CCCC_DDDD);
    assert_eq!(native.regs.rip, 3);
}

#[test]
fn jit_mov_to_control_register_ends_at_exact_next_instruction() {
    let memory = memory_with_code(&[
        0x0F, 0x22, 0xD0, // mov cr2,rax
        0x48, 0xBB, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // mov rbx,imm64
        0xEB, 0x00, 0xF4,
    ]);
    let mut vcpu = test_vcpu(memory);
    vcpu.regs.rax = 0xCAFE_BABE_1234_5678;
    vcpu.regs.rbx = 0xDEAD_BEEF;
    let first = vcpu
        .jit_compile_region()
        .expect("compile control-write frontier")
        .expect("control write must be native eligible");

    vcpu.jit_run_region_native(&first);

    assert_eq!(vcpu.regs.rip, 3);
    assert_eq!(vcpu.sregs.cr2, 0xCAFE_BABE_1234_5678);
    assert_eq!(
        vcpu.regs.rbx, 0xDEAD_BEEF,
        "next instruction did not execute"
    );

    let continuation = vcpu
        .jit_compile_region()
        .expect("compile post-control continuation")
        .expect("continuation must remain independently native eligible");
    vcpu.jit_run_region_native(&continuation);
    assert_eq!(vcpu.regs.rbx, 0x1122_3344_5566_7788);
    assert_eq!(vcpu.regs.rip, 15);
}

#[test]
fn jit_rejects_mov_to_control_register_outside_cs_l() {
    let memory = memory_with_code(&[0x66, 0x0F, 0x22, 0xD0, 0xEB, 0x00, 0xF4]);
    let mut long_mode = test_vcpu(memory.clone());
    assert!(
        long_mode.jit_compile_region().unwrap().is_some(),
        "64-bit MOV-to-CR baseline must compile"
    );

    let mut compatibility = test_vcpu(memory);
    compatibility.sregs.cs.l = false;
    compatibility.sregs.cs.db = true;
    compatibility.regs.rax = 0xFFFF_AAAA_8765_4321;
    assert!(
        compatibility.jit_compile_region().unwrap().is_none(),
        "compatibility-mode MOV-to-CR must remain on the 32-bit direct path"
    );
    assert!(compatibility.step().unwrap().is_none());
    assert_eq!(compatibility.sregs.cr2, 0x8765_4321);
}

#[test]
fn jit_control_helper_models_ia32e_transitions_atomically() {
    let memory = memory_with_code(&[0xF4]);
    let mut vcpu = test_vcpu(memory);
    let mut state = GuestRegs::default();
    state.ctx = (&mut vcpu as *mut X86_64Vcpu) as u64;
    state.cpl = 0;
    state.cr0 = 1;
    state.cr4 = 1 << 5;
    state.efer = 1 << 8;
    state.cs_l = 0;
    state.tr_type = 9;

    let entered = unsafe { rax_jit_write_control(&mut state, 0, (1 << 31) | 1) };
    assert_eq!(entered, 1);
    assert_ne!(state.efer & (1 << 10), 0);
    assert_ne!(state.cr0 & (1 << 31), 0);

    let exited = unsafe { rax_jit_write_control(&mut state, 0, 1) };
    assert_eq!(exited, 1);
    assert_eq!(state.efer & (1 << 10), 0);
    assert_eq!(state.cr0 & (1 << 31), 0);

    state.cr0 = 1;
    state.efer = 1 << 8;
    state.cs_l = 1;
    let before = (state.cr0, state.efer);
    let rejected = unsafe { rax_jit_write_control(&mut state, 0, (1 << 31) | 1) };
    assert_eq!(rejected, 0);
    assert_eq!((state.cr0, state.efer), before);
}
