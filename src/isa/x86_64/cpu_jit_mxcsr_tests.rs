//! CPU-level native x86-64 JIT differentials for MXCSR memory operations.

use super::*;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const DEST: u64 = 0x4000;
const STACK: u64 = 0x8000;
const MXCSR: u32 = 0xFFE5;

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
    vcpu.sregs.cr0 = 0x21;
    vcpu.regs.rip = 0;
    vcpu.regs.rsp = STACK;
    vcpu.regs.rbp = 0x7000;
    vcpu.regs.rbx = DEST;
    vcpu.regs.rax = 0xA5A5_5A5A_DEAD_BEEF;
    vcpu.regs.rflags = 0x2 | 0x08D5 | (1 << 10);
    vcpu.mxcsr = MXCSR;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);
    vcpu
}

fn run_direct_to(vcpu: &mut X86_64Vcpu, target: u64) {
    for _ in 0..32 {
        if vcpu.regs.rip == target {
            return;
        }
        assert!(
            vcpu.step().expect("direct MXCSR sequence").is_none(),
            "unexpected direct exit at {:#x}",
            vcpu.regs.rip
        );
    }
    panic!("direct execution did not reach {target:#x}");
}

#[test]
fn jit_unmasked_mxcsr_executes_exception_free_replay_and_rejects_fp_arithmetic() {
    let safe = [0x66, 0x0F, 0x38, 0x17, 0xC1, 0xEB, 0x00, 0xF4]; // PTEST XMM0,XMM1
    let unsafe_fp = [0x0F, 0x58, 0xC1, 0xEB, 0x00, 0xF4]; // ADDPS XMM0,XMM1
    for mxcsr in [0x0041, 0x0000, 0x1F00] {
        let mut direct = test_vcpu(memory_with_code(&safe));
        let mut native = test_vcpu(memory_with_code(&safe));
        for cpu in [&mut direct, &mut native] {
            cpu.mxcsr = mxcsr;
            cpu.regs.xmm[0] = [0x7FF0_0000_0000_0001, u64::MAX];
            cpu.regs.xmm[1] = [u64::MAX, 0];
        }
        run_direct_to(&mut direct, 7);
        let mut rejected = test_vcpu(memory_with_code(&unsafe_fp));
        rejected.mxcsr = mxcsr;
        assert!(rejected.jit_compile_region().unwrap().is_none());
        if !crate::smir::lower::runtime::x86_native_unmasked_mxcsr_supported() {
            assert!(native.jit_compile_region().unwrap().is_none());
            continue;
        }
        let region = native
            .jit_compile_region()
            .expect("compile safe replay")
            .expect("unmasked exception-free replay must be admitted");
        assert!(region.uses_vector);
        native.jit_run_region_native(&region);
        assert_eq!(native.regs.rip, direct.regs.rip);
        assert_eq!(native.regs.rflags, direct.regs.rflags);
        assert_eq!(native.regs.xmm, direct.regs.xmm);
        assert_eq!(native.mxcsr, direct.mxcsr);
    }
}

fn exception_without_idt(vcpu: &mut X86_64Vcpu) -> String {
    format!(
        "{:#}",
        vcpu.step()
            .expect_err("exception delivery must fail against the empty test IDT")
    )
}

fn read_u32(memory: &GuestMemoryMmap, addr: u64) -> u32 {
    let mut bytes = [0u8; 4];
    memory.read_slice(&mut bytes, GuestAddress(addr)).unwrap();
    u32::from_le_bytes(bytes)
}

#[test]
fn direct_mxcsr_load_reserved_bits_raise_precise_gp_without_commit() {
    for (name, instruction) in [
        ("legacy", &[0x0F, 0xAE, 0x13][..]),
        ("VEX.W0", &[0xC5, 0xF8, 0xAE, 0x13][..]),
        ("VEX.W1", &[0xC4, 0xE1, 0xF8, 0xAE, 0x13][..]),
    ] {
        let memory = memory_with_code(instruction);
        memory
            .write_slice(&0x0001_1F80u32.to_le_bytes(), GuestAddress(DEST))
            .unwrap();
        let mut vcpu = test_vcpu(memory);
        let before = (vcpu.mxcsr, vcpu.regs.clone());

        let error = exception_without_idt(&mut vcpu);
        assert!(
            error.contains("IDT entry 13 not present"),
            "{name}: wrong exception: {error}"
        );
        assert_eq!(vcpu.mxcsr, before.0, "{name}: MXCSR");
        assert_eq!(vcpu.regs.rip, 0, "{name}: fault RIP");
        assert_eq!(vcpu.regs.rax, before.1.rax, "{name}: RAX");
        assert_eq!(vcpu.regs.rbx, before.1.rbx, "{name}: RBX");
        assert_eq!(vcpu.regs.rflags, before.1.rflags, "{name}: RFLAGS");
    }
}

#[test]
fn jit_mxcsr_loads_match_direct_at_the_exact_completed_instruction_frontier() {
    const LOADED_MXCSR: u32 = 0x3F80;

    for (name, instruction) in [
        ("legacy", &[0x0F, 0xAE, 0x13][..]),
        ("VEX.W0", &[0xC5, 0xF8, 0xAE, 0x13][..]),
        ("VEX.W1", &[0xC4, 0xE1, 0xF8, 0xAE, 0x13][..]),
    ] {
        let mut code = instruction.to_vec();
        code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
        let direct_memory = memory_with_code(&code);
        let native_memory = memory_with_code(&code);
        for memory in [&direct_memory, &native_memory] {
            memory
                .write_slice(&LOADED_MXCSR.to_le_bytes(), GuestAddress(DEST))
                .unwrap();
        }
        let mut direct = test_vcpu(direct_memory);
        let mut native = test_vcpu(native_memory);

        assert!(
            direct.step().expect("direct MXCSR load").is_none(),
            "{name}: direct exit"
        );
        let region = native
            .jit_compile_region()
            .unwrap_or_else(|error| panic!("{name}: compile error: {error:?}"))
            .unwrap_or_else(|| panic!("{name}: MXCSR load must be native eligible"));
        assert!(!region.uses_vector, "{name}");
        assert!(!region.uses_xmm_state, "{name}");
        assert!(region.uses_mxcsr_state, "{name}");
        native.jit_run_region_native(&region);

        assert_eq!(native.mxcsr, direct.mxcsr, "{name}: MXCSR");
        assert_eq!(native.mxcsr, LOADED_MXCSR, "{name}: loaded value");
        assert_eq!(native.regs.rax, direct.regs.rax, "{name}: RAX");
        assert_eq!(native.regs.rbx, direct.regs.rbx, "{name}: RBX");
        assert_eq!(native.regs.rflags, direct.regs.rflags, "{name}: RFLAGS");
        assert_eq!(
            native.regs.rip,
            instruction.len() as u64,
            "{name}: completed-instruction frontier"
        );
        assert_eq!(native.regs.rip, direct.regs.rip, "{name}: direct frontier");
    }
}

#[test]
fn jit_mxcsr_load_address_forms_match_direct_with_exact_width_arithmetic() {
    const LOADED_MXCSR: u32 = 0x7F80;

    for (name, instruction, address_case) in [
        (
            "RIP-relative",
            &[0x0F, 0xAE, 0x15, 0xF9, 0x3F, 0x00, 0x00][..],
            0u8,
        ),
        (
            "absolute-SIB",
            &[0x0F, 0xAE, 0x14, 0x25, 0x00, 0x40, 0x00, 0x00],
            0,
        ),
        ("addr32-wrap-SIB", &[0x67, 0x0F, 0xAE, 0x14, 0x77], 1),
        ("FS-base", &[0x64, 0x0F, 0xAE, 0x13], 2),
        ("base-index-scale", &[0x0F, 0xAE, 0x14, 0x4B], 3),
        ("RSP-base", &[0x0F, 0xAE, 0x54, 0x24, 0x08], 4),
        ("RBP-base", &[0x0F, 0xAE, 0x55, 0x00], 5),
    ] {
        let mut code = instruction.to_vec();
        code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
        let direct_memory = memory_with_code(&code);
        let native_memory = memory_with_code(&code);
        for memory in [&direct_memory, &native_memory] {
            memory
                .write_slice(&LOADED_MXCSR.to_le_bytes(), GuestAddress(DEST))
                .unwrap();
        }
        let mut direct = test_vcpu(direct_memory);
        let mut native = test_vcpu(native_memory);
        for vcpu in [&mut direct, &mut native] {
            match address_case {
                0 => {}
                1 => {
                    vcpu.regs.rdi = 0xFFFF_FFFF_0000_3FF0;
                    vcpu.regs.rsi = 0x8000_0000_0000_0008;
                }
                2 => {
                    vcpu.sregs.fs.base = 0x1000;
                    vcpu.regs.rbx = 0x3000;
                }
                3 => {
                    vcpu.regs.rbx = 0x3FE0;
                    vcpu.regs.rcx = 0x10;
                }
                4 => vcpu.regs.rsp = DEST - 8,
                5 => vcpu.regs.rbp = DEST,
                _ => unreachable!(),
            }
        }

        assert!(
            direct.step().expect("direct addressed LDMXCSR").is_none(),
            "{name}: direct exit"
        );
        let region = native
            .jit_compile_region()
            .unwrap_or_else(|error| panic!("{name}: compile error: {error:?}"))
            .unwrap_or_else(|| panic!("{name}: addressed LDMXCSR must be native eligible"));
        native.jit_run_region_native(&region);

        assert_eq!(native.mxcsr, LOADED_MXCSR, "{name}: loaded value");
        assert_eq!(native.mxcsr, direct.mxcsr, "{name}: MXCSR");
        assert_eq!(native.regs.rip, instruction.len() as u64, "{name}: PC");
        assert_eq!(native.regs.rip, direct.regs.rip, "{name}: direct PC");
        assert_eq!(native.regs.rsp, direct.regs.rsp, "{name}: RSP");
        assert_eq!(native.regs.rbp, direct.regs.rbp, "{name}: RBP");
        assert_eq!(native.regs.rflags, direct.regs.rflags, "{name}: RFLAGS");
    }
}

#[test]
fn jit_mxcsr_load_reserved_bits_deopt_precisely_without_commit() {
    for (name, instruction) in [
        ("legacy", &[0x0F, 0xAE, 0x13][..]),
        ("VEX.W0", &[0xC5, 0xF8, 0xAE, 0x13][..]),
        ("VEX.W1", &[0xC4, 0xE1, 0xF8, 0xAE, 0x13][..]),
    ] {
        let mut code = instruction.to_vec();
        code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
        let memory = memory_with_code(&code);
        memory
            .write_slice(&0x0001_1F80u32.to_le_bytes(), GuestAddress(DEST))
            .unwrap();
        let mut native = test_vcpu(memory);
        let before = (
            native.mxcsr,
            native.regs.rax,
            native.regs.rbx,
            native.regs.rflags,
        );

        let region = native
            .jit_compile_region()
            .unwrap_or_else(|error| panic!("{name}: compile error: {error:?}"))
            .unwrap_or_else(|| panic!("{name}: dynamic reserved-bit guard must be native"));
        native.jit_run_region_native(&region);
        assert_eq!(native.regs.rip, 0, "{name}: fault restart PC");
        assert_eq!(
            (
                native.mxcsr,
                native.regs.rax,
                native.regs.rbx,
                native.regs.rflags,
            ),
            before,
            "{name}: reserved-bit path committed state"
        );
        let error = exception_without_idt(&mut native);
        assert!(
            error.contains("IDT entry 13 not present"),
            "{name}: wrong replay exception: {error}"
        );
    }
}

#[test]
fn jit_mxcsr_load_memory_fault_is_precise_and_noncommitting() {
    let code = [0x0F, 0xAE, 0x13, 0xEB, 0x00, 0xF4];
    let memory = memory_with_code(&code);
    let mut native = test_vcpu(memory);
    native.regs.rbx = 0x20_000;
    let before = (
        native.mxcsr,
        native.regs.rax,
        native.regs.rbx,
        native.regs.rflags,
    );

    let region = native
        .jit_compile_region()
        .expect("compile faulting MXCSR-load region")
        .expect("dynamic memory fault must not block admission");
    assert!(region.uses_mxcsr_state);
    native.jit_run_region_native(&region);

    assert_eq!(native.regs.rip, 0, "fault must restart LDMXCSR");
    assert_eq!(
        (
            native.mxcsr,
            native.regs.rax,
            native.regs.rbx,
            native.regs.rflags,
        ),
        before,
        "faulting LDMXCSR committed architectural state"
    );
    assert!(
        native.step().is_err(),
        "direct replay must deliver the guest memory fault"
    );
    assert_eq!(native.regs.rip, 0);
}

#[test]
fn jit_mxcsr_load_deopts_before_an_mmio_read() {
    const LAPIC_BASE: u64 = 0xFEE0_0000;
    let code = [0x0F, 0xAE, 0x13, 0xEB, 0x00, 0xF4];
    let memory = memory_with_code(&code);
    let mut native = test_vcpu(memory);
    native.regs.rbx = LAPIC_BASE;
    let before = (
        native.mxcsr,
        native.regs.rax,
        native.regs.rbx,
        native.regs.rflags,
    );

    let region = native
        .jit_compile_region()
        .expect("compile MMIO-source MXCSR-load region")
        .expect("dynamic RAM/MMIO classification must not block admission");
    native.jit_run_region_native(&region);
    assert_eq!(native.regs.rip, 0, "native helper speculatively read MMIO");
    assert_eq!(
        (
            native.mxcsr,
            native.regs.rax,
            native.regs.rbx,
            native.regs.rflags,
        ),
        before,
        "MMIO preflight committed architectural state"
    );

    assert!(
        native
            .step()
            .expect("single direct LAPIC-backed LDMXCSR")
            .is_none()
    );
    assert_eq!(native.regs.rip, 3);
}

#[test]
fn jit_rex2_mxcsr_load_admission_is_dynamic_and_apx_precedes_memory() {
    const LOADED_MXCSR: u32 = 0x5F80;
    // REX2.M=1 LDMXCSR [R31]; JMP HLT; HLT.
    let code = [0xD5, 0x91, 0xAE, 0x17, 0xEB, 0x00, 0xF4];
    let memory = memory_with_code(&code);
    memory
        .write_slice(&LOADED_MXCSR.to_le_bytes(), GuestAddress(DEST))
        .unwrap();

    let mut disabled = test_vcpu(memory.clone());
    disabled.regs.r31 = 0x20_000;
    disabled.sregs.cr0 |= 1 << 3;
    let before = (disabled.mxcsr, disabled.regs.r31, disabled.regs.rflags);
    let region = disabled
        .jit_compile_region()
        .expect("compile REX2 MXCSR-load region")
        .expect("REX2 LDMXCSR must retain a dynamic APX guard");
    disabled.jit_run_region_native(&region);
    assert_eq!(disabled.regs.rip, 0);
    assert_eq!(
        (disabled.mxcsr, disabled.regs.r31, disabled.regs.rflags),
        before
    );
    assert!(exception_without_idt(&mut disabled).contains("IDT entry 6 not present"));

    let mut direct = test_vcpu(memory.clone());
    let mut native = test_vcpu(memory);
    for vcpu in [&mut direct, &mut native] {
        vcpu.regs.r31 = DEST;
        vcpu.set_apx_enabled(true);
    }
    assert!(direct.step().expect("direct REX2 LDMXCSR").is_none());
    let region = native
        .jit_compile_region()
        .expect("compile enabled REX2 MXCSR-load region")
        .expect("enabled REX2 LDMXCSR must be native eligible");
    native.jit_run_region_native(&region);
    assert_eq!(native.regs.rip, 4);
    assert_eq!(native.regs.rip, direct.regs.rip);
    assert_eq!(native.mxcsr, LOADED_MXCSR);
    assert_eq!(native.mxcsr, direct.mxcsr);
    assert_eq!(native.regs.r31, direct.regs.r31);
    assert_eq!(native.regs.rflags, direct.regs.rflags);
}

#[test]
fn jit_mxcsr_ts_guard_deopts_before_loads_and_stores_for_legacy_and_vex() {
    const LOAD_VALUE: u32 = 0x5F80;
    const STORE_SENTINEL: u32 = 0xDEAD_BEEF;

    for (name, instruction, is_store) in [
        ("legacy-load", &[0x0F, 0xAE, 0x13][..], false),
        ("VEX.W0-load", &[0xC5, 0xF8, 0xAE, 0x13][..], false),
        ("VEX.W1-load", &[0xC4, 0xE1, 0xF8, 0xAE, 0x13][..], false),
        ("legacy-store", &[0x0F, 0xAE, 0x1B][..], true),
        ("VEX.W0-store", &[0xC5, 0xF8, 0xAE, 0x1B][..], true),
        ("VEX.W1-store", &[0xC4, 0xE1, 0xF8, 0xAE, 0x1B][..], true),
    ] {
        let mut code = instruction.to_vec();
        code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
        let memory = memory_with_code(&code);
        memory
            .write_slice(
                &(if is_store { STORE_SENTINEL } else { LOAD_VALUE }).to_le_bytes(),
                GuestAddress(DEST),
            )
            .unwrap();
        let mut native = test_vcpu(memory.clone());
        native.sregs.cr0 |= 1 << 3;
        let before = (
            native.mxcsr,
            native.regs.rax,
            native.regs.rbx,
            native.regs.rflags,
        );

        let region = native
            .jit_compile_region()
            .unwrap_or_else(|error| panic!("{name}: compile error: {error:?}"))
            .unwrap_or_else(|| panic!("{name}: CR0.TS must remain a dynamic native guard"));
        native.jit_run_region_native(&region);

        assert_eq!(native.regs.rip, 0, "{name}: deoptimization PC");
        assert_eq!(
            (
                native.mxcsr,
                native.regs.rax,
                native.regs.rbx,
                native.regs.rflags,
            ),
            before,
            "{name}: native guard committed state"
        );
        assert_eq!(
            read_u32(&memory, DEST),
            if is_store { STORE_SENTINEL } else { LOAD_VALUE },
            "{name}: native guard touched memory"
        );

        let error = exception_without_idt(&mut native);
        assert!(
            error.contains("IDT entry 7 not present"),
            "{name}: direct replay did not deliver #NM: {error}"
        );
    }
}

#[test]
fn compatibility_mode_mxcsr_memory_operations_stay_out_of_the_long_mode_lifter() {
    for instruction in [
        &[0x0F, 0xAE, 0x13, 0xEB, 0x00, 0xF4][..],
        &[0x0F, 0xAE, 0x1B, 0xEB, 0x00, 0xF4],
        &[0xC5, 0xF8, 0xAE, 0x13, 0xEB, 0x00, 0xF4],
        &[0xC5, 0xF8, 0xAE, 0x1B, 0xEB, 0x00, 0xF4],
    ] {
        let memory = memory_with_code(instruction);
        let mut compatibility = test_vcpu(memory);
        compatibility.sregs.cs.l = false;
        assert!(
            compatibility.jit_compile_region().unwrap().is_none(),
            "64-bit SMIR address semantics admitted compatibility MXCSR form {instruction:02X?}"
        );
    }
}

#[test]
fn jit_mxcsr_stores_match_direct_for_legacy_and_both_vex_wig_encodings() {
    for (name, instruction) in [
        ("legacy", &[0x0F, 0xAE, 0x1B][..]),
        ("VEX.W0", &[0xC5, 0xF8, 0xAE, 0x1B][..]),
        ("VEX.W1", &[0xC4, 0xE1, 0xF8, 0xAE, 0x1B][..]),
    ] {
        let mut code = instruction.to_vec();
        code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
        let frontier = code.len() as u64 - 1;
        let direct_memory = memory_with_code(&code);
        let native_memory = memory_with_code(&code);
        let mut direct = test_vcpu(direct_memory.clone());
        let mut native = test_vcpu(native_memory.clone());

        run_direct_to(&mut direct, frontier);
        let region = native
            .jit_compile_region()
            .unwrap_or_else(|error| panic!("{name}: compile error: {error:?}"))
            .unwrap_or_else(|| panic!("{name}: MXCSR store must be native eligible"));
        assert!(!region.uses_vector, "{name}");
        assert!(!region.uses_xmm_state, "{name}");
        assert!(region.uses_mxcsr_state, "{name}");
        native.jit_run_region_native(&region);

        assert_eq!(read_u32(&direct_memory, DEST), MXCSR, "{name}: direct");
        assert_eq!(
            read_u32(&native_memory, DEST),
            read_u32(&direct_memory, DEST),
            "{name}: native store"
        );
        assert_eq!(native.mxcsr, direct.mxcsr, "{name}: MXCSR");
        assert_eq!(native.regs.rax, direct.regs.rax, "{name}: RAX");
        assert_eq!(native.regs.rbx, direct.regs.rbx, "{name}: RBX");
        assert_eq!(native.regs.rflags, direct.regs.rflags, "{name}: RFLAGS");
        assert_eq!(native.regs.rip, frontier, "{name}: frontier");
    }
}

#[test]
fn jit_rex2_mxcsr_store_admission_is_dynamic_and_apx_precedes_ts_and_memory() {
    const STORE_SENTINEL: u32 = 0xDEAD_BEEF;
    // REX2.M=1 STMXCSR [R31]; JMP HLT; HLT.
    let code = [0xD5, 0x91, 0xAE, 0x1F, 0xEB, 0x00, 0xF4];

    let disabled_memory = memory_with_code(&code);
    disabled_memory
        .write_slice(&STORE_SENTINEL.to_le_bytes(), GuestAddress(DEST))
        .unwrap();
    let mut disabled = test_vcpu(disabled_memory.clone());
    disabled.regs.r31 = DEST;
    disabled.sregs.cr0 |= 1 << 3;
    let before = (disabled.mxcsr, disabled.regs.r31, disabled.regs.rflags);
    let region = disabled
        .jit_compile_region()
        .expect("compile REX2 MXCSR-store region")
        .expect("REX2 STMXCSR must retain a dynamic APX guard");
    disabled.jit_run_region_native(&region);
    assert_eq!(disabled.regs.rip, 0);
    assert_eq!(
        (disabled.mxcsr, disabled.regs.r31, disabled.regs.rflags),
        before
    );
    assert_eq!(read_u32(&disabled_memory, DEST), STORE_SENTINEL);
    assert!(
        exception_without_idt(&mut disabled).contains("IDT entry 6 not present"),
        "APX-disabled REX2 must deliver #UD before CR0.TS can deliver #NM"
    );

    let direct_memory = memory_with_code(&code);
    let native_memory = memory_with_code(&code);
    for memory in [&direct_memory, &native_memory] {
        memory
            .write_slice(&STORE_SENTINEL.to_le_bytes(), GuestAddress(DEST))
            .unwrap();
    }
    let mut direct = test_vcpu(direct_memory.clone());
    let mut native = test_vcpu(native_memory.clone());
    for vcpu in [&mut direct, &mut native] {
        vcpu.regs.r31 = DEST;
        vcpu.set_apx_enabled(true);
    }

    run_direct_to(&mut direct, 6);
    let region = native
        .jit_compile_region()
        .expect("compile enabled REX2 MXCSR-store region")
        .expect("enabled REX2 STMXCSR must be native eligible");
    assert!(region.uses_mxcsr_state);
    native.jit_run_region_native(&region);

    assert_eq!(native.regs.rip, 6);
    assert_eq!(native.regs.rip, direct.regs.rip);
    assert_eq!(read_u32(&native_memory, DEST), MXCSR);
    assert_eq!(
        read_u32(&native_memory, DEST),
        read_u32(&direct_memory, DEST)
    );
    assert_eq!(native.mxcsr, direct.mxcsr);
    assert_eq!(native.regs.r31, direct.regs.r31);
    assert_eq!(native.regs.rflags, direct.regs.rflags);
}

#[test]
fn jit_mxcsr_store_fault_is_precise_and_noncommitting() {
    let code = [0x0F, 0xAE, 0x1B, 0xEB, 0x00, 0xF4];
    let memory = memory_with_code(&code);
    let mut native = test_vcpu(memory);
    native.regs.rbx = 0x20_000;
    let before = (
        native.mxcsr,
        native.regs.rax,
        native.regs.rbx,
        native.regs.rflags,
    );

    let region = native
        .jit_compile_region()
        .expect("compile faulting MXCSR-store region")
        .expect("dynamic memory fault must not block admission");
    assert!(region.uses_mxcsr_state);
    native.jit_run_region_native(&region);

    assert_eq!(native.regs.rip, 0, "fault must restart STMXCSR");
    assert_eq!(
        (
            native.mxcsr,
            native.regs.rax,
            native.regs.rbx,
            native.regs.rflags,
        ),
        before,
        "faulting STMXCSR committed architectural state"
    );
    assert!(
        native.step().is_err(),
        "direct replay must deliver the guest memory fault"
    );
    assert_eq!(native.regs.rip, 0);
}

#[test]
fn jit_mxcsr_state_is_coherent_across_interpreter_callouts() {
    // call 100h; stmxcsr [rbx]; jmp hlt; hlt
    let code = [
        0xE8, 0xFB, 0x00, 0x00, 0x00, 0x0F, 0xAE, 0x1B, 0xEB, 0x00, 0xF4,
    ];
    let direct_memory = memory_with_code(&code);
    let native_memory = memory_with_code(&code);
    // ldmxcsr [rbx+4]; ret
    for memory in [&direct_memory, &native_memory] {
        memory
            .write_slice(&[0x0F, 0xAE, 0x53, 0x04, 0xC3], GuestAddress(0x100))
            .unwrap();
        memory
            .write_slice(&MXCSR.to_le_bytes(), GuestAddress(DEST + 4))
            .unwrap();
    }

    let mut direct = test_vcpu(direct_memory.clone());
    let mut native = test_vcpu(native_memory.clone());
    direct.mxcsr = 0x1F80;
    native.mxcsr = 0x1F80;
    native.set_jit_call(true);
    run_direct_to(&mut direct, 10);

    let region = native
        .jit_compile_region()
        .expect("compile MXCSR callout region")
        .expect("MXCSR callout region must be native eligible");
    assert!(region.uses_mxcsr_state);
    assert!(!region.uses_vector);
    native.jit_run_region_native(&region);

    assert_eq!(native.regs.rip, 10);
    assert_eq!(native.regs.rsp, STACK);
    assert_eq!(native.mxcsr, MXCSR, "callee MXCSR update was not imported");
    assert_eq!(read_u32(&native_memory, DEST), MXCSR);
    assert_eq!(
        read_u32(&native_memory, DEST),
        read_u32(&direct_memory, DEST)
    );
    assert_eq!(native.regs.rflags, direct.regs.rflags);
    assert_eq!(native.regs.rax, direct.regs.rax);
}
