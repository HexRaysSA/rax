//! Direct and native tests for architectural REX2 admission.

use super::*;
use crate::vm::vcpu::VCpu;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

fn memory_with_code(code: &[u8]) -> Arc<GuestMemoryMmap> {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    memory.write_slice(code, GuestAddress(0)).unwrap();
    memory
}

fn test_vcpu(memory: Arc<GuestMemoryMmap>) -> X86_64Vcpu {
    let mut vcpu = X86_64Vcpu::new(0, memory);
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.sregs.cs.selector = 0;
    vcpu.sregs.cr0 = 0x0005_0033;
    vcpu.regs.rip = 0;
    vcpu.regs.rsp = 0x3000;
    vcpu.regs.rax = u64::MAX;
    vcpu.regs.rbx = 0x0123_4567_89AB_CDEF;
    vcpu.regs.rcx = 0x1020_3040_5060_7080;
    vcpu.regs.r16 = 0x0200;
    vcpu.regs.r31 = 0x3131_3131_3131_3131;
    // Keep every modeled arithmetic/control bit nonzero except AF. The
    // linux/amd64 user-mode emulator used for cross-host native validation
    // clears imported AF across an otherwise flag-neutral pushfq/popfq guard;
    // the dedicated native guard test retains an AF=1 hardware regression.
    vcpu.regs.rflags = 0x2 | 0x08C5 | flags::bits::DF;
    #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
    {
        vcpu.set_jit_mem(true);
        vcpu.set_jit_call(false);
    }
    vcpu
}

fn register_image(vcpu: &X86_64Vcpu) -> serde_json::Value {
    serde_json::to_value(vcpu.get_regs().expect("read materialized x86 registers"))
        .expect("serialize x86 register image")
}

fn control_debug_image(vcpu: &X86_64Vcpu) -> [u64; 12] {
    [
        vcpu.sregs.cr0,
        vcpu.sregs.cr2,
        vcpu.sregs.cr3,
        vcpu.sregs.cr4,
        vcpu.sregs.cr8,
        vcpu.sregs.efer,
        vcpu.sregs.dr0,
        vcpu.sregs.dr1,
        vcpu.sregs.dr2,
        vcpu.sregs.dr3,
        vcpu.sregs.dr6,
        vcpu.sregs.dr7,
    ]
}

fn step_error(vcpu: &mut X86_64Vcpu, name: &str) -> String {
    match vcpu.step() {
        Ok(exit) => panic!("{name}: expected #UD, got {exit:?}"),
        Err(error) => format!("{error:#}"),
    }
}

fn assert_direct_ud_on_cold_and_cache_hit(code: &[u8], name: &str) {
    let mut vcpu = test_vcpu(memory_with_code(code));
    vcpu.set_apx_enabled(true);
    vcpu.fpu.tag_word = 0x1357;
    let before = register_image(&vcpu);

    for pass in 0..2 {
        let error = step_error(&mut vcpu, &format!("{name}, pass {pass}"));
        assert!(
            error.contains("IDT entry 6 not present"),
            "{name}, pass {pass}: {error}"
        );
        assert_eq!(register_image(&vcpu), before, "{name}, pass {pass}");
        assert_eq!(vcpu.fpu.tag_word, 0x1357, "{name}, pass {pass}");
        assert_eq!(vcpu.regs.rip, 0, "{name}, pass {pass}");
        if pass == 0 {
            let cached = vcpu.decode_cache[X86_64Vcpu::decode_cache_index(0)];
            assert_ne!(cached.bytes_len, 0, "{name}: cold decode was not cached");
            assert_eq!(cached.rip, 0, "{name}: cached RIP");
        }
    }
}

#[test]
fn direct_rex2_reservations_are_exhaustive_precise_and_cached_without_commit() {
    for opcode in 0_u8..=u8::MAX {
        let map0_reserved = matches!(opcode & 0xF0, 0x40 | 0x70 | 0xE0)
            || opcode & 0xF0 == 0xA0 && opcode != 0xA1
            || matches!(
                opcode,
                0x0F | 0x26 | 0x2E | 0x36 | 0x3E | 0x62 | 0x64
                    ..=0x67 | 0xC4 | 0xC5 | 0xD5 | 0xF0 | 0xF2 | 0xF3
            );
        if map0_reserved {
            assert_direct_ud_on_cold_and_cache_hit(
                &[0xD5, 0x00, opcode, 0xFF, 0xFF],
                &format!("map 0 opcode {opcode:#04x}"),
            );
        }

        if matches!(opcode & 0xF0, 0x30 | 0x80) {
            assert_direct_ud_on_cold_and_cache_hit(
                &[0xD5, 0x80, opcode, 0xFF, 0xFF],
                &format!("map 1 opcode {opcode:#04x}"),
            );
        }
    }

    for (opcode, groups) in [(0xAE, &[4_u8, 5, 6][..]), (0xC7, &[3_u8, 4, 5][..])] {
        for mod_bits in 0_u8..=2 {
            for &group in groups {
                let modrm = mod_bits << 6 | group << 3;
                assert_direct_ud_on_cold_and_cache_hit(
                    &[0xD5, 0x80, opcode, modrm, 0xFF, 0xFF],
                    &format!("XSAVE-family opcode={opcode:#04x}, ModR/M={modrm:#04x}"),
                );
            }
        }
    }
}

#[test]
fn direct_rex2_emms_is_dynamic_and_cache_stable() {
    let mut vcpu = test_vcpu(memory_with_code(&[0xD5, 0x80, 0x77]));
    vcpu.set_apx_enabled(true);

    for pass in 0..2 {
        vcpu.regs.rip = 0;
        vcpu.fpu.tag_word = 0;
        assert!(vcpu.step().expect("REX2 EMMS direct execution").is_none());
        assert_eq!(vcpu.regs.rip, 3, "pass {pass}");
        assert_eq!(vcpu.fpu.tag_word, 0xFFFF, "pass {pass}");
    }

    vcpu.regs.rip = 0;
    vcpu.fpu.tag_word = 0x2468;
    vcpu.set_apx_enabled(false);
    let error = step_error(&mut vcpu, "APX-disabled REX2 EMMS");
    assert!(error.contains("IDT entry 6 not present"), "{error}");
    assert_eq!(vcpu.regs.rip, 0);
    assert_eq!(vcpu.fpu.tag_word, 0x2468);
}

#[test]
fn direct_rex2_control_debug_transfers_use_full_extensions_on_cold_and_cache_hits() {
    let status = 0x08C5 | flags::bits::DF;

    // LLVM 23 encodes `movq %cr8,%r31` as D5 95 20 C7.
    let mut read_control = test_vcpu(memory_with_code(&[0xD5, 0x95, 0x20, 0xC7]));
    read_control.set_apx_enabled(true);
    read_control.sregs.cr8 = 0xD;
    read_control
        .mmu
        .set_task_priority((0xD << 4) as u32)
        .unwrap();
    for pass in 0..2 {
        read_control.regs.rip = 0;
        read_control.regs.r31 = u64::MAX;
        assert!(read_control.step().expect("REX2 MOV-from-CR").is_none());
        assert_eq!(read_control.regs.rip, 4, "MOV-from-CR pass {pass}");
        assert_eq!(read_control.regs.r31, 0xD, "MOV-from-CR pass {pass}");
        assert_eq!(read_control.regs.rflags & status, status);
    }

    // LLVM 23 encodes `movq %r16,%cr2` as D5 90 22 D0.
    let mut write_control = test_vcpu(memory_with_code(&[0xD5, 0x90, 0x22, 0xD0]));
    write_control.set_apx_enabled(true);
    write_control.regs.r16 = 0x1616_2222_3333_4444;
    for pass in 0..2 {
        write_control.regs.rip = 0;
        write_control.sregs.cr2 = 0xA5A5;
        assert!(write_control.step().expect("REX2 MOV-to-CR").is_none());
        assert_eq!(write_control.regs.rip, 4, "MOV-to-CR pass {pass}");
        assert_eq!(
            write_control.sregs.cr2, 0x1616_2222_3333_4444,
            "MOV-to-CR pass {pass}"
        );
        assert_eq!(write_control.regs.rflags & status, status);
    }

    // LLVM 23 encodes `movq %dr7,%r31` as D5 91 21 FF.
    let mut read_debug = test_vcpu(memory_with_code(&[0xD5, 0x91, 0x21, 0xFF]));
    read_debug.set_apx_enabled(true);
    read_debug.sregs.dr7 = 0x400;
    for pass in 0..2 {
        read_debug.regs.rip = 0;
        read_debug.regs.r31 = u64::MAX;
        assert!(read_debug.step().expect("REX2 MOV-from-DR").is_none());
        assert_eq!(read_debug.regs.rip, 4, "MOV-from-DR pass {pass}");
        assert_eq!(read_debug.regs.r31, 0x400, "MOV-from-DR pass {pass}");
        assert_eq!(read_debug.regs.rflags & status, status);
    }

    // LLVM 23 encodes `movq %r31,%dr3` as D5 91 23 DF.
    let mut write_debug = test_vcpu(memory_with_code(&[0xD5, 0x91, 0x23, 0xDF]));
    write_debug.set_apx_enabled(true);
    write_debug.regs.r31 = 0x3131_2222_3333_4444;
    for pass in 0..2 {
        write_debug.regs.rip = 0;
        write_debug.sregs.dr3 = 0xA5A5;
        assert!(write_debug.step().expect("REX2 MOV-to-DR").is_none());
        assert_eq!(write_debug.regs.rip, 4, "MOV-to-DR pass {pass}");
        assert_eq!(
            write_debug.sregs.dr3, 0x3131_2222_3333_4444,
            "MOV-to-DR pass {pass}"
        );
        assert_eq!(write_debug.regs.rflags & status, status);
    }

    // The valid cached decode must still re-evaluate APX before the handler.
    read_control.regs.rip = 0;
    read_control.regs.r31 = 0x3131_3131_3131_3131;
    read_control.set_apx_enabled(false);
    let before_regs = register_image(&read_control);
    let before_system = control_debug_image(&read_control);
    let error = step_error(&mut read_control, "cached APX-disabled MOV-from-CR");
    assert!(error.contains("IDT entry 6 not present"), "{error}");
    assert_eq!(register_image(&read_control), before_regs);
    assert_eq!(control_debug_image(&read_control), before_system);
}

#[test]
fn direct_rex2_control_debug_nonexistent_selectors_ud_before_all_state() {
    for (name, code) in [
        ("MOV r64,CR16", &[0xD5, 0xC0, 0x20, 0xC0][..]),
        ("MOV CR9,r64", &[0xD5, 0x84, 0x22, 0xC8]),
        ("MOV r64,DR8", &[0xD5, 0x84, 0x21, 0xC0]),
        ("MOV DR16,r64", &[0xD5, 0xC0, 0x23, 0xC0]),
    ] {
        let mut vcpu = test_vcpu(memory_with_code(code));
        vcpu.set_apx_enabled(true);
        vcpu.sregs.cr2 = 0x2222_3333_4444_5555;
        vcpu.sregs.dr0 = 0x1111_2222_3333_4444;
        vcpu.sregs.dr6 = 0x400;
        vcpu.sregs.dr7 = 1 << 13;
        let before_regs = register_image(&vcpu);
        let before_system = control_debug_image(&vcpu);

        for pass in 0..2 {
            let error = step_error(&mut vcpu, &format!("{name}, pass {pass}"));
            assert!(
                error.contains("IDT entry 6 not present"),
                "{name}, pass {pass}: {error}"
            );
            assert_eq!(register_image(&vcpu), before_regs, "{name}, pass {pass}");
            assert_eq!(
                control_debug_image(&vcpu),
                before_system,
                "{name}, pass {pass}"
            );
            assert_eq!(vcpu.regs.rip, 0, "{name}, pass {pass}");
            if pass == 0 {
                let cached = vcpu.decode_cache[X86_64Vcpu::decode_cache_index(0)];
                assert_ne!(cached.bytes_len, 0, "{name}: cold decode was not cached");
            }
        }
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_rex2_emms_matches_direct_and_rechecks_apx_without_commit() {
    const CODE: &[u8] = &[
        0xD5, 0x80, 0x77, // REX2 EMMS
        0x48, 0x8D, 0x5B, 0x01, // LEA RBX,[RBX+1]
        0xEB, 0x00, // JMP HLT
        0xF4,
    ];
    let memory = memory_with_code(CODE);
    let mut direct = test_vcpu(memory.clone());
    let mut native = test_vcpu(memory.clone());
    direct.set_apx_enabled(true);
    native.set_apx_enabled(true);
    direct.fpu.tag_word = 0;
    native.fpu.tag_word = 0;

    for _ in 0..3 {
        assert!(direct.step().expect("direct REX2 EMMS sequence").is_none());
    }
    assert_eq!(direct.regs.rip, 9);
    let region = native
        .jit_compile_region()
        .expect("compile REX2 EMMS region")
        .expect("guarded REX2 EMMS must be native eligible");
    assert!(!region.uses_mmx, "EMMS does not consume MM0-MM7 state");
    assert!(
        region.uses_x87_tag_state,
        "EMMS must commit the x87/MMX tag state channel"
    );
    native.jit_run_region_native(&region);
    assert_eq!(register_image(&native), register_image(&direct));
    assert_eq!(native.fpu.tag_word, direct.fpu.tag_word);

    let mut disabled = test_vcpu(memory);
    disabled.set_apx_enabled(true);
    disabled.fpu.tag_word = 0x2468;
    let region = disabled
        .jit_compile_region()
        .expect("compile dynamically guarded REX2 EMMS")
        .expect("REX2 EMMS guard must not block native admission");
    disabled.set_apx_enabled(false);
    let before = register_image(&disabled);
    disabled.jit_run_region_native(&region);
    assert_eq!(register_image(&disabled), before);
    assert_eq!(disabled.fpu.tag_word, 0x2468);
    assert_eq!(disabled.regs.rip, 0);
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_rex2_control_debug_transfers_match_direct_and_recheck_apx() {
    // MOV R31,CR8 continues through the following branch.
    let memory = memory_with_code(&[0xD5, 0x95, 0x20, 0xC7, 0xEB, 0x00, 0xF4]);
    let mut direct = test_vcpu(memory.clone());
    let mut native = test_vcpu(memory.clone());
    for vcpu in [&mut direct, &mut native] {
        vcpu.set_apx_enabled(true);
        vcpu.sregs.cr8 = 0xD;
        vcpu.mmu.set_task_priority((0xD << 4) as u32).unwrap();
        vcpu.regs.r31 = u64::MAX;
    }
    for _ in 0..2 {
        assert!(direct.step().expect("direct REX2 MOV-from-CR").is_none());
    }
    let region = native
        .jit_compile_region()
        .expect("compile REX2 MOV-from-CR")
        .expect("REX2 MOV-from-CR must be native eligible");
    native.jit_run_region_native(&region);
    assert_eq!(register_image(&native), register_image(&direct));
    assert_eq!(control_debug_image(&native), control_debug_image(&direct));
    assert_eq!(native.regs.r31, 0xD);

    // MOV CR2,R16 ends at its exact post-instruction frontier.
    let memory = memory_with_code(&[0xD5, 0x90, 0x22, 0xD0, 0xEB, 0x00, 0xF4]);
    let mut direct = test_vcpu(memory.clone());
    let mut native = test_vcpu(memory);
    for vcpu in [&mut direct, &mut native] {
        vcpu.set_apx_enabled(true);
        vcpu.regs.r16 = 0x1616_2222_3333_4444;
        vcpu.sregs.cr2 = 0;
    }
    assert!(direct.step().expect("direct REX2 MOV-to-CR").is_none());
    let region = native
        .jit_compile_region()
        .expect("compile REX2 MOV-to-CR")
        .expect("REX2 MOV-to-CR must be native eligible");
    native.jit_run_region_native(&region);
    assert_eq!(register_image(&native), register_image(&direct));
    assert_eq!(control_debug_image(&native), control_debug_image(&direct));
    assert_eq!(native.regs.rip, 4);
    assert_eq!(native.sregs.cr2, 0x1616_2222_3333_4444);

    // MOV R31,DR7 continues through the following branch.
    let memory = memory_with_code(&[0xD5, 0x91, 0x21, 0xFF, 0xEB, 0x00, 0xF4]);
    let mut direct = test_vcpu(memory.clone());
    let mut native = test_vcpu(memory);
    for vcpu in [&mut direct, &mut native] {
        vcpu.set_apx_enabled(true);
        vcpu.sregs.dr7 = 0x400;
        vcpu.regs.r31 = u64::MAX;
    }
    for _ in 0..2 {
        assert!(direct.step().expect("direct REX2 MOV-from-DR").is_none());
    }
    let region = native
        .jit_compile_region()
        .expect("compile REX2 MOV-from-DR")
        .expect("REX2 MOV-from-DR must be native eligible");
    native.jit_run_region_native(&region);
    assert_eq!(register_image(&native), register_image(&direct));
    assert_eq!(control_debug_image(&native), control_debug_image(&direct));
    assert_eq!(native.regs.r31, 0x400);

    // MOV DR3,R31 commits the state-backed EGPR source.
    let memory = memory_with_code(&[0xD5, 0x91, 0x23, 0xDF, 0xEB, 0x00, 0xF4]);
    let mut direct = test_vcpu(memory.clone());
    let mut native = test_vcpu(memory);
    for vcpu in [&mut direct, &mut native] {
        vcpu.set_apx_enabled(true);
        vcpu.regs.r31 = 0x3131_2222_3333_4444;
        vcpu.sregs.dr3 = 0;
    }
    for _ in 0..2 {
        assert!(direct.step().expect("direct REX2 MOV-to-DR").is_none());
    }
    let region = native
        .jit_compile_region()
        .expect("compile REX2 MOV-to-DR")
        .expect("REX2 MOV-to-DR must be native eligible");
    native.jit_run_region_native(&region);
    assert_eq!(register_image(&native), register_image(&direct));
    assert_eq!(control_debug_image(&native), control_debug_image(&direct));
    assert_eq!(native.sregs.dr3, 0x3131_2222_3333_4444);

    // The generic APX guard must win before the CR privilege guard and commit.
    let memory = memory_with_code(&[0xD5, 0x95, 0x20, 0xC7, 0xF4]);
    let mut disabled = test_vcpu(memory);
    disabled.set_apx_enabled(true);
    disabled.sregs.cr8 = 0xD;
    disabled.mmu.set_task_priority((0xD << 4) as u32).unwrap();
    disabled.sregs.cs.selector = 3;
    disabled.regs.r31 = 0x3131_3131_3131_3131;
    let region = disabled
        .jit_compile_region()
        .expect("compile dynamically guarded REX2 MOV-from-CR")
        .expect("dynamic APX and CPL guards must not block native admission");
    disabled.set_apx_enabled(false);
    let before_regs = register_image(&disabled);
    let before_system = control_debug_image(&disabled);
    disabled.jit_run_region_native(&region);
    assert_eq!(register_image(&disabled), before_regs);
    assert_eq!(control_debug_image(&disabled), before_system);
    assert_eq!(disabled.regs.rip, 0);
    let error = step_error(&mut disabled, "APX-disabled REX2 MOV-from-CR replay");
    assert!(error.contains("IDT entry 6 not present"), "{error}");
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_stateful_rex2_guard_deoptimizes_at_the_exact_mid_region_frontier() {
    const CODE: &[u8] = &[
        0x48, 0x8D, 0x5B, 0x01, // LEA RBX,[RBX+1]
        0x48, 0x39, 0xDB, // CMP RBX,RBX: its flags must be visible on deopt
        0xD5, 0x18, 0x8B, 0x00, // MOV RAX,[R16]
        0x48, 0x39, 0xD9, // CMP RCX,RBX: kills prior flags only after the guard
        0x48, 0x8D, 0x49, 0x01, // LEA RCX,[RCX+1]
        0xEB, 0x00, // JMP HLT
        0xF4,
    ];
    let memory = memory_with_code(CODE);
    memory
        .write_slice(
            &0xA1B2_C3D4_E5F6_0718_u64.to_le_bytes(),
            GuestAddress(0x200),
        )
        .unwrap();

    let mut direct = test_vcpu(memory.clone());
    let mut native = test_vcpu(memory.clone());
    direct.set_apx_enabled(true);
    native.set_apx_enabled(true);
    for _ in 0..6 {
        assert!(
            direct
                .step()
                .expect("direct stateful REX2 sequence")
                .is_none()
        );
    }
    assert_eq!(direct.regs.rip, 20);
    let region = native
        .jit_compile_region()
        .expect("compile stateful REX2 region")
        .expect("generic REX2 guard must preserve native admission");
    native.jit_run_region_native(&region);
    assert_eq!(register_image(&native), register_image(&direct));

    let mut direct_disabled = test_vcpu(memory.clone());
    let mut native_disabled = test_vcpu(memory);
    direct_disabled.set_apx_enabled(false);
    native_disabled.set_apx_enabled(true);
    native_disabled.regs.r16 = u64::MAX;
    direct_disabled.regs.r16 = u64::MAX;
    let region = native_disabled
        .jit_compile_region()
        .expect("compile before changing dynamic APX state")
        .expect("stateful REX2 region must remain dynamically admissible");
    native_disabled.set_apx_enabled(false);

    for name in ["direct pre-REX2 LEA", "direct pre-REX2 CMP"] {
        assert!(direct_disabled.step().expect(name).is_none());
    }
    let expected_frontier = register_image(&direct_disabled);
    assert_eq!(direct_disabled.regs.rip, 7);
    assert_ne!(direct_disabled.regs.rflags & flags::bits::ZF, 0);

    native_disabled.jit_run_region_native(&region);
    assert_eq!(register_image(&native_disabled), expected_frontier);
    assert_eq!(native_disabled.regs.rip, 7);

    let error = step_error(&mut direct_disabled, "direct APX-disabled REX2 MOV");
    assert!(error.contains("IDT entry 6 not present"), "{error}");
    assert_eq!(
        register_image(&native_disabled),
        register_image(&direct_disabled)
    );
}
