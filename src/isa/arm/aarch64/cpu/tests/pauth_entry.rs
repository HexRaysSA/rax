//! Arm EndOfDecode BTI priority and exact instruction-entry state.

use super::*;

fn guarded_cpu(word: u32, el: u8, pauth: bool, control: bool) -> AArch64Cpu {
    let mut memory = FlatMemory::new(0, 0x100000);
    for (base, next) in [(0x10000, 0x20000), (0x20000, 0x30000), (0x30000, 0x40000)] {
        memory.write_u64(base, next | 3).unwrap();
    }
    memory
        .write_u64(
            0x40000,
            0x80000 | 0x403 | (u64::from(el == 0) << 6) | (1 << 50),
        )
        .unwrap();
    memory.write_u32(0x80000, word).unwrap();
    let mut features = ArmFeatures::armv8_0_base() | ArmFeatures::BTI;
    features.set(ArmFeatures::PACA, pauth);
    let mut cpu = AArch64Cpu::new(
        AArch64Config {
            initial_el: el,
            features,
            gic_config: None,
            ..Default::default()
        },
        Box::new(memory),
    );
    cpu.sysregs.el1.sctlr = 1 | if control {
        1 << if el == 0 { 35 } else { 36 }
    } else {
        0
    };
    cpu.sysregs.el1.tcr = 16 | (16 << 16) | (5 << 32);
    cpu.sysregs.el1.ttbr0 = 0x10000;
    cpu.sysregs.el1.mair = 0xff;
    cpu.sysregs.el1.vbar = 0x4000;
    cpu.set_x(30, 0x1230);
    cpu.set_current_sp(0x9000);
    cpu.update_mmu_config();
    cpu
}

#[test]
fn pauth_entry_bti_and_implicit_pac_landing_matrix() {
    for el in [0, 1] {
        for control in [false, true] {
            for pauth in [false, true] {
                for btype in 0..4 {
                    for (word, compatible) in [
                        (0xd503_241f, btype == 0), // BTI
                        (0xd503_245f, btype != 3), // BTI C
                        (0xd503_249f, btype != 2), // BTI J
                        (0xd503_24df, true),       // BTI JC
                        (
                            0xd503_233f,
                            btype == 0 || (pauth && (btype != 3 || !control)),
                        ),
                        (
                            0xd503_237f,
                            btype == 0 || (pauth && (btype != 3 || !control)),
                        ),
                        (0xd503_201f, btype == 0), // NOP
                        (0xd503_23bf, btype == 0), // AUTIASP has no implicit BTI
                        (0xd420_0000, true),       // BRK
                        (0xd440_0000, true),       // HLT
                    ] {
                        let mut cpu = guarded_cpu(word, el, pauth, control);
                        cpu.btype = btype;
                        let before = cpu.x;
                        let result = cpu.step();
                        if compatible {
                            assert!(
                                result.is_ok(),
                                "EL{el} BT={control} PAC={pauth} BTYPE={btype} {word:#x}: {result:?}"
                            );
                            assert_eq!(cpu.btype, 0);
                            assert_eq!(cpu.instruction_count(), 1);
                        } else {
                            assert!(
                                matches!(result, Err(ArmError::ArchitecturalException { ec: 0x0d, iss, target_el: Some(1) }) if iss == u32::from(btype)),
                                "{word:#x}: {result:?}"
                            );
                            assert_eq!(cpu.x, before);
                            assert_eq!(cpu.btype, btype);
                            assert_eq!(cpu.get_pc(), 0);
                            assert_eq!(cpu.instruction_count(), 0);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn pauth_entry_plain_br_uses_guarded_source_page_for_outgoing_btype() {
    for register in 0..32 {
        let word = 0xd61f_0000 | (register << 5);
        let mut cpu = guarded_cpu(word, 1, false, false);
        cpu.set_x(register as u8, 0x20);
        cpu.btype = 0;
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!(cpu.get_pc(), if register == 31 { 0 } else { 0x20 });
        assert_eq!(
            cpu.btype,
            if register == 16 || register == 17 {
                1
            } else {
                3
            }
        );
        assert_eq!(cpu.instruction_count(), 1);
    }
}

#[test]
fn pauth_entry_bti_precedes_undefined_and_pac_use_traps() {
    for word in [0, 0xd503_233f] {
        let mut cpu = guarded_cpu(word, 1, true, true);
        cpu.btype = 3;
        cpu.sysregs.el1.sctlr |= 1 << 31;
        assert!(matches!(
            cpu.step(),
            Err(ArmError::ArchitecturalException {
                ec: 0x0d,
                iss: 3,
                ..
            })
        ));
        cpu.step_system().unwrap();
        assert_eq!(cpu.sysregs.el1.elr, 0);
        assert_eq!((cpu.sysregs.el1.esr >> 26) & 63, 0x0d);
        assert_eq!(cpu.sysregs.el1.esr & 0x1ff_ffff, 3);
        assert_eq!((cpu.sysregs.el1.spsr >> 10) & 3, 3);
    }
}

#[test]
fn pauth_entry_illegal_state_fault_prevents_any_instruction_effect() {
    let mut cpu = guarded_cpu(0x9100_0400, 1, true, false); // ADD X0,X0,#1
    cpu.il = true;
    cpu.set_x(0, 7);
    assert!(matches!(
        cpu.step(),
        Err(ArmError::ArchitecturalException {
            ec: 0x0e,
            iss: 0,
            target_el: Some(1)
        })
    ));
    assert_eq!(cpu.get_x(0), 7);
    assert_eq!(cpu.get_pc(), 0);
    assert_eq!(cpu.instruction_count(), 0);
    cpu.step_system().unwrap();
    assert_eq!((cpu.sysregs.el1.esr >> 26) & 63, 0x0e);
    assert_ne!(cpu.sysregs.el1.spsr & (1 << 20), 0);
    assert!(!cpu.il);
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn pauth_entry_cached_native_code_cannot_bypass_il_or_incoming_btype() {
    let mut cpu = guarded_cpu(0x9100_0400, 1, true, false);
    for (offset, word) in [(4, 0xf100_0803u32), (8, 0x54ff_ffc3), (12, 0xd420_0000)] {
        cpu.mem_write_u32(offset, word).unwrap();
    }
    cpu.set_x(0, 1);
    let region = cpu.jit_compile_region().expect("scalar loop");
    cpu.btype = 3;
    assert!(!cpu.jit_run_region(&region));
    assert_eq!(cpu.get_x(0), 1);
    assert_eq!(cpu.get_pc(), 0);
    cpu.btype = 0;
    cpu.il = true;
    assert!(!cpu.jit_run_region(&region));
    assert_eq!(cpu.get_x(0), 1);
    cpu.il = false;
    assert!(cpu.jit_run_region(&region));
    assert_eq!(cpu.get_x(0), 2);
    assert_eq!(cpu.get_pc(), 12);
}
