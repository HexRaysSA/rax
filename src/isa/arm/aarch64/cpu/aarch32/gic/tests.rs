use super::*;
use crate::isa::arm::aarch64::gic::GicConfig;
use crate::isa::arm::common::cpu::{ArmCpu, CpuExit};
use crate::isa::arm::common::memory::FlatMemory;

const ENTRY: u64 = 0x100;

fn cpu(instructions: &[u32], thumb: bool) -> AArch64Cpu {
    let bytes = instructions
        .iter()
        .flat_map(|&word| if thumb { word.rotate_left(16) } else { word }.to_le_bytes())
        .collect();
    let mut config = crate::isa::arm::aarch64::AArch64Config::v8_0();
    config.gic_config = Some(GicConfig {
        num_cpus: 2,
        ..Default::default()
    });
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::with_data(ENTRY, bytes)));
    let mut controls = cpu.pauth_controls();
    controls.scr_el3 = 0x501;
    controls.hcr_el2 = 0;
    cpu.set_pauth_controls(controls).unwrap();
    cpu.set_pstate_bits(0x1d3 | (u64::from(thumb) << 5))
        .unwrap();
    cpu.set_pc(ENTRY);
    cpu
}

#[test]
fn a32_and_t32_use_the_same_active_priority_registers_as_a64() {
    const AP1R1: Aarch64SysRegEncoding = Aarch64SysRegEncoding::new(3, 0, 12, 9, 1);
    for thumb in [false, true] {
        let mut cpu = cpu(
            &[
                0xee1c_5f1c, // MRC p15, 0, R5, c12, c12, 0 (ICC_IAR1)
                0xee1c_6f7b, // MRC p15, 0, R6, c12, c11, 3 (ICC_RPR)
                0xee1c_7f39, // MRC p15, 0, R7, c12, c9, 1 (ICC_AP1R1)
                0xee0c_1f79, // MCR p15, 0, R1, c12, c9, 3 (ICC_AP1R3)
                0xee0c_5f3c, // MCR p15, 0, R5, c12, c12, 1 (ICC_EOIR1)
                0xee1c_8f7b, // MRC p15, 0, R8, c12, c11, 3 (ICC_RPR)
            ],
            thumb,
        );
        let gic = cpu.gic.as_ref().unwrap().clone();
        {
            let mut gic = gic.lock().unwrap();
            gic.write_dist(0, 3);
            gic.write_redist(0, 0x14, 0);
            gic.set_group_enable(0, true, true);
            gic.write_dist(0x84, 1 << 8);
            gic.set_enabled(40, true);
            gic.set_priority(40, 0x60);
            gic.set_pending(40);
        }
        cpu.set_x(1, 2);
        for _ in 0..6 {
            assert!(matches!(
                cpu.step_system_with_fault_exit(),
                Ok(CpuExit::Continue)
            ));
        }
        assert_eq!(cpu.instruction_count(), 6);
        assert_eq!(cpu.get_pc(), ENTRY + 24);
        assert_eq!(cpu.get_x(5), 40);
        assert_eq!(cpu.get_x(6), 0x60);
        assert_eq!(cpu.get_x(7), 1 << 16);
        assert_eq!(cpu.get_x(8), 0xc2);
        assert_eq!(cpu.read_icc(AP1R1), Some(0));
        assert_eq!(gic.lock().unwrap().read_dist(0x304) & (1 << 8), 0);
    }
}

#[test]
fn a32_and_t32_dir_writes_obey_eoi_mode_without_dropping_priority() {
    for thumb in [false, true] {
        for split in [false, true] {
            let mut cpu = cpu(
                &[
                    0xee0c_1f9c, // MCR p15,0,R1,c12,c12,4 (ICC_CTLR)
                    0xee1c_5f1c, // MRC p15,0,R5,c12,c12,0 (ICC_IAR1)
                    0xee0c_5f3b, // MCR p15,0,R5,c12,c11,1 (ICC_DIR)
                    0xee1c_6f7b, // MRC p15,0,R6,c12,c11,3 (ICC_RPR)
                    0xee0c_5f3c, // MCR p15,0,R5,c12,c12,1 (ICC_EOIR1)
                    0xee1c_7f7b, // MRC p15,0,R7,c12,c11,3 (ICC_RPR)
                ],
                thumb,
            );
            let gic = cpu.gic.as_ref().unwrap().clone();
            {
                let mut gic = gic.lock().unwrap();
                gic.write_dist(0, 3);
                gic.set_group_enable(0, true, true);
                gic.write_dist(0x84, 1 << 8);
                gic.set_enabled(40, true);
                gic.set_priority(40, 0x60);
                gic.set_pending(40);
            }
            cpu.set_x(1, u64::from(split) << 1);
            for index in 0..6 {
                assert!(matches!(
                    cpu.step_system_with_fault_exit(),
                    Ok(CpuExit::Continue)
                ));
                if index == 2 {
                    assert_eq!(cpu.get_x(5), 40);
                    assert_eq!(
                        gic.lock().unwrap().read_dist(0x304) & (1 << 8) != 0,
                        !split,
                        "ICC_DIR active state in Thumb={thumb}, split={split}"
                    );
                }
            }
            assert_eq!(cpu.instruction_count(), 6);
            assert_eq!(cpu.get_x(6), 0x60);
            assert_eq!(cpu.get_x(7), 0xff);
            assert_eq!(gic.lock().unwrap().read_dist(0x304) & (1 << 8), 0);
        }
    }
}

#[test]
fn a32_gic_predicate_and_hstr_precede_acknowledgement() {
    for thumb in [false, true] {
        let mut cpu = cpu(&[0xee1c_5f1c], thumb);
        let gic = cpu.gic.as_ref().unwrap().clone();
        {
            let mut gic = gic.lock().unwrap();
            gic.write_dist(0, 3);
            gic.write_redist(0, 0x14, 0);
            gic.set_group_enable(0, true, true);
            gic.write_dist(0x84, 1 << 8);
            gic.set_enabled(40, true);
            gic.set_pending(40);
        }
        cpu.sysregs.write_hstr(1 << 12);
        cpu.set_x(5, 0xabcd);
        cpu.sysregs.el2.vbar = 0x800;
        // A32 condition EQ and a T32 IT EQ both fail with Z=0. Advance
        // the instruction as a no-op before retrying with Z=1 below.
        if thumb {
            cpu.set_pstate_bits(cpu.pstate_bits() | (2 << 10)).unwrap();
        } else {
            cpu.mem_write_u32(ENTRY, 0x0e1c_5f1c).unwrap();
        }
        assert!(matches!(
            cpu.step_system_with_fault_exit(),
            Ok(CpuExit::Continue)
        ));
        assert_eq!(cpu.instruction_count(), 1);
        assert_eq!(cpu.get_x(5), 0xabcd);
        cpu.set_pc(ENTRY);
        cpu.set_pstate_bits(cpu.pstate_bits() | (1 << 30) | (u64::from(thumb) << 11))
            .unwrap();
        let stop = cpu.step_system_with_fault_exit();
        assert!(
            matches!(
                stop,
                Err(ArmError::ArchitecturalException {
                    ec: 3,
                    target_el: Some(2),
                    ..
                })
            ),
            "{stop:?}"
        );
        assert_eq!(cpu.instruction_count(), 1);
        assert_eq!(cpu.get_x(5), 0xabcd);
        assert_eq!(gic.lock().unwrap().highest_pending_in_group(0, 1), 40);
    }
}

#[test]
fn a32_mcrr_sgi_uses_both_words_and_targets_the_other_pe() {
    for thumb in [false, true] {
        let mut cpu = cpu(&[0xec41_0f0c], thumb); // MCRR p15, 0, R0, R1, c12 (ICC_SGI1R)
        let gic = cpu.gic.as_ref().unwrap().clone();
        {
            let mut gic = gic.lock().unwrap();
            gic.write_dist(0, 3);
            for pe in 0..2 {
                gic.write_redist(pe, 0x14, 0);
                gic.write_redist(pe, 0x10080, 1 << 7);
            }
        }
        cpu.set_x(0, 7 << 24);
        cpu.set_x(1, 1 << 8); // ICC_SGI1R.IRM is bit 40 of the pair.
        assert!(matches!(
            cpu.step_system_with_fault_exit(),
            Ok(CpuExit::Continue)
        ));
        let gic = gic.lock().unwrap();
        assert_eq!(gic.read_redist(0, 0x10200) & (1 << 7), 0);
        assert_ne!(gic.read_redist(1, 0x10200) & (1 << 7), 0);
    }
}

#[test]
fn a32_gic_privilege_and_transfer_direction_gate_side_effects() {
    for thumb in [false, true] {
        for (instruction, user) in [
            (0xee1c_5f1c, true),  // IAR1 read at EL0
            (0xee0c_5f1c, false), // IAR1 write
            (0xee1c_5f3c, false), // EOIR1 read
            (0xec51_0f0c, false), // SGI1R read
        ] {
            let mut cpu = cpu(&[instruction], thumb);
            if user {
                cpu.set_pstate_bits(0x1d0 | (u64::from(thumb) << 5))
                    .unwrap();
            }
            let gic = cpu.gic.as_ref().unwrap().clone();
            let before = crate::codec::serialize(&gic.lock().unwrap().checkpoint()).unwrap();
            let stop = cpu.step_system_with_fault_exit();
            assert!(
                matches!(stop, Err(ArmError::UndefinedInstruction(raw)) if raw == instruction),
                "{stop:?}"
            );
            assert_eq!(cpu.instruction_count(), 0);
            assert_eq!(
                before,
                crate::codec::serialize(&gic.lock().unwrap().checkpoint()).unwrap()
            );
        }
    }
}

#[test]
fn a32_gic_virtual_routing_uses_the_corresponding_irq_group() {
    const RPR: u32 = 0xee1c_2f7b; // MRC p15, 0, R2, c12, c11, 3
    const AP0R0: u32 = 0xee1c_2f98; // MRC p15, 0, R2, c12, c8, 4
    const AP1R0: u32 = 0xee1c_2f19; // MRC p15, 0, R2, c12, c9, 0
    for (instruction, hcr, scr, allowed) in [
        (RPR, IMO, 0, false),
        (RPR, FMO, 0, false),
        (AP0R0, IMO, 0, true),
        (AP1R0, IMO, 0, false),
        (AP0R0, FMO, 0, false),
        (AP1R0, FMO, 0, true),
        (RPR, 0, 1 << 2, true),
        (RPR, 0, 3 << 1, false),
    ] {
        let mut cpu = cpu(&[instruction], false);
        let mut controls = cpu.pauth_controls();
        controls.hcr_el2 |= hcr;
        controls.scr_el3 |= scr;
        cpu.set_pauth_controls(controls).unwrap();
        let outcome = cpu.step_system_with_fault_exit();
        if allowed {
            assert!(matches!(outcome, Ok(CpuExit::Continue)), "{outcome:?}");
            assert_eq!(cpu.instruction_count(), 1);
        } else {
            assert!(
                matches!(outcome, Err(ArmError::UnsupportedExecutionState(_))),
                "{outcome:?}"
            );
            assert_eq!(cpu.instruction_count(), 0);
        }
    }
}
