//! FPEXC32_EL2 permissions, canonical alias and precise access faults.
use super::*;
use crate::isa::arm::common::memory::FlatMemory;

const ENTRY: u64 = 0x100;
const READ: u32 = 0xd53c_5300;
const WRITE: u32 = 0xd51c_5300;
const TFP: u64 = 1 << 10;

fn configured(word: u32, el: u8, trapping: bool) -> AArch64Cpu {
    let mut config = AArch64Config::v8_2();
    config.features |= ArmFeatures::VHE;
    config.initial_el = el;
    config.gic_config = None;
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x6000)));
    cpu.pc = ENTRY;
    cpu.sp_sel = el != 0;
    cpu.x.fill(u64::MAX);
    cpu.v.fill(0x1234_5678);
    cpu.sysregs.scr_el3 = 0x501;
    cpu.sysregs.hcr_el2 = 1 << 31;
    cpu.sysregs.el1.cpacr = 3 << 20;
    cpu.sysregs.el1.vbar = 0x1000;
    cpu.sysregs.el2.vbar = 0x2000;
    cpu.sysregs.el3.vbar = 0x3000;
    for op1 in [4, 6] {
        cpu.sysregs
            .impl_defined
            .insert(Aarch64SysRegEncoding::new(3, op1, 1, 1, 2).encode(), 0);
    }
    if trapping {
        let id = cpu.sysregs.aarch32_fp_ids()[0] | (1 << 12);
        cpu.sysregs.impl_defined.insert(
            Aarch64SysRegEncoding::new(3, 0, 0, 3, 0).encode(),
            u64::from(id),
        );
    }
    cpu.write_memory(ENTRY, &word.to_le_bytes()).unwrap();
    cpu
}

#[test]
fn lower_exception_levels_cannot_access_fpexc32_in_either_selected_profile() {
    for trapping in [false, true] {
        for el in [0, 1] {
            for operation in [READ, WRITE] {
                for rt in 0..32 {
                    let mut cpu = configured(operation | rt, el, trapping);
                    let before = (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.export_sregs());
                    assert!(
                        matches!(cpu.step(), Err(ArmError::InvalidExceptionLevel(level)) if level == el),
                        "EL{el} trapping={trapping} word={:08x}",
                        operation | rt
                    );
                    assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (ENTRY, 0, 0));
                    assert_eq!(
                        (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.export_sregs()),
                        before
                    );
                }
            }
        }
    }
}

#[test]
fn higher_fp_controls_trap_fpexc32_before_read_write_or_retirement() {
    for trapping in [false, true] {
        for (el, cptr2, cptr3, target) in [(2, TFP, TFP, 2), (2, 0, TFP, 3), (3, TFP, TFP, 3)] {
            for operation in [READ, WRITE] {
                for rt in [0, 9, 31] {
                    let mut cpu = configured(operation | rt, el, trapping);
                    for (op1, value) in [(4, cptr2), (6, cptr3)] {
                        cpu.sysregs
                            .impl_defined
                            .insert(Aarch64SysRegEncoding::new(3, op1, 1, 1, 2).encode(), value);
                    }
                    let before = (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.export_sregs());
                    assert_eq!(
                        cpu.step(),
                        Err(ArmError::ArchitecturalException {
                            ec: 7,
                            iss: 0,
                            target_el: Some(target),
                        })
                    );
                    assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (ENTRY, 0, 0));
                    assert_eq!(
                        (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.export_sregs()),
                        before
                    );
                }
            }
        }
    }
}

#[test]
fn nontrapping_alias_canonicalizes_upper_and_reserved_bits() {
    for el in [2, 3] {
        let mut cpu = configured(WRITE, el, false);
        cpu.write_memory(ENTRY + 4, &(READ | 1).to_le_bytes())
            .unwrap();
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!(cpu.x[1], 0x4000_0700);
        assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (ENTRY + 8, 2, 2));
    }
}

#[test]
fn absent_or_reserved_el1_aarch32_capability_precedes_fpexc32_control_traps() {
    for trapping in [false, true] {
        for capability in [1, 3, 15] {
            for el in [2, 3] {
                for operation in [READ, WRITE] {
                    let mut cpu = configured(operation, el, trapping);
                    cpu.sysregs.id_aa64pfr0_el1 =
                        (cpu.sysregs.id_aa64pfr0_el1 & !(15 << 4)) | (capability << 4);
                    for op1 in [4, 6] {
                        cpu.sysregs
                            .impl_defined
                            .insert(Aarch64SysRegEncoding::new(3, op1, 1, 1, 2).encode(), TFP);
                    }
                    let before = (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.export_sregs());
                    assert_eq!(cpu.step(), Err(ArmError::UndefinedInstruction(operation)));
                    assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (ENTRY, 0, 0));
                    assert_eq!(
                        (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.export_sregs()),
                        before
                    );
                }
            }
        }
    }
}

#[test]
fn vhe_fpen_and_selected_fpexc_views_cover_every_transfer_register() {
    for trapping in [false, true] {
        for short_vectors in [false, true] {
            for fpen in 0..4 {
                for rt in 0..32 {
                    let mut cpu = configured(WRITE | rt, 2, trapping);
                    cpu.sysregs.hcr_el2 |= 1 << 34;
                    cpu.sysregs.impl_defined.insert(
                        Aarch64SysRegEncoding::new(3, 4, 1, 1, 2).encode(),
                        fpen << 20,
                    );
                    if short_vectors {
                        let id = (cpu.sysregs.aarch32_fp_ids()[0] & !(15 << 24)) | (1 << 24);
                        cpu.sysregs.impl_defined.insert(
                            Aarch64SysRegEncoding::new(3, 0, 0, 3, 0).encode(),
                            u64::from(id),
                        );
                    }
                    let before = (cpu.x, cpu.v, cpu.export_sregs());
                    if fpen & 1 == 0 {
                        assert_eq!(
                            cpu.step(),
                            Err(ArmError::ArchitecturalException {
                                ec: 7,
                                iss: 0,
                                target_el: Some(2),
                            })
                        );
                        assert_eq!((cpu.x, cpu.v, cpu.export_sregs()), before);
                        assert_eq!((cpu.pc, cpu.insn_count), (ENTRY, 0));
                    } else {
                        cpu.step().unwrap();
                        cpu.write_memory(ENTRY + 4, &(READ | rt).to_le_bytes())
                            .unwrap();
                        cpu.step().unwrap();
                        let wanted = if rt == 31 {
                            0 // XZR transfer has no destination.
                        } else if !trapping {
                            0x4000_0700
                        } else if short_vectors {
                            0x6000_079f
                        } else {
                            0x6400_079f
                        };
                        assert_eq!(cpu.get_x(rt as u8), wanted);
                        assert_eq!(cpu.insn_count, 2);
                    }
                }
            }
        }
    }
}

#[test]
fn system_delivery_preserves_exact_fault_frame_and_retries_the_denied_transfer() {
    for trapping in [false, true] {
        for (el, target) in [(2, 2), (2, 3), (3, 3)] {
            for operation in [READ, WRITE] {
                let mut cpu = configured(operation, el, trapping);
                cpu.sysregs.impl_defined.insert(
                    Aarch64SysRegEncoding::new(3, if target == 2 { 4 } else { 6 }, 1, 1, 2)
                        .encode(),
                    TFP,
                );
                let before = (cpu.x, cpu.v, cpu.read_aarch32_fpexc(), cpu.pstate_bits());
                assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
                assert_eq!(cpu.current_el, target);
                let bank = cpu.sysregs.bank(target);
                assert_eq!(
                    (bank.elr, bank.esr, bank.spsr),
                    (ENTRY, (7 << 26) | (1 << 25), before.3)
                );
                assert_eq!(
                    (cpu.x, cpu.v, cpu.read_aarch32_fpexc()),
                    (before.0, before.1, before.2)
                );
                assert_eq!((cpu.insn_count, cpu.cycle_count), (0, 0));
                // Clear the trapping control as a handler would, then use a real
                // ERET to retry the exact same access, without manual PC repair.
                cpu.sysregs.impl_defined.insert(
                    Aarch64SysRegEncoding::new(3, if target == 2 { 4 } else { 6 }, 1, 1, 2)
                        .encode(),
                    0,
                );
                cpu.write_memory(cpu.pc, &0xd69f_03e0u32.to_le_bytes())
                    .unwrap();
                cpu.step_system().unwrap();
                assert_eq!((cpu.pc, cpu.current_el, cpu.insn_count), (ENTRY, el, 1));
                cpu.step_system().unwrap();
                assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (ENTRY + 4, 2, 2));
                if operation == READ {
                    assert_eq!(cpu.x[0], before.2);
                } else {
                    assert_eq!(
                        cpu.read_aarch32_fpexc(),
                        if trapping { 0x6400_079f } else { 0x4000_0700 }
                    );
                }
            }
        }
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn original_fpexc32_words_retain_managed_access_even_with_no_live_result() {
    use crate::smir::ir::ops::{OpKind, SmirOp};
    use crate::smir::ir::types::{BlockId, FunctionId, OpId};
    use crate::smir::ir::{SmirBlock, SmirFunction};
    let mut function = SmirFunction::new(FunctionId(0), BlockId(0), ENTRY);
    let mut block = SmirBlock::new(BlockId(0), ENTRY);
    block.push_op(SmirOp::new(OpId(0), ENTRY, OpKind::Nop));
    function.add_block(block);
    let cpu = configured(READ, 2, false);
    assert!(
        cpu.native_requirements(&function, ENTRY, &0xd503_201fu32.to_le_bytes())
            .is_some()
    );
    for operation in [READ, WRITE] {
        for rt in 0..32 {
            assert!(
                cpu.native_requirements(&function, ENTRY, &(operation | rt).to_le_bytes())
                    .is_none()
            );
        }
    }

    // Exercise the same source words in a hot guest loop through bounded system
    // entry, then change the higher control while its caches are warm.
    for operation in [READ, WRITE] {
        for rt in [0, 31] {
            let mut cpu = configured(operation | rt, 2, false);
            let code = [
                0x9100_0442u32, // ADD X2,X2,#1.
                operation | rt,
                0xf102_005f, // CMP X2,#128.
                0x54ff_ffa3, // B.LO entry.
                0xd503_201f,
            ]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
            cpu.write_memory(ENTRY, &code).unwrap();
            cpu.x[2] = 0;
            cpu.set_jit_mem(true);
            cpu.jit.hot.insert(ENTRY + 4, A64_JIT_HOT_THRESHOLD - 1);
            for _ in 0..512 {
                assert_eq!(cpu.step_system_bounded(true).unwrap(), CpuExit::Continue);
            }
            assert_eq!(
                (cpu.pc, cpu.x[2], cpu.insn_count, cpu.cycle_count),
                (ENTRY + 16, 128, 512, 512)
            );
            assert!(
                cpu.jit.bounded_runs > 0,
                "ordinary loop instructions must exercise active native entry"
            );
            cpu.sysregs
                .impl_defined
                .insert(Aarch64SysRegEncoding::new(3, 4, 1, 1, 2).encode(), TFP);
            cpu.pc = ENTRY + 4;
            let before = (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.read_aarch32_fpexc());
            assert_eq!(
                cpu.step_system_bounded(true),
                Err(ArmError::ArchitecturalException {
                    ec: 7,
                    iss: 0,
                    target_el: Some(2),
                })
            );
            assert_eq!(
                (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.read_aarch32_fpexc()),
                before
            );
            assert_eq!(
                (cpu.pc, cpu.insn_count, cpu.cycle_count),
                (ENTRY + 4, 512, 512)
            );
        }
    }
}
