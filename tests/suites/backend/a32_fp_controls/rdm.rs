//! Arm DDI0597 VQRDMLAH/VQRDMLSH arithmetic and ID_ISAR5 admission.
use super::*;
use rax::isa::arm::decoder::{Mnemonic, ThumbDecoder};

const RDM: u32 = 1 << 24;
const QC: u32 = 1 << 27;
const ID_ISAR5: u32 = 0xee10_0fb2; // MRC P15,0,R0,C0,C2,5.
const INPUT: [u64; 6] = [
    0x4000_8000_7fff_ffff,
    0x8000_4000_ffff_0001,
    0xc000_8000_7fff_4000,
    0x7fff_0001_8000_0000,
    0x8000_0000_8000_0000,
    0x8000_0000_4000_0000,
];

fn thumb_word(raw: u32) -> u32 {
    // Move the A32 U/Q bit to T32 bit 28, select the T32 SIMD class.
    let selector = (raw & (1 << 24)) << 4;
    (raw & 0x00ff_ffff) | 0xef00_0000 | selector
}

fn operation(cpu: &mut Armv7Cpu, raw: u32) -> ExecResult {
    let insn = if cpu.cpsr.t {
        ThumbDecoder::decode_32bit(thumb_word(raw)).unwrap()
    } else {
        Aarch32Decoder::decode(raw).unwrap()
    };
    Executor::new(cpu, &mut Memory32::new(4096, 0)).execute(&insn)
}

#[test]
fn rdm_vector_and_indexed_arithmetic_round_and_saturate_once() {
    let cases = [
        (0xf311_0b12, [0x7fff_8000_7ffe_0000, INPUT[1]], true),
        (0xf311_0c12, [0x0000_c000_7fff_ffff, INPUT[1]], true),
        (
            0xf322_0b54,
            [0x7fff_ffff_0000_bfff, 0x8000_0000_bfff_0001],
            true,
        ),
        (
            0xf322_0c54,
            [0x0001_0000_7fff_ffff, 0xffff_4001_3fff_0001],
            true,
        ),
        (
            0xf392_0e68,
            [0x2000_8000_7fff_1fff, 0xc000_4001_bfff_0001],
            true,
        ),
        (
            0xf392_0f68,
            [0x6000_c000_4000_dfff, 0x8000_4000_3fff_0001],
            true,
        ),
        (0xf2a1_0e60, [0x0000_2000_7fff_7fff, INPUT[1]], false),
        (0xf2a1_0f60, [0x7fff_ffff_7fff_ffff, INPUT[1]], true),
    ];
    for (raw, expected, saturates) in cases {
        for thumb in [false, true] {
            for sticky in [false, true] {
                let mut cpu = Armv7Cpu::new();
                cpu.cp15.id_isar[5] |= RDM;
                cpu.cpsr.t = thumb;
                cpu.vfp.dregs[..INPUT.len()].copy_from_slice(&INPUT);
                cpu.vfp.fpscr.set_qc(sticky);
                let result = operation(&mut cpu, raw);
                assert!(
                    matches!(result, ExecResult::Continue),
                    "{raw:#x}, {thumb}: {result:?}"
                );
                assert_eq!(cpu.vfp.dregs[..2], expected, "{raw:#x}, {thumb}");
                assert_eq!(cpu.vfp.dregs[2..INPUT.len()], INPUT[2..]);
                assert_eq!(cpu.vfp.fpscr.bits() & QC != 0, sticky || saturates);
            }
        }
    }

    // The unclipped product of MIN * MIN rounds to +32768. After
    // adding -1 the answer fits, and there must be no saturation flag.
    let mut cpu = Armv7Cpu::new();
    cpu.cp15.id_isar[5] |= RDM;
    cpu.vfp.dregs[..3].copy_from_slice(&[u64::MAX, 0x8000_8000_8000_8000, 0x8000_8000_8000_8000]);
    assert!(matches!(
        operation(&mut cpu, 0xf311_0b12),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.dregs[0], 0x7fff_7fff_7fff_7fff);
    assert_eq!(cpu.vfp.fpscr.bits() & QC, 0);
}

#[test]
fn rdm_feature_and_encoding_checks_precede_fp_access() {
    for raw in [0xf311_0b12, 0xf311_0c12, 0xf392_0e68, 0xf392_0f68] {
        for thumb in [false, true] {
            for field in 0..16 {
                let mut cpu = hyp();
                cpu.cp15.id_isar[5] = field << 24;
                cpu.cp15.hcptr = 1 << 10;
                cpu.cpsr.t = thumb;
                let before = cpu.vfp.dregs;
                let result = operation(&mut cpu, raw);
                if field == 1 {
                    assert!(matches!(
                        result,
                        ExecResult::FpAccessTrap { target_el: 2, .. }
                    ));
                } else {
                    assert!(
                        matches!(result, ExecResult::Undefined),
                        "{raw:#x}, {field}: {result:?}"
                    );
                }
                assert_eq!(cpu.vfp.dregs, before);
                assert_eq!(cpu.vfp.fpscr.bits() & QC, 0);
            }
        }
    }
    for raw in [
        0xf301_0b12,
        0xf331_0c12,
        0xf311_0b52,
        0xf382_0e68,
        0xf391_0f68,
    ] {
        assert_eq!(
            Aarch32Decoder::decode(raw).unwrap().mnemonic,
            Mnemonic::UNDEFINED
        );
        assert_eq!(
            ThumbDecoder::decode_32bit(thumb_word(raw))
                .unwrap()
                .mnemonic,
            Mnemonic::UNDEFINED
        );
    }
    let mut cpu = hyp();
    cpu.cp15.id_isar[5] = RDM;
    cpu.cp15.hcptr = 1 << 10;
    cpu.cpsr.t = true;
    cpu.cpsr.it_state = 0x18; // IT NE; the executed slot is constrained unpredictable.
    assert!(matches!(
        operation(&mut cpu, 0xf311_0b12),
        ExecResult::Undefined
    ));
}

#[test]
fn mixed_width_rdm_readback_and_execution_share_the_selected_id() {
    for field in [0u64, 1, 2] {
        for thumb in [false, true] {
            let mut cpu = mixed(ID_ISAR5, thumb, 2, false, true);
            let mut state = cpu.export_sregs();
            let sysregs = &mut state.execution.as_mut().unwrap().sysregs;
            sysregs.id_aa64isar0_el1 = (sysregs.id_aa64isar0_el1 & !(15 << 28)) | (field << 28);
            sysregs
                .impl_defined
                .remove(&Aarch64SysRegEncoding::new(3, 4, 1, 1, 2).encode());
            let alias = Aarch64SysRegEncoding::new(3, 0, 0, 2, 5);
            assert_eq!(sysregs.read(alias, 1), Some(field << 24));
            cpu.import_sregs(&state).unwrap();
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(cpu.get_x(0), field << 24);

            let raw = if thumb {
                thumb_word(0xf311_0b12)
            } else {
                0xf311_0b12
            };
            let [b0, b1, b2, b3] = raw.to_le_bytes();
            let bytes = if thumb {
                [b2, b3, b0, b1]
            } else {
                [b0, b1, b2, b3]
            };
            cpu.write_memory(0x104, &bytes).unwrap();
            cpu.set_simd(0, u128::from(INPUT[0]) | (u128::from(INPUT[1]) << 64));
            cpu.set_simd(1, u128::from(INPUT[2]));
            let before = cpu.get_simd(0);
            if field == 1 {
                assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
                assert_eq!(
                    cpu.get_simd(0),
                    (before & !u128::from(u64::MAX)) | 0x7fff_8000_7ffe_0000
                );
                assert_eq!(cpu.fpsr_value() & QC, QC);
            } else {
                assert!(
                    matches!(cpu.step(), Err(ArmError::UndefinedInstruction(actual)) if actual == raw)
                );
                assert_eq!(cpu.get_simd(0), before);
                assert_eq!(cpu.get_pc(), 0x104);
                assert_eq!(cpu.fpsr_value() & QC, 0);
            }
        }
    }
}

#[test]
fn rdm_id_reads_trap_on_tid3_without_fp_data_access() {
    for thumb in [false, true] {
        let mut cpu = mixed(ID_ISAR5, thumb, 2, false, false);
        let mut state = cpu.export_sregs();
        state.execution.as_mut().unwrap().sysregs.hcr_el2 |= 1 << 18;
        cpu.import_sregs(&state).unwrap();
        cpu.set_x(0, 0x1357);
        assert!(matches!(
            cpu.step(),
            Err(ArmError::ArchitecturalException {
                ec: 3,
                target_el: Some(2),
                ..
            })
        ));
        assert_eq!(cpu.get_x(0), 0x1357);
        assert_eq!(cpu.get_pc(), 0x100);
        assert_eq!(cpu.instruction_count(), 0);
    }
}
