//! EVEX VRNDSCALE{PH,PS,PD,SH,SS,SD} lifted interpretation tests.

use super::*;
use crate::smir::interpret::tests::*;
use crate::smir::interpret::*;

fn vector_u32(values: &[u32], fill: u64) -> VecValue {
    let mut bytes = values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    bytes.resize(bytes.len().next_multiple_of(8), 0);
    let mut result = [fill; 16];
    for (index, chunk) in bytes.chunks_exact(8).enumerate() {
        result[index] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    result
}
fn lanes_u32(value: &VecValue, count: usize) -> Vec<u32> {
    value
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .take(count * 4)
        .collect::<Vec<_>>()
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect()
}
fn vector_u16(values: &[u16], fill: u64) -> VecValue {
    let mut bytes = values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    bytes.resize(bytes.len().next_multiple_of(8), 0);
    let mut result = [fill; 16];
    for (index, chunk) in bytes.chunks_exact(8).enumerate() {
        result[index] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    result
}
fn lanes_u16(value: &VecValue, count: usize) -> Vec<u16> {
    value
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .take(count * 2)
        .collect::<Vec<_>>()
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes(chunk.try_into().unwrap()))
        .collect()
}

const IE: u32 = 1;
const UE: u32 = 1 << 4;
const PE: u32 = 1 << 5;
const DAZ: u32 = 1 << 6;
const IM: u32 = 1 << 7;
const UM: u32 = 1 << 11;
const PM: u32 = 1 << 12;
const FTZ: u32 = 1 << 15;

#[test]
fn lifted_round_scale_executes_grids_mxcsr_masks_sae_and_faults() {
    let sentinel = [0xCCCC_CCCC_CCCC_CCCCu64; 16];
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x200);

    // M=0 selects the integer grid. The low two immediate bits select all
    // four IEEE rounding directions when imm[2] is clear.
    let source = [1.5f32, 2.5, -1.5, -2.5].map(f32::to_bits);
    for (imm, expected) in [
        (0x00, [2.0f32, 2.0, -2.0, -2.0]),
        (0x01, [1.0f32, 2.0, -2.0, -3.0]),
        (0x02, [2.0f32, 3.0, -1.0, -2.0]),
        (0x03, [1.0f32, 2.0, -1.0, -2.0]),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.xmm[1] = sentinel;
            x86.xmm[3] = vector_u32(&source, 0);
            x86.mxcsr = 0x1F80;
        }
        let result = execute_lifted_x86(
            &[0x62, 0xF3, 0x7D, 0x08, 0x08, 0xCB, imm],
            &mut ctx,
            &mut memory,
        );
        assert!(matches!(result, BlockResult::Exit(ExitReason::Halt)));
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(lanes_u32(&x86.xmm[1], 4), expected.map(f32::to_bits));
            assert!(x86.xmm[1][2..].iter().all(|word| *word == 0));
            assert_ne!(x86.mxcsr & PE, 0);
        }
    }

    // M=1 rounds to a 2^-1 grid. imm[2] delegates the rounding direction
    // to MXCSR.RC and ignores the immediate RC bits.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[3] = vector_u32(&[1.25f32, 1.75, -1.25, -1.75].map(f32::to_bits), 0);
        x86.mxcsr = 0x1F80;
    }
    execute_lifted_x86(
        &[0x62, 0xF3, 0x7D, 0x08, 0x08, 0xCB, 0x10],
        &mut ctx,
        &mut memory,
    );
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            lanes_u32(&x86.xmm[1], 4),
            [1.0f32, 2.0, -1.0, -2.0].map(f32::to_bits)
        );
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[3] = vector_u32(&[1.25f32.to_bits(); 4], 0);
        x86.mxcsr = 0x1F80 | (2 << 13); // round toward +infinity
    }
    execute_lifted_x86(
        &[0x62, 0xF3, 0x7D, 0x08, 0x08, 0xCB, 0x07],
        &mut ctx,
        &mut memory,
    );
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(lanes_u32(&x86.xmm[1], 4), [2.0f32.to_bits(); 4]);
    }

    // imm[3] suppresses only precision. An unmasked precision exception
    // commits MXCSR.PE but leaves the destination atomic; SPE avoids both.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = sentinel;
        x86.xmm[3] = vector_u32(&[1.25f32.to_bits(); 4], 0);
        x86.mxcsr = 0x1F80 & !PM;
    }
    let precision = execute_lifted_x86(
        &[0x62, 0xF3, 0x7D, 0x08, 0x08, 0xCB, 0x00],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(
        precision,
        BlockResult::Exit(ExitReason::SimdFloatingPoint { .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1], sentinel);
        assert_ne!(x86.mxcsr & PE, 0);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = sentinel;
        x86.mxcsr = 0x1F80 & !PM;
    }
    let precision_suppressed = execute_lifted_x86(
        &[0x62, 0xF3, 0x7D, 0x08, 0x08, 0xCB, 0x08],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(
        precision_suppressed,
        BlockResult::Exit(ExitReason::Halt)
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(lanes_u32(&x86.xmm[1], 4), [1.0f32.to_bits(); 4]);
        assert_eq!(x86.mxcsr & PE, 0);
    }

    // Zeros and infinities are unchanged. QNaN sign/payload survive while
    // SNaN is quieted and raises IE unless an inactive mask or SAE applies.
    let qnan = 0xFFC0_1234u32;
    let snan = 0xFF80_5678u32;
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[3] = vector_u32(
            &[
                0.0f32.to_bits(),
                (-0.0f32).to_bits(),
                f32::INFINITY.to_bits(),
                f32::NEG_INFINITY.to_bits(),
            ],
            0,
        );
        x86.mxcsr = 0x1F80;
    }
    execute_lifted_x86(
        &[0x62, 0xF3, 0x7D, 0x08, 0x08, 0xCB, 0xF3],
        &mut ctx,
        &mut memory,
    );
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            lanes_u32(&x86.xmm[1], 4),
            [
                0.0f32.to_bits(),
                (-0.0f32).to_bits(),
                f32::INFINITY.to_bits(),
                f32::NEG_INFINITY.to_bits(),
            ]
        );
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = sentinel;
        x86.xmm[3] = vector_u32(&[qnan, snan, qnan, snan], 0);
        x86.mxcsr = 0x1F80 & !IM;
    }
    let invalid = execute_lifted_x86(
        &[0x62, 0xF3, 0x7D, 0x08, 0x08, 0xCB, 0x00],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(
        invalid,
        BlockResult::Exit(ExitReason::SimdFloatingPoint { .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1], sentinel);
        assert_ne!(x86.mxcsr & IE, 0);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = sentinel;
        x86.xmm[3] = vector_u32(&[snan; 16], 0);
        x86.mxcsr = 0x1F80 & !IM;
    }
    let sae = execute_lifted_x86(
        &[0x62, 0xF3, 0x7D, 0x18, 0x08, 0xCB, 0x00],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(sae, BlockResult::Exit(ExitReason::Halt)));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(lanes_u32(&x86.xmm[1], 1), [snan | 0x0040_0000]);
        assert_eq!(x86.mxcsr & 0x3F, 0);
    }

    // DAZ affects FP32/FP64 only. FP16 ignores DAZ and FTZ; M=15 with RU
    // maps the smallest subnormal to 2^-15, reports UE and optionally PE.
    for (mxcsr, expected_status) in [(0x1F80, PE), (0x1F80 | DAZ, 0)] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.xmm[3] = vector_u32(&[0x8000_0001; 4], 0);
            x86.mxcsr = mxcsr;
        }
        execute_lifted_x86(
            &[0x62, 0xF3, 0x7D, 0x08, 0x08, 0xCB, 0x00],
            &mut ctx,
            &mut memory,
        );
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(lanes_u32(&x86.xmm[1], 4), [0x8000_0000; 4]);
            assert_eq!(x86.mxcsr & (IE | UE | PE), expected_status);
        }
    }
    for (imm, expected_status) in [(0xF2, UE | PE), (0xFA, UE)] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.xmm[3] = vector_u16(&[1; 8], 0);
            x86.mxcsr = 0x1F80 | DAZ | FTZ;
        }
        execute_lifted_x86(
            &[0x62, 0xF3, 0x7C, 0x08, 0x08, 0xCB, imm],
            &mut ctx,
            &mut memory,
        );
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(lanes_u16(&x86.xmm[1], 8), [0x0200; 8]);
            assert_eq!(x86.mxcsr & (UE | PE), expected_status);
        }
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = sentinel;
        x86.xmm[3] = vector_u16(&[1; 32], 0);
        x86.mxcsr = (0x1F80 | DAZ | FTZ) & !UM;
    }
    let fp16_underflow_sae = execute_lifted_x86(
        &[0x62, 0xF3, 0x7C, 0x18, 0x08, 0xCB, 0xF2],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(
        fp16_underflow_sae,
        BlockResult::Exit(ExitReason::Halt)
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(lanes_u16(&x86.xmm[1], 32), [0x0200; 32]);
        assert_eq!(x86.mxcsr & (UE | PE), 0);
    }

    // F64 uses the same immediate grid without host floating-point state.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[3] = [
            1.25f64.to_bits(),
            (-1.75f64).to_bits(),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        x86.mxcsr = 0x1F80;
    }
    execute_lifted_x86(
        &[0x62, 0xF3, 0xFD, 0x08, 0x09, 0xCB, 0x10],
        &mut ctx,
        &mut memory,
    );
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1][..2], [1.0f64.to_bits(), (-2.0f64).to_bits()]);
    }

    // Scalar writemasking applies to the low element only. Inactive merge
    // preserves old dst[31:0], copies upper XMM bits from vvvv, and clears
    // architectural state above bit 127; {z} replaces only the low lane.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = vector_u32(&[7.0f32.to_bits(); 4], sentinel[0]);
        x86.xmm[2] = vector_u32(
            &[
                99.0f32.to_bits(),
                11.0f32.to_bits(),
                12.0f32.to_bits(),
                13.0f32.to_bits(),
            ],
            sentinel[0],
        );
        x86.xmm[3] = vector_u32(&[snan, 0, 0, 0], 0);
        x86.k[2] = 0;
        x86.mxcsr = 0x1F80 & !IM;
    }
    let masked_snan = execute_lifted_x86(
        &[0x62, 0xF3, 0x6D, 0x0A, 0x0A, 0xCB, 0x00],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(masked_snan, BlockResult::Exit(ExitReason::Halt)));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(
            lanes_u32(&x86.xmm[1], 4),
            [7.0f32, 11.0, 12.0, 13.0].map(f32::to_bits)
        );
        assert!(x86.xmm[1][2..].iter().all(|word| *word == 0));
        assert_eq!(x86.mxcsr & IE, 0);
    }
    execute_lifted_x86(
        &[0x62, 0xF3, 0x6D, 0x8A, 0x0A, 0xCB, 0x00],
        &mut ctx,
        &mut memory,
    );
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(lanes_u32(&x86.xmm[1], 1), [0]);
    }

    // Inactive scalar and packed-broadcast masks suppress invalid memory.
    // Any applicable active bit performs exactly one scalar broadcast read.
    ctx.write_vreg(rax, 0x300);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = sentinel;
        x86.k[2] = 0;
        x86.mxcsr = 0x1F80;
    }
    let scalar_suppressed = execute_lifted_x86(
        &[0x62, 0xF3, 0x6D, 0x0A, 0x0A, 0x08, 0x00],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(
        scalar_suppressed,
        BlockResult::Exit(ExitReason::Halt)
    ));
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[1] = sentinel;
        x86.k[2] = 1;
    }
    let scalar_fault = execute_lifted_x86(
        &[0x62, 0xF3, 0x6D, 0x0A, 0x0A, 0x08, 0x00],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(
        scalar_fault,
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[1], sentinel);
    }
    let mut broadcast_preserved = sentinel;
    broadcast_preserved[8..].fill(0);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.xmm[0] = sentinel;
        x86.k[2] = 1 << 63;
    }
    let broadcast_suppressed = execute_lifted_x86(
        &[0x62, 0xF3, 0x7D, 0x5A, 0x08, 0x00, 0x00],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(
        broadcast_suppressed,
        BlockResult::Exit(ExitReason::Halt)
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[0], broadcast_preserved);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.k[2] = 1;
    }
    let broadcast_fault = execute_lifted_x86(
        &[0x62, 0xF3, 0x7D, 0x5A, 0x08, 0x00, 0x00],
        &mut ctx,
        &mut memory,
    );
    assert!(matches!(
        broadcast_fault,
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.xmm[0], broadcast_preserved);
    }
}

#[test]
fn lifted_fp16_round_scale_to_signed_zero_reports_precision_without_underflow() {
    // M=11 selects a 2^-11 grid, so every non-zero result is at least the
    // FP16 minimum normal 2^-14. Nonzero sources below 2^-12 round to signed
    // zero; that result is not tiny and reports only precision.
    let source = [
        0x0C00, 0x8C00, 0x0001, 0x8001, 0x03FF, 0x0E00, 0x1000, 0x0000u16,
    ];
    let expected = [
        0x0000, 0x8000, 0x0000, 0x8000, 0x0000, 0x1000, 0x1000, 0x0000u16,
    ];
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x200);
    for (mxcsr, imm, expected_status) in [
        (0x1F80, 0xB0, PE),
        // RS selects MXCSR.RC; FP16 ignores FTZ and DAZ.
        (0x1F80 | FTZ, 0xB6, PE),
        (0x1F80 | DAZ | FTZ, 0xB0, PE),
        // SPE suppresses precision and no underflow remains to report.
        (0x1F80, 0xB8, 0),
        // An unmasked underflow requires a non-zero tiny result.
        (0x1F80 & !UM, 0xB0, PE),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.xmm[1] = [0xCCCC_CCCC_CCCC_CCCC; 16];
            x86.xmm[3] = vector_u16(&source, 0);
            x86.mxcsr = mxcsr;
        }
        let result = execute_lifted_x86(
            &[0x62, 0xF3, 0x7C, 0x08, 0x08, 0xCB, imm],
            &mut ctx,
            &mut memory,
        );
        assert!(
            matches!(result, BlockResult::Exit(ExitReason::Halt)),
            "MXCSR {mxcsr:#06x} imm {imm:#04x}: {result:?}"
        );
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(lanes_u16(&x86.xmm[1], 8), expected);
            assert!(x86.xmm[1][2..].iter().all(|word| *word == 0));
            assert_eq!(
                x86.mxcsr & (IE | UE | PE),
                expected_status,
                "MXCSR {mxcsr:#06x} imm {imm:#04x}"
            );
        }
    }
}
