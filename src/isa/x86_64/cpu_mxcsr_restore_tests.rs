//! Portable direct state-restore MXCSR regressions.
//!
//! Intel SDM 086 (December 2024), Vol. 1 §§10.5.3, 13.8.1, 13.8.2,
//! and 13.12; Vol. 2A FXRSTOR and Vol. 2D XRSTOR/XRSTORS entries.
//! Every encoding below restores from [RBX]; 0F AE /1 is FXRSTOR,
//! 0F AE /5 is XRSTOR, and 0F C7 /3 is XRSTORS.

use super::*;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

#[path = "cpu_mxcsr_restore_tests/parity.rs"]
mod parity;

const CODE: u64 = 0x1000;
const AREA: u64 = 0x4000;
const ORIGINAL_MXCSR: u32 = 0xFFE5;
const COMPACTED: u64 = 1 << 63;

#[derive(Clone, Copy, Debug)]
enum Restore {
    Fx,
    Standard,
    Compacted,
    Supervisor,
}

impl Restore {
    fn bytes(self, rex_w: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        if rex_w {
            bytes.push(0x48);
        }
        bytes.extend_from_slice(match self {
            Self::Fx => &[0x0F, 0xAE, 0x0B],
            Self::Standard | Self::Compacted => &[0x0F, 0xAE, 0x2B],
            Self::Supervisor => &[0x0F, 0xC7, 0x1B],
        });
        bytes
    }

    fn compacted(self) -> bool {
        matches!(self, Self::Compacted | Self::Supervisor)
    }
}

fn put(memory: &GuestMemoryMmap, addr: u64, value: u64, width: usize) {
    memory
        .write_slice(&value.to_le_bytes()[..width], GuestAddress(addr))
        .unwrap();
}

fn cpu(kind: Restore, rex_w: bool) -> (X86_64Vcpu, Arc<GuestMemoryMmap>) {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
    memory
        .write_slice(&kind.bytes(rex_w), GuestAddress(CODE))
        .unwrap();
    let mut vcpu = X86_64Vcpu::new(0, memory.clone());
    vcpu.sregs.efer = (1 << 8) | (1 << 10);
    vcpu.sregs.cs.l = true;
    vcpu.sregs.cs.db = false;
    vcpu.sregs.cs.selector = 0;
    vcpu.sregs.cr0 = 0x21;
    vcpu.sregs.cr2 = 0xCAFE_BABE;
    vcpu.sregs.cr4 = (1 << 9) | (1 << 18);
    vcpu.xcr0 = 7;
    vcpu.regs.rip = CODE;
    vcpu.regs.rsp = 0x7000;
    vcpu.regs.rbx = AREA;
    vcpu.regs.rax = 7;
    vcpu.regs.rflags = 0xCD7;
    vcpu.mxcsr = ORIGINAL_MXCSR;
    vcpu.fpu.control_word = 0x0B7F;
    vcpu.fpu.status_word = 0x2845;
    vcpu.fpu.tag_word = 0xCAFE;
    vcpu.fpu.top = 5;
    vcpu.fpu.instr_ptr = 0x1122_3344_5566_7788;
    vcpu.fpu.data_ptr = 0x8877_6655_4433_2211;
    vcpu.fpu.last_opcode = 0x3A5;
    vcpu.fpu.st = std::array::from_fn(|index| {
        crate::smir::interpret::SmirInterpreter::x86_x87_from_f64(index as f64 + 0.25)
    });
    for index in 0..16 {
        vcpu.regs.xmm[index] = [0x1111_2222_3333_4444 ^ index as u64; 2];
        vcpu.regs.ymm_high[index] = [0x5555_6666_7777_8888 ^ index as u64; 2];
        vcpu.regs.zmm_high[index] = [0x9999_AAAA_BBBB_CCCC ^ index as u64; 4];
        vcpu.regs.zmm_ext[index] = [0xDDDD_EEEE_FFFF_0000 ^ index as u64; 8];
    }
    vcpu.regs.k = std::array::from_fn(|index| 0xFEDC_BA98_7654_3210 ^ index as u64);
    image(&memory, AREA, kind, 7, 0x3FA1);
    (vcpu, memory)
}

fn image(memory: &GuestMemoryMmap, addr: u64, kind: Restore, xstate: u64, mxcsr: u32) {
    memory
        .write_slice(&[0u8; 0xB00], GuestAddress(addr))
        .unwrap();
    put(memory, addr, 0x027F, 2);
    put(memory, addr + 2, 0x0800, 2);
    put(memory, addr + 4, 0xFF, 1);
    put(memory, addr + 6, 0x125, 2);
    put(memory, addr + 8, 0x1234_5678, 8);
    put(memory, addr + 16, 0x8765_4321, 8);
    put(memory, addr + 24, u64::from(mxcsr), 4);
    // This save-area field is ignored by all restore forms, not a permission
    // mask by which the image can enable otherwise-reserved MXCSR bits.
    put(memory, addr + 28, u64::from(u32::MAX), 4);
    for index in 0..16 {
        put(memory, addr + 160 + index * 16, 0x1234_0000 | index, 8);
        put(memory, addr + 168 + index * 16, 0xABCD_0000 | index, 8);
        put(memory, addr + 576 + index * 16, 0x5678_0000 | index, 8);
        put(memory, addr + 584 + index * 16, 0xEF01_0000 | index, 8);
    }
    put(memory, addr + 512, xstate, 8);
    put(
        memory,
        addr + 520,
        if kind.compacted() { COMPACTED | 7 } else { 0 },
        8,
    );
}

fn payload(vcpu: &X86_64Vcpu) -> (Vec<u8>, Vec<u8>) {
    // Bincode preserves the exact binary80 register bytes of the snapshot,
    // including signed zero and NaN payloads.
    (
        bincode::serialize(&vcpu.regs).unwrap(),
        bincode::serialize(&vcpu.get_emulator_state().unwrap()).unwrap(),
    )
}

fn fault(vcpu: &mut X86_64Vcpu, vector: u8) {
    let error = vcpu
        .step()
        .expect_err("the empty IDT must report the attempted architectural exception");
    assert!(
        error
            .to_string()
            .contains(&format!("IDT entry {vector} not present")),
        "expected exception vector {vector}, got {error}"
    );
    assert_eq!(vcpu.regs.rip, CODE, "fault must retain the instruction PC");
}

#[test]
fn direct_mxcsr_restore_rejects_each_reserved_bit_before_any_payload_commit() {
    for (kind, requested, xstate) in [
        (Restore::Fx, 7, 7),
        (Restore::Standard, 3, 3),
        (Restore::Standard, 3, 1), // SSE init still loads MXCSR.
        (Restore::Standard, 5, 1), // AVX-only selection still loads MXCSR.
        (Restore::Compacted, 3, 3),
        (Restore::Supervisor, 3, 3),
    ] {
        for rex_w in [false, true] {
            for bit in 16..32 {
                let (mut vcpu, memory) = cpu(kind, rex_w);
                vcpu.regs.rax = requested;
                image(&memory, AREA, kind, xstate, 0x1F80 | (1 << bit));
                let before = payload(&vcpu);
                fault(&mut vcpu, 13);
                assert_eq!(payload(&vcpu), before, "{kind:?}, REX.W={rex_w}, bit={bit}");
                assert_eq!(vcpu.sregs.cr2, 0xCAFE_BABE, "#GP must not alter CR2");
            }
        }
    }
}

#[test]
fn direct_mxcsr_restore_selection_distinguishes_standard_and_compacted_forms() {
    for kind in [Restore::Standard, Restore::Compacted, Restore::Supervisor] {
        for rex_w in [false, true] {
            for requested in 0u64..8 {
                for xstate in 0u64..8 {
                    let (mut vcpu, memory) = cpu(kind, rex_w);
                    // The upper halves of EAX/EDX are not part of EDX:EAX.
                    vcpu.regs.rax = 0xA5A5_A5A5_0000_0000 | requested;
                    vcpu.regs.rdx = 0x5A5A_5A5A_0000_0000;
                    image(&memory, AREA, kind, xstate, 0x0041);
                    assert!(vcpu.step().unwrap().is_none());
                    let expected = if kind.compacted() {
                        if requested & 2 == 0 {
                            ORIGINAL_MXCSR
                        } else if xstate & 2 == 0 {
                            0x1F80
                        } else {
                            0x0041
                        }
                    } else if requested & 6 != 0 {
                        0x0041
                    } else {
                        ORIGINAL_MXCSR
                    };
                    assert_eq!(
                        vcpu.mxcsr, expected,
                        "{kind:?}, REX.W={rex_w}, RFBM={requested:#x}, XSTATE_BV={xstate:#x}"
                    );
                    assert_eq!(vcpu.regs.rip, CODE + kind.bytes(rex_w).len() as u64);
                    assert_eq!(vcpu.regs.rflags, 0xCD7);
                }
            }
        }
    }
}

#[test]
fn direct_mxcsr_restore_ignores_invalid_memory_when_mxcsr_is_unselected_or_initialized() {
    for (kind, requested, xstate, expected) in [
        (Restore::Standard, 1, 1, ORIGINAL_MXCSR),
        (Restore::Compacted, 5, 5, ORIGINAL_MXCSR),
        (Restore::Supervisor, 5, 5, ORIGINAL_MXCSR),
        (Restore::Compacted, 3, 1, 0x1F80),
        (Restore::Supervisor, 3, 1, 0x1F80),
    ] {
        for rex_w in [false, true] {
            let (mut vcpu, memory) = cpu(kind, rex_w);
            vcpu.regs.rax = requested;
            image(&memory, AREA, kind, xstate, u32::MAX);
            assert!(vcpu.step().unwrap().is_none(), "{kind:?}");
            assert_eq!(vcpu.mxcsr, expected, "{kind:?}, RFBM={requested:#x}");
        }
    }
}

#[test]
fn direct_mxcsr_restore_fxrstor_accepts_all_supported_bits_and_pending_unmasked_status() {
    for long_mode in [false, true] {
        for rex_w in [false, true] {
            if rex_w && !long_mode {
                continue;
            }
            for value in [0, 0x0041, 0x003F, 0x1F80, 0xFFFF] {
                for osfxsr in [false, true] {
                    let (mut vcpu, memory) = cpu(Restore::Fx, rex_w);
                    vcpu.sregs.cs.l = long_mode;
                    vcpu.sregs.cs.db = !long_mode;
                    if !osfxsr {
                        vcpu.sregs.cr4 &= !(1 << 9);
                    }
                    image(&memory, AREA, Restore::Fx, 7, value);
                    // RAX's existing OSFXSR=0 implementation choice restores
                    // SSE state; the SDM permits either choice in this mode.
                    assert!(vcpu.step().unwrap().is_none());
                    assert_eq!(vcpu.mxcsr, value);
                    assert_eq!(vcpu.regs.rip, CODE + Restore::Fx.bytes(rex_w).len() as u64);
                    assert_eq!(vcpu.regs.rflags, 0xCD7);
                }
            }
        }
    }
}

#[test]
fn direct_mxcsr_restore_earlier_legality_faults_precede_operand_reads_and_commit() {
    for kind in [
        Restore::Fx,
        Restore::Standard,
        Restore::Compacted,
        Restore::Supervisor,
    ] {
        for rex_w in [false, true] {
            for case in 0..5 {
                if (matches!(kind, Restore::Fx) && matches!(case, 0 | 4))
                    || (!matches!(kind, Restore::Fx) && case == 2)
                    || (!matches!(kind, Restore::Supervisor) && case == 4)
                {
                    continue;
                }
                let (mut vcpu, _) = cpu(kind, rex_w);
                vcpu.regs.rbx = 0x20001; // Unmapped and misaligned.
                let vector = match case {
                    0 => {
                        vcpu.sregs.cr4 &= !(1 << 18);
                        vcpu.sregs.cr0 |= 1 << 3;
                        6
                    }
                    1 => {
                        vcpu.sregs.cr0 |= 1 << 3;
                        7
                    }
                    2 => {
                        vcpu.sregs.cr0 |= 1 << 2;
                        7
                    }
                    3 => 13, // Alignment precedes any memory fetch.
                    4 => {
                        vcpu.sregs.cs.selector = 3;
                        vcpu.regs.rbx = 0x20000;
                        13
                    }
                    _ => unreachable!(),
                };
                let before = payload(&vcpu);
                fault(&mut vcpu, vector);
                assert_eq!(
                    payload(&vcpu),
                    before,
                    "{kind:?}, REX.W={rex_w}, case={case}"
                );
                assert_eq!(vcpu.sregs.cr2, 0xCAFE_BABE);
            }
        }
    }
}

fn split_header_cpu(kind: Restore) -> (X86_64Vcpu, Arc<GuestMemoryMmap>) {
    let (mut vcpu, memory) = cpu(kind, false);
    // The 64-byte-aligned area's MXCSR lies in absent page 3, while its XSAVE
    // header begins at mapped page 4. This makes header-before-MXCSR ordering
    // observable independently of the value stored in either field.
    vcpu.regs.rbx = 0x3E00;
    image(&memory, 0x3E00, kind, 2, 0x1F80);
    for (addr, value) in [(0x8000, 0x9007), (0x9000, 0xA007), (0xA000, 0xB007)] {
        put(&memory, addr, value, 8);
    }
    for page in [0u64, 1, 2, 4, 5, 6, 7] {
        put(&memory, 0xB000 + page * 8, page * 0x1000 | 7, 8);
    }
    vcpu.sregs.cr0 = 0x8005_0033;
    vcpu.sregs.cr3 = 0x8000;
    vcpu.sregs.cr4 |= 1 << 5;
    (vcpu, memory)
}

#[test]
fn direct_mxcsr_restore_header_faults_precede_selected_mxcsr_page_faults() {
    for kind in [Restore::Standard, Restore::Compacted, Restore::Supervisor] {
        let malformed: &[(u64, u64, usize)] = if kind.compacted() {
            &[
                (520, COMPACTED | 8, 8), // Unsupported format component.
                (512, 8, 8),             // XSTATE_BV is not a subset of format.
                (528, 1, 1),
                (575, 1, 1),
            ]
        } else {
            &[
                (512, 8, 8),
                (512, COMPACTED | 2, 8), // Bit 63 requires compacted XCOMP_BV.
                (520, 1, 8),
                (528, 1, 1),
                (535, 1, 1),
            ]
        };
        for &(offset, value, width) in malformed {
            let (mut vcpu, memory) = split_header_cpu(kind);
            vcpu.regs.rax = 2;
            put(&memory, 0x3E00 + offset, value, width);
            let before = payload(&vcpu);
            fault(&mut vcpu, 13);
            assert_eq!(payload(&vcpu), before, "{kind:?}, header offset {offset}");
            assert_eq!(vcpu.sregs.cr2, 0xCAFE_BABE);
        }
    }

    let (mut vcpu, memory) = split_header_cpu(Restore::Supervisor);
    vcpu.regs.rax = 2;
    put(&memory, 0x3E00 + 520, 0, 8); // XRSTORS has no standard form.
    let before = payload(&vcpu);
    fault(&mut vcpu, 13);
    assert_eq!(payload(&vcpu), before);
    assert_eq!(vcpu.sregs.cr2, 0xCAFE_BABE);
}

#[test]
fn direct_mxcsr_restore_only_selected_memory_values_can_page_fault() {
    for (kind, requested, xstate, expected) in [
        (Restore::Standard, 2, 0, None),
        (Restore::Standard, 4, 0, None),
        (Restore::Compacted, 2, 2, None),
        (Restore::Supervisor, 2, 2, None),
        (Restore::Standard, 0, 0, Some(ORIGINAL_MXCSR)),
        (Restore::Compacted, 4, 0, Some(ORIGINAL_MXCSR)),
        (Restore::Supervisor, 4, 0, Some(ORIGINAL_MXCSR)),
        (Restore::Compacted, 2, 0, Some(0x1F80)),
        (Restore::Supervisor, 2, 0, Some(0x1F80)),
    ] {
        let (mut vcpu, memory) = split_header_cpu(kind);
        vcpu.regs.rax = requested;
        put(&memory, 0x3E00 + 512, xstate, 8);
        let before = payload(&vcpu);
        let result = vcpu.step();
        if let Some(expected) = expected {
            assert!(result.unwrap().is_none(), "{kind:?}");
            assert_eq!(vcpu.mxcsr, expected, "{kind:?}");
            assert_eq!(vcpu.regs.rip, CODE + kind.bytes(false).len() as u64);
        } else {
            assert!(
                matches!(
                    result,
                    Err(Error::PageFault {
                        vaddr: 0x3E18,
                        error_code: 0
                    })
                ),
                "{kind:?}, RFBM={requested:#x}: {result:?}"
            );
            assert_eq!(payload(&vcpu), before, "{kind:?}");
        }
    }
}

#[test]
fn direct_mxcsr_restore_standard_ignores_only_the_unspecified_header_tail() {
    for offset in 536..576 {
        let (mut vcpu, memory) = split_header_cpu(Restore::Standard);
        vcpu.regs.rax = 0;
        put(&memory, 0x3E00 + 512, 0, 8);
        put(&memory, 0x3E00 + offset, 0xFF, 1);
        assert!(
            vcpu.step().unwrap().is_none(),
            "header byte {}",
            offset - 512
        );
        assert_eq!(vcpu.mxcsr, ORIGINAL_MXCSR);
        assert_eq!(vcpu.regs.rip, CODE + 3);
    }
}

#[test]
fn direct_mxcsr_restore_snapshot_rejects_reserved_bits_without_mutation() {
    for bit in 16..32 {
        let (mut vcpu, _) = cpu(Restore::Fx, false);
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        {
            vcpu.jit_vsib_resume_pc = Some(CODE);
        }
        let before = payload(&vcpu);
        let mut state = vcpu.get_emulator_state().unwrap();
        state.mxcsr = 0x1F80 | (1 << bit);
        state.fpu.control_word ^= 0x400;
        state.fpu.st[0] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80]; // -0.0
        state.lazy_flags.op = 1;
        state.lazy_flags.result = u64::MAX;
        state.kernel_gs_base ^= u64::MAX;
        state.tsc_aux ^= u32::MAX;
        state.pat ^= u64::MAX;
        state.halted = !state.halted;
        state.interrupt_inhibit = !state.interrupt_inhibit;
        let error = vcpu
            .set_emulator_state(&state)
            .expect_err("invalid snapshot MXCSR");
        assert!(error.to_string().contains("MXCSR"));
        assert_eq!(payload(&vcpu), before, "reserved bit {bit}");
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        assert_eq!(vcpu.jit_vsib_resume_pc, Some(CODE));
    }
}

#[test]
fn direct_mxcsr_restore_snapshot_roundtrips_supported_mxcsr_and_all_existing_fields() {
    for mxcsr in [0, 0x0041, 0x003F, 0x1F80, 0xFFFF] {
        let (mut vcpu, _) = cpu(Restore::Fx, false);
        let mut state = vcpu.get_emulator_state().unwrap();
        state.mxcsr = mxcsr;
        // A quiet NaN with a payload, in binary80.
        state.fpu.st = [[0x42, 0, 0, 0, 0, 0, 0, 0xC0, 0xFF, 0x7F]; 8];
        state.fpu.top = 7;
        state.fpu.status_word = 7 << 11;
        state.lazy_flags.op = 5;
        state.lazy_flags.result = 0xFEDC_BA98_7654_3210;
        state.lazy_flags.src = 0xCAFE;
        state.lazy_flags.dst = 0xBABE;
        state.lazy_flags.size = 8;
        state.kernel_gs_base = 0x1234;
        state.tsc_adjust = 0x2345;
        state.tsc_aux = 0x3456;
        state.misc_enable = 0x4567;
        state.pat = 0x5678;
        state.umwait_control = 0x6789;
        state.pkru = 0x789A;
        state.halted = true;
        state.interrupt_inhibit = true;
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        {
            vcpu.jit_vsib_resume_pc = Some(CODE);
        }
        vcpu.set_emulator_state(&state).unwrap();
        assert_eq!(
            bincode::serialize(&vcpu.get_emulator_state().unwrap()).unwrap(),
            bincode::serialize(&state).unwrap()
        );
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        assert_eq!(vcpu.jit_vsib_resume_pc, None);
    }
}
