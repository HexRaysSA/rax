//! Embedder x87 initialization, distinct from XRSTOR init-state payload clearing.
//!
//! Expectations follow the retained Intel SDM revision 086, Vol. 2A,
//! FINIT/FNINIT pp. 3-405–3-406 and FLDCW pp. 3-416–3-417:
//! `docs/specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf`.
//! The instruction comparison is direct-interpreter parity, not a silicon oracle.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use super::X86_64Vcpu;
use crate::error::{GuestMemoryFault, MemoryAccessKind};
use crate::isa::x86_64::cpu::LazyFlagOp;
use crate::isa::x86_64::{X86EventSource, X86UserEvent, X86UserTrap};
use crate::vm::memory::FlatTranslation;
use crate::vm::vcpu::VCpu;

const CODE: u64 = 0x40_0000;
const DATA: u64 = 0x60_0000;

#[derive(Default)]
struct TestSpace {
    accesses: AtomicUsize,
}

impl FlatTranslation for TestSpace {
    fn translate(&self, linear: u64, access: MemoryAccessKind) -> Result<u64, GuestMemoryFault> {
        self.accesses.fetch_add(1, Ordering::Relaxed);
        if (CODE..CODE + 0x1000).contains(&linear)
            && matches!(access, MemoryAccessKind::Read | MemoryAccessKind::Fetch)
        {
            Ok(linear - CODE)
        } else if (DATA..DATA + 0x1000).contains(&linear)
            && matches!(access, MemoryAccessKind::Read)
        {
            Ok(0x1000 + linear - DATA)
        } else {
            Err(GuestMemoryFault::unmapped(linear, 1, access))
        }
    }
}

fn user_cpu(code: &[u8], control_word: u16, compat: bool) -> (X86_64Vcpu, Arc<TestSpace>) {
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x8000)]).unwrap());
    mem.write_slice(code, GuestAddress(0)).unwrap();
    mem.write_slice(&control_word.to_le_bytes(), GuestAddress(0x1000))
        .unwrap();
    let space = Arc::new(TestSpace::default());
    let mut cpu = X86_64Vcpu::new(0, mem);
    cpu.enable_user_mode(space.clone());
    cpu.set_user_compat(compat);
    cpu.regs.rip = CODE;
    cpu.regs.rax = DATA;
    (cpu, space)
}

fn binary80(significand: u64, sign_exponent: u16) -> [u8; 10] {
    let mut raw = [0; 10];
    raw[..8].copy_from_slice(&significand.to_le_bytes());
    raw[8..].copy_from_slice(&sign_exponent.to_le_bytes());
    raw
}

fn payloads(arbitrary: bool) -> [[u8; 10]; 8] {
    if arbitrary {
        std::array::from_fn(|reg| {
            std::array::from_fn(|byte| 0xA5u8.wrapping_add((reg * 41 + byte * 17) as u8))
        })
    } else {
        [
            binary80(0, 0),                          // +0
            binary80(0, 0x8000),                     // -0
            binary80(1, 0),                          // smallest positive subnormal
            binary80(u64::MAX, 0x7FFE),              // largest positive finite value
            binary80(1 << 63, 0x7FFF),               // +infinity
            binary80(0xC000_0000_0000_0123, 0xFFFF), // negative quiet NaN with payload
            binary80(0x8000_0000_0000_0123, 0x7FFF), // signaling NaN with payload
            binary80(0x1234_5678_9ABC_DEF0, 0x3FFF), // unsupported unnormal encoding
        ]
    }
}

fn poison_x87(cpu: &mut X86_64Vcpu, top: u8, raw: [[u8; 10]; 8]) {
    cpu.fpu.control_word = 0x0040; // All exception masks clear.
    cpu.fpu.status_word = (0xFFFF & !(7 << 11)) | (u16::from(top) << 11);
    cpu.fpu.tag_word = 0x94E4;
    cpu.fpu.data_ptr = 0xFEDC_BA98_7654_3210;
    cpu.fpu.instr_ptr = 0x1234_5678_9ABC_DEF0;
    cpu.fpu.last_opcode = 0x07FF;
    cpu.fpu.top = top;
    cpu.fpu.st = raw;
}

fn assert_initialized(cpu: &X86_64Vcpu, control_word: u16, raw: [[u8; 10]; 8]) {
    assert_eq!(cpu.fpu.control_word, control_word);
    assert_eq!(cpu.fpu.status_word, 0);
    assert_eq!(cpu.fpu.tag_word, 0xFFFF);
    assert_eq!(cpu.fpu.data_ptr, 0);
    assert_eq!(cpu.fpu.instr_ptr, 0);
    assert_eq!(cpu.fpu.last_opcode, 0);
    assert_eq!(cpu.fpu.top, 0);
    assert_eq!(
        cpu.fpu.st, raw,
        "physical binary80 payloads must not rotate"
    );
}

#[test]
fn user_x87_init_preserves_physical_payloads_for_every_top() {
    for compat in [false, true] {
        for arbitrary in [false, true] {
            let raw = payloads(arbitrary);
            for top in 0..8 {
                for control_word in [0x0000, 0x027F, 0x037F, 0x0F7F, 0xFFFF] {
                    let (mut cpu, space) = user_cpu(&[], 0, compat);
                    poison_x87(&mut cpu, top, raw);
                    let accesses = space.accesses.load(Ordering::Relaxed);
                    cpu.init_user_x87(control_word);
                    assert_initialized(&cpu, control_word, raw);
                    assert_eq!(space.accesses.load(Ordering::Relaxed), accesses);
                    assert_eq!(cpu.take_user_trap(), None);

                    // TOP is now zero: an XSAVE image exposes the preserved
                    // physical R0-R7 payloads in its logical ST0-ST7 slots.
                    let image = cpu.xsave_image(1).bytes;
                    assert_eq!(&image[0..2], &control_word.to_le_bytes());
                    assert_eq!(&image[2..5], &[0, 0, 0]);
                    assert_eq!(&image[6..24], &[0; 18]);
                    for (reg, expected) in raw.iter().enumerate() {
                        let at = 32 + reg * 16;
                        assert_eq!(&image[at..at + 10], expected);
                    }
                }
            }
        }
    }
}

#[test]
fn user_x87_init_installs_every_raw_control_word_without_normalization() {
    let (mut cpu, _) = user_cpu(&[], 0, false);
    let raw = payloads(true);
    cpu.fpu.st = raw;
    // This tests the embedder's exact-bit contract, not hardware behavior for
    // reserved control-word bits or the reserved precision-control encoding.
    for control_word in 0..=u16::MAX {
        cpu.init_user_x87(control_word);
        assert_initialized(&cpu, control_word, raw);
    }
}

fn pattern(index: usize) -> u64 {
    0xA55A_39C6_817E_02FDu64
        .rotate_left(index as u32)
        .wrapping_add((index as u64).wrapping_mul(0x1020_3040_5060_7081))
}

#[test]
fn user_x87_init_preserves_non_x87_state_and_bypasses_instruction_fault_checks() {
    for compat in [false, true] {
        for xcr0 in [0, 1, 0xE7, 0xE7 | (1 << 19)] {
            let (mut cpu, space) = user_cpu(&[], 0, compat);
            poison_x87(&mut cpu, 5, payloads(true));
            for reg in 0..32 {
                cpu.set_reg(reg, pattern(reg as usize), 8);
            }
            cpu.regs.rip = pattern(32);
            cpu.regs.rflags = 0x0045_0247;
            cpu.regs.xmm =
                std::array::from_fn(|i| std::array::from_fn(|j| pattern(40 + i * 2 + j)));
            cpu.regs.ymm_high =
                std::array::from_fn(|i| std::array::from_fn(|j| pattern(80 + i * 2 + j)));
            cpu.regs.zmm_high =
                std::array::from_fn(|i| std::array::from_fn(|j| pattern(120 + i * 4 + j)));
            cpu.regs.zmm_ext =
                std::array::from_fn(|i| std::array::from_fn(|j| pattern(200 + i * 8 + j)));
            cpu.regs.k = std::array::from_fn(|i| pattern(340 + i));
            cpu.regs.mm =
                std::array::from_fn(|i| u64::from_le_bytes(cpu.fpu.st[i][..8].try_into().unwrap()));
            cpu.mxcsr = 0xFFC5;
            cpu.xcr0 = xcr0;
            cpu.xgetbv1_value = 0xA5A5_5A5A;
            cpu.insn_count = 0x1234_5678_9ABC_DEF0;
            cpu.halted = true;
            cpu.interrupt_inhibit = true;
            cpu.sregs.cr0 |= (1 << 2) | (1 << 3) | (1 << 5); // EM, TS, NE
            cpu.sregs.fs.base = 0x0123_4500;
            cpu.sregs.gs.base = 0x0678_9000;
            cpu.pkru = 0xA55A_C33C;
            cpu.lazy_flags.op = LazyFlagOp::Add;
            cpu.lazy_flags.result = 0;
            cpu.lazy_flags.src = u64::MAX;
            cpu.lazy_flags.dst = 1;
            cpu.lazy_flags.size = 8;
            let trap = Some(X86UserTrap::Event(X86UserEvent {
                vector: 16,
                error_code: None,
                source: X86EventSource::Exception,
                insn_rip: CODE,
                return_rip: CODE,
            }));
            cpu.user.as_mut().unwrap().trap = trap;

            let registers = serde_json::to_value(&cpu.regs).unwrap();
            let system = serde_json::to_value(&cpu.sregs).unwrap();
            let before = cpu.get_emulator_state().unwrap();
            let accesses = space.accesses.load(Ordering::Relaxed);
            cpu.init_user_x87(0x027F);
            let mut after = cpu.get_emulator_state().unwrap();
            // Compare every emulator-private non-x87 snapshot field without
            // materializing lazy integer flags; x87 has separate exact checks.
            after.fpu = before.fpu.clone();
            assert_eq!(
                serde_json::to_value(after).unwrap(),
                serde_json::to_value(before).unwrap()
            );
            assert_eq!(serde_json::to_value(&cpu.regs).unwrap(), registers);
            assert_eq!(serde_json::to_value(&cpu.sregs).unwrap(), system);
            assert_eq!(cpu.xcr0, xcr0);
            assert_eq!(cpu.xgetbv1_value, 0xA5A5_5A5A);
            assert_eq!(cpu.insn_count, 0x1234_5678_9ABC_DEF0);
            assert_eq!(cpu.user.as_ref().unwrap().trap, trap);
            assert_eq!(space.accesses.load(Ordering::Relaxed), accesses);
            assert_initialized(&cpu, 0x027F, payloads(true));
        }
    }
}

#[test]
fn user_x87_init_matches_admitted_guest_fninit_then_fldcw() {
    // Intel SDM encodings: FNINIT = DB E3; FLDCW m2byte = D9 /5.
    // D9 28 selects [RAX] in 64-bit mode, [EAX] in compatibility mode.
    // Only architectural control words are used for instruction parity.
    for compat in [false, true] {
        for top in 0..8 {
            for control_word in [0x007F, 0x027F, 0x037F, 0x077F, 0x0B7F, 0x0F7F, 0x037E] {
                let (mut guest, _) = user_cpu(&[0xDB, 0xE3, 0xD9, 0x28], control_word, compat);
                let (mut embedder, _) = user_cpu(&[], 0, compat);
                let raw = payloads(true);
                poison_x87(&mut guest, top, raw);
                poison_x87(&mut embedder, top, raw);
                embedder.init_user_x87(control_word);

                // Old FSW has ES set and all FCW exception masks are clear.
                // FNINIT must not deliver the old pending exception; FLDCW
                // then executes with the cleared status word.
                assert!(guest.step().unwrap().is_none());
                assert!(guest.step().unwrap().is_none());
                assert_eq!(guest.take_user_trap(), None);
                assert_eq!(guest.regs.rip, CODE + 4);
                let mut actual = guest.get_emulator_state().unwrap().fpu;
                let expected = embedder.get_emulator_state().unwrap().fpu;
                // FLDCW leaves C0/C1/C2/C3 architecturally undefined. Neither
                // that parity comparison nor a future silicon oracle may
                // require these condition codes to equal the helper's zeros.
                actual.status_word &= !0x4700;
                assert_eq!(
                    serde_json::to_value(actual).unwrap(),
                    serde_json::to_value(expected).unwrap()
                );
            }
        }
    }
}
