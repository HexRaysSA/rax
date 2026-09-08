//! Direct EVEX gather/scatter regressions using architectural page faults.
//!
//! Intel SDM 086 (December 2024), Vol. 2A Tables 2-38/2-63 and Vol. 2C
//! VGATHER/VPGATHER and VSCATTER/VPSCATTER descriptions and operations.
//! RAX selects ascending element completion and defers unused destination/mask
//! clearing until success, including the mixed-width cases where early clearing
//! is also permitted. These tests assert that deterministic implementation choice.

use crate::error::Error;
use crate::isa::x86_64::cpu::X86_64Vcpu;
use crate::vm::vcpu::MemAccess;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const CODE: u64 = 0x1000;
const DATA: u64 = 0x2000;
const FAULT: u64 = 0x3000;
const PML4: u64 = 0x8000;
const PDPT: u64 = 0x9000;
const PD: u64 = 0xA000;
const PT: u64 = 0xB000;
const DEST: u8 = 17;
const INDEX: u8 = 29;
const MASK: usize = 3;
const HIGH_MASK: u64 = (1 << 63) | (1 << 47);

#[derive(Clone, Copy, Debug)]
struct Shape {
    scatter: bool,
    floating: bool,
    index_bytes: usize,
    data_bytes: usize,
    ll: u8,
}

impl Shape {
    fn lanes(self) -> usize {
        // SDM opcode tables: DD/DPS has 4/8/16 elements; all other index/data
        // combinations have 2/4/8. In particular, QD/QPS uses half-width data.
        let lanes_128 = if self.index_bytes == 4 && self.data_bytes == 4 {
            4
        } else {
            2
        };
        lanes_128 << self.ll
    }

    fn data_mask(self) -> u64 {
        if self.data_bytes == 4 {
            u64::from(u32::MAX)
        } else {
            u64::MAX
        }
    }

    fn encoding(self, register: u8, index: u8) -> Vec<u8> {
        let mut p0 = 0xF2;
        p0 &= !(u8::from(register & 8 != 0) << 7);
        p0 &= !(u8::from(register & 16 != 0) << 4);
        p0 &= !(u8::from(index & 8 != 0) << 6);
        vec![
            0x62,
            p0,
            0x7D | (u8::from(self.data_bytes == 8) << 7),
            (self.ll << 5) | (u8::from(index & 16 == 0) << 3) | MASK as u8,
            if self.scatter { 0xA0 } else { 0x90 }
                | (u8::from(self.floating) << 1)
                | u8::from(self.index_bytes == 8),
            ((register & 7) << 3) | 4,
            (index & 7) << 3, // scale 1, RAX base, no displacement.
        ]
    }
}

fn shapes() -> Vec<Shape> {
    let mut result = Vec::new();
    for scatter in [false, true] {
        for floating in [false, true] {
            for index_bytes in [4, 8] {
                for data_bytes in [4, 8] {
                    for ll in 0..3 {
                        result.push(Shape {
                            scatter,
                            floating,
                            index_bytes,
                            data_bytes,
                            ll,
                        });
                    }
                }
            }
        }
    }
    assert_eq!(result.len(), 48);
    result
}

fn vector(vcpu: &X86_64Vcpu, register: u8) -> [u8; 64] {
    let words = if register >= 16 {
        vcpu.regs.zmm_ext[usize::from(register - 16)]
    } else {
        let register = usize::from(register);
        let mut words = [0; 8];
        words[..2].copy_from_slice(&vcpu.regs.xmm[register]);
        words[2..4].copy_from_slice(&vcpu.regs.ymm_high[register]);
        words[4..].copy_from_slice(&vcpu.regs.zmm_high[register]);
        words
    };
    std::array::from_fn(|byte| words[byte / 8].to_le_bytes()[byte % 8])
}

fn put_vector(vcpu: &mut X86_64Vcpu, register: u8, bytes: &[u8; 64]) {
    let words: [u64; 8] = std::array::from_fn(|word| {
        u64::from_le_bytes(bytes[word * 8..word * 8 + 8].try_into().unwrap())
    });
    if register >= 16 {
        vcpu.regs.zmm_ext[usize::from(register - 16)] = words;
    } else {
        let register = usize::from(register);
        vcpu.regs.xmm[register].copy_from_slice(&words[..2]);
        vcpu.regs.ymm_high[register].copy_from_slice(&words[2..4]);
        vcpu.regs.zmm_high[register].copy_from_slice(&words[4..]);
    }
}

fn put_lane(bytes: &mut [u8; 64], lane: usize, width: usize, value: u64) {
    bytes[lane * width..(lane + 1) * width].copy_from_slice(&value.to_le_bytes()[..width]);
}

fn lane(bytes: &[u8; 64], lane: usize, width: usize) -> u64 {
    let mut value = [0; 8];
    value[..width].copy_from_slice(&bytes[lane * width..(lane + 1) * width]);
    u64::from_le_bytes(value)
}

fn write_phys(memory: &GuestMemoryMmap, address: u64, value: u64, width: usize) {
    memory
        .write_slice(&value.to_le_bytes()[..width], GuestAddress(address))
        .unwrap();
}

fn read_phys(memory: &GuestMemoryMmap, address: u64, width: usize) -> u64 {
    let mut value = [0; 8];
    memory
        .read_slice(&mut value[..width], GuestAddress(address))
        .unwrap();
    u64::from_le_bytes(value)
}

fn cpu(code: &[u8], paging: bool) -> (X86_64Vcpu, Arc<GuestMemoryMmap>) {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
    memory.write_slice(code, GuestAddress(CODE)).unwrap();
    let mut vcpu = X86_64Vcpu::new(0, memory.clone());
    vcpu.sregs.efer = (1 << 8) | (1 << 10);
    vcpu.sregs.cs.l = true;
    vcpu.sregs.cs.db = false;
    vcpu.sregs.cs.selector = 0;
    vcpu.regs.rip = CODE;
    vcpu.regs.rax = DATA;
    vcpu.regs.rsp = 0x7000;
    vcpu.regs.rflags = 0x2 | 0x8D5;
    for register in 0..32 {
        let bytes =
            std::array::from_fn(|byte| (byte as u8).wrapping_mul(17).wrapping_add(register + 1));
        put_vector(&mut vcpu, register, &bytes);
    }
    vcpu.regs.k = std::array::from_fn(|index| 0x1234_5678_9ABC_DEF0 ^ index as u64);
    if paging {
        for (address, value) in [
            (PML4, PDPT | 7),
            (PDPT, PD | 7),
            (PD, PT | 7),
            (PT + (CODE >> 12) * 8, CODE | 7),
            (PT + (DATA >> 12) * 8, DATA | 7),
        ] {
            write_phys(&memory, address, value, 8);
        }
        vcpu.sregs.cr0 = 0x8005_0033;
        vcpu.sregs.cr3 = PML4;
        vcpu.sregs.cr4 = 1 << 5;
    }
    (vcpu, memory)
}

fn data_records(vcpu: &mut X86_64Vcpu) -> Vec<(MemAccess, u64, u8, u64)> {
    let mut records = Vec::new();
    vcpu.mmu.drain_mem_records(&mut records);
    records
        .into_iter()
        .filter(|record| record.access != MemAccess::Exec)
        .map(|record| (record.access, record.addr, record.size, record.value))
        .collect()
}

fn assert_pf(vcpu: &mut X86_64Vcpu, shape: Shape) {
    let result = vcpu.step();
    assert!(
        matches!(result, Err(Error::PageFault { vaddr: FAULT, error_code })
            if error_code == if shape.scatter { 2 } else { 0 }),
        "{shape:?}: expected nonpresent-page fault at {FAULT:#x}, got {result:?}"
    );
    assert_eq!(vcpu.regs.rip, CODE, "{shape:?}: faulting instruction PC");
}

#[test]
fn vsib_all_48_shapes_commit_each_completed_lane_and_resume_without_repeating_accesses() {
    for shape in shapes() {
        let code = shape.encoding(DEST, INDEX);
        let (mut vcpu, memory) = cpu(&code, true);
        let last = shape.lanes() - 1;
        let mut indices = [0; 64];
        for element in 0..shape.lanes() {
            // Every inactive lane names an unmapped page: it must be suppressed.
            put_lane(&mut indices, element, shape.index_bytes, 0x0040_0000);
        }
        put_lane(&mut indices, 0, shape.index_bytes, 0);
        put_lane(&mut indices, last, shape.index_bytes, FAULT - DATA);
        put_vector(&mut vcpu, INDEX, &indices);
        vcpu.regs.k[MASK] = HIGH_MASK | 1 | (1 << last);
        let before = vcpu.regs.clone();
        let mxcsr = vcpu.mxcsr;
        let original = vector(&vcpu, DEST);
        let first_value = 0x1122_3344_5566_7788 & shape.data_mask();
        let last_value = 0xFFE1_C3A5_8769_4B2D & shape.data_mask();
        write_phys(&memory, DATA, first_value, shape.data_bytes);
        write_phys(&memory, FAULT, last_value, shape.data_bytes);
        vcpu.mmu.set_mem_recording(true);

        assert_pf(&mut vcpu, shape);
        assert_eq!(vcpu.regs.k[MASK], HIGH_MASK | (1 << last), "{shape:?}");
        let mut expected = original;
        if !shape.scatter {
            put_lane(&mut expected, 0, shape.data_bytes, first_value);
        }
        assert_eq!(
            vector(&vcpu, DEST),
            expected,
            "{shape:?}: partial destination"
        );
        assert_eq!(
            vector(&vcpu, INDEX),
            indices,
            "{shape:?}: index preservation"
        );
        let first_access = if shape.scatter {
            (
                MemAccess::Write,
                DATA,
                shape.data_bytes as u8,
                lane(&original, 0, shape.data_bytes),
            )
        } else {
            (MemAccess::Read, DATA, shape.data_bytes as u8, first_value)
        };
        assert_eq!(data_records(&mut vcpu), vec![first_access], "{shape:?}");
        for other_mask in 0..8 {
            if other_mask != MASK {
                assert_eq!(vcpu.regs.k[other_mask], before.k[other_mask], "{shape:?}");
            }
        }
        assert_eq!(vcpu.regs.rax, before.rax, "{shape:?}");
        assert_eq!(vcpu.regs.rsp, before.rsp, "{shape:?}");
        assert_eq!(vcpu.regs.rflags, before.rflags, "{shape:?}");
        assert_eq!(vcpu.mxcsr, mxcsr, "{shape:?}");

        // Repair the missing PTE without changing the instruction or its index
        // vector. A completed scatter lane must not be stored again, even if the
        // handler changes that source lane. The portable recorder checks access
        // count independently of final RAM values (no native/JIT host gate).
        write_phys(&memory, PT + (FAULT >> 12) * 8, FAULT | 7, 8);
        vcpu.mmu.flush_tlb();
        if shape.scatter {
            put_lane(&mut expected, 0, shape.data_bytes, 0xA5A5_5A5A_F0F0_0F0F);
            put_vector(&mut vcpu, DEST, &expected);
        } else {
            write_phys(&memory, DATA, !first_value, shape.data_bytes);
        }
        assert!(vcpu.step().unwrap().is_none(), "{shape:?}");
        assert_eq!(vcpu.regs.rip, CODE + code.len() as u64, "{shape:?}");
        assert_eq!(
            vcpu.regs.k[MASK], 0,
            "{shape:?}: completion clears all 64 mask bits"
        );
        let last_access = if shape.scatter {
            assert_eq!(
                read_phys(&memory, DATA, shape.data_bytes),
                lane(&original, 0, shape.data_bytes),
                "{shape:?}: completed store repeated after restart"
            );
            assert_eq!(
                read_phys(&memory, FAULT, shape.data_bytes),
                lane(&original, last, shape.data_bytes),
                "{shape:?}: resumed store"
            );
            (
                MemAccess::Write,
                FAULT,
                shape.data_bytes as u8,
                lane(&original, last, shape.data_bytes),
            )
        } else {
            put_lane(&mut expected, last, shape.data_bytes, last_value);
            expected[shape.lanes() * shape.data_bytes..].fill(0);
            (MemAccess::Read, FAULT, shape.data_bytes as u8, last_value)
        };
        assert_eq!(
            vector(&vcpu, DEST),
            expected,
            "{shape:?}: resumed destination"
        );
        assert_eq!(data_records(&mut vcpu), vec![last_access], "{shape:?}");
    }
}

#[test]
fn vsib_first_active_lane_fault_preserves_entire_destination_and_high_mask() {
    for shape in shapes() {
        let code = shape.encoding(DEST, INDEX);
        let (mut vcpu, _) = cpu(&code, true);
        let mut indices = [0; 64];
        put_lane(&mut indices, 0, shape.index_bytes, FAULT - DATA);
        put_vector(&mut vcpu, INDEX, &indices);
        vcpu.regs.k[MASK] = HIGH_MASK | 1;
        let original = vector(&vcpu, DEST);
        vcpu.mmu.set_mem_recording(true);
        assert_pf(&mut vcpu, shape);
        assert_eq!(vcpu.regs.k[MASK], HIGH_MASK | 1, "{shape:?}");
        assert_eq!(vector(&vcpu, DEST), original, "{shape:?}");
        assert!(data_records(&mut vcpu).is_empty(), "{shape:?}");
    }
}

#[test]
fn vsib_zero_active_masks_suppress_faults_and_clear_only_completion_outputs() {
    for shape in shapes() {
        for mask in [0, u64::MAX << shape.lanes()] {
            let code = shape.encoding(DEST, INDEX);
            let (mut vcpu, _) = cpu(&code, true);
            vcpu.regs.rax = 0x0000_8000_0000_0000;
            vcpu.regs.k[MASK] = mask;
            let mut expected = vector(&vcpu, DEST);
            let index = vector(&vcpu, INDEX);
            vcpu.mmu.set_mem_recording(true);
            assert!(vcpu.step().unwrap().is_none(), "{shape:?}: mask={mask:#x}");
            if !shape.scatter {
                expected[shape.lanes() * shape.data_bytes..].fill(0);
            }
            assert_eq!(vector(&vcpu, DEST), expected, "{shape:?}");
            assert_eq!(vector(&vcpu, INDEX), index, "{shape:?}");
            assert_eq!(vcpu.regs.k[MASK], 0, "{shape:?}");
            assert_eq!(vcpu.regs.rip, CODE + code.len() as u64, "{shape:?}");
            assert!(data_records(&mut vcpu).is_empty(), "{shape:?}");
        }
    }
}

#[test]
fn vsib_full_masks_cover_all_lane_positions_and_data_widths() {
    for shape in shapes() {
        let code = shape.encoding(DEST, INDEX);
        let (mut vcpu, memory) = cpu(&code, false);
        let mut indices = [0; 64];
        let original = vector(&vcpu, DEST);
        let mut expected = original;
        for element in 0..shape.lanes() {
            put_lane(
                &mut indices,
                element,
                shape.index_bytes,
                (element * 16) as u64,
            );
            let value = 0xF0E1_D2C3_B4A5_9600 | element as u64;
            write_phys(
                &memory,
                DATA + (element * 16) as u64,
                value,
                shape.data_bytes,
            );
            if !shape.scatter {
                put_lane(&mut expected, element, shape.data_bytes, value);
            }
        }
        put_vector(&mut vcpu, INDEX, &indices);
        vcpu.regs.k[MASK] = u64::MAX;
        vcpu.mmu.set_mem_recording(true);
        assert!(vcpu.step().unwrap().is_none(), "{shape:?}");
        if !shape.scatter {
            expected[shape.lanes() * shape.data_bytes..].fill(0);
        }
        assert_eq!(vector(&vcpu, DEST), expected, "{shape:?}");
        assert_eq!(vcpu.regs.k[MASK], 0, "{shape:?}");
        let records = data_records(&mut vcpu);
        assert_eq!(records.len(), shape.lanes(), "{shape:?}");
        for (element, record) in records.into_iter().enumerate() {
            let value = if shape.scatter {
                lane(&original, element, shape.data_bytes)
            } else {
                (0xF0E1_D2C3_B4A5_9600 | element as u64) & shape.data_mask()
            };
            assert_eq!(
                record,
                (
                    if shape.scatter {
                        MemAccess::Write
                    } else {
                        MemAccess::Read
                    },
                    DATA + (element * 16) as u64,
                    shape.data_bytes as u8,
                    value,
                ),
                "{shape:?}: lane {element}"
            );
        }
    }
}

fn assert_ud(code: &[u8]) {
    let (mut vcpu, _) = cpu(code, false);
    vcpu.regs.rax = 0x0000_8000_0000_0000;
    vcpu.regs.k[MASK] = u64::MAX;
    let before = vcpu.regs.clone();
    let vectors: [[u8; 64]; 32] = std::array::from_fn(|reg| vector(&vcpu, reg as u8));
    let result = vcpu.step();
    assert!(
        matches!(&result, Err(Error::Emulator(message)) if message.contains("IDT entry 6 not present")),
        "{code:02X?}: expected #UD before memory access, got {result:?}"
    );
    assert_eq!(vcpu.regs.rip, CODE, "{code:02X?}");
    assert_eq!(vcpu.regs.k, before.k, "{code:02X?}");
    assert_eq!(vcpu.regs.rax, before.rax, "{code:02X?}");
    assert_eq!(vcpu.regs.rflags, before.rflags, "{code:02X?}");
    for register in 0..32 {
        assert_eq!(
            vector(&vcpu, register),
            vectors[usize::from(register)],
            "{code:02X?}"
        );
    }
}

#[test]
fn vsib_reserved_fields_raise_ud_before_memory_or_completion_changes() {
    for shape in shapes() {
        let valid = shape.encoding(DEST, INDEX);
        for encoded_vvvv in 0..15 {
            let mut code = valid.clone();
            code[2] = (code[2] & !0x78) | (encoded_vvvv << 3);
            assert_ud(&code);
        }
        for (byte, clear, set) in [
            (3, 0x60, 0x60), // L'L=11 is reserved.
            (3, 0x07, 0x00), // k0 is prohibited, including an empty mask.
            (3, 0x00, 0x80), // zeroing is prohibited.
            (3, 0x00, 0x10), // EVEX.b is prohibited.
            (5, 0x00, 0xC0), // ModR/M register form has no VSIB.
            (5, 0x07, 0x00), // Memory without a SIB is prohibited.
        ] {
            let mut code = valid.clone();
            code[byte] = (code[byte] & !clear) | set;
            assert_ud(&code);
        }
    }
}

#[test]
fn vsib_gather_rejects_destination_index_alias_even_for_an_empty_mask() {
    for shape in shapes().into_iter().filter(|shape| !shape.scatter) {
        for register in [0, 8, 16, 31] {
            let code = shape.encoding(register, register);
            assert_ud(&code);
            let (mut vcpu, _) = cpu(&code, false);
            vcpu.regs.k[MASK] = 0;
            let result = vcpu.step();
            assert!(
                matches!(&result, Err(Error::Emulator(message)) if message.contains("IDT entry 6 not present")),
                "{code:02X?}: alias with zero mask must #UD: {result:?}"
            );
            assert_eq!(vcpu.regs.rip, CODE, "{code:02X?}");
        }
    }
}

#[test]
fn vsib_scatter_all_24_shapes_allow_source_index_alias() {
    for shape in shapes().into_iter().filter(|shape| shape.scatter) {
        let code = shape.encoding(INDEX, INDEX);
        let (mut vcpu, memory) = cpu(&code, false);
        let mut source_and_indices = [0; 64];
        for element in 0..shape.lanes() {
            put_lane(
                &mut source_and_indices,
                element,
                shape.index_bytes,
                (element * 16) as u64,
            );
        }
        put_vector(&mut vcpu, INDEX, &source_and_indices);
        vcpu.regs.k[MASK] = u64::MAX;
        assert!(vcpu.step().unwrap().is_none(), "{shape:?}");
        for element in 0..shape.lanes() {
            assert_eq!(
                read_phys(&memory, DATA + (element * 16) as u64, shape.data_bytes),
                lane(&source_and_indices, element, shape.data_bytes),
                "{shape:?}: alias lane {element}"
            );
        }
        assert_eq!(vector(&vcpu, INDEX), source_and_indices, "{shape:?}");
        assert_eq!(vcpu.regs.k[MASK], 0, "{shape:?}");
    }
}

#[test]
fn vsib_scatter_partially_overlapping_elements_commit_in_lane_order() {
    for shape in shapes().into_iter().filter(|shape| shape.scatter) {
        let code = shape.encoding(DEST, INDEX);
        let (mut vcpu, memory) = cpu(&code, false);
        let original = vector(&vcpu, DEST);
        let mut indices = [0; 64];
        let overlap_offset = shape.data_bytes / 2;
        put_lane(&mut indices, 1, shape.index_bytes, overlap_offset as u64);
        put_vector(&mut vcpu, INDEX, &indices);
        vcpu.regs.k[MASK] = 3;
        assert!(vcpu.step().unwrap().is_none(), "{shape:?}");
        let mut expected = [0; 16];
        expected[..shape.data_bytes].copy_from_slice(&original[..shape.data_bytes]);
        expected[overlap_offset..overlap_offset + shape.data_bytes]
            .copy_from_slice(&original[shape.data_bytes..2 * shape.data_bytes]);
        let mut actual = [0; 16];
        memory.read_slice(&mut actual, GuestAddress(DATA)).unwrap();
        assert_eq!(actual, expected, "{shape:?}");
    }
}

#[test]
fn vsib_addr32_wraps_after_signed_index_scale_and_compressed_displacement_before_fs() {
    // Explicit 32-bit effective-address calculations (all outputs are bytes):
    // FFFFFFFC + 4 = 0 (mod 2^32);
    // FFFFFFF0 + (-4)*8 + disp8(16)*N = 0x10/0x50 for N=4/8;
    // 0x10 + (-4)*8 + disp8(-1)*N = FFFFFFEC/FFFFFFE8.
    for shape in shapes() {
        for (base, signed_index, scale_bits, disp8, fs_base, expected_address) in [
            (0xFFFF_FFFCu64, 4i64, 0u8, 0i8, DATA, DATA),
            (
                0xFFFF_FFF0,
                -4,
                3,
                16,
                DATA,
                DATA + if shape.data_bytes == 4 { 0x10 } else { 0x50 },
            ),
            (
                0x10,
                -4,
                3,
                -1,
                DATA.wrapping_sub(0x1_0000_0000),
                DATA - if shape.data_bytes == 4 { 0x14 } else { 0x18 },
            ),
        ] {
            let mut code = vec![0x67, 0x64];
            let mut instruction = shape.encoding(DEST, INDEX);
            instruction[5] |= 0x40;
            instruction[6] |= scale_bits << 6;
            instruction.push(disp8 as u8);
            code.extend(instruction);
            let (mut vcpu, memory) = cpu(&code, false);
            vcpu.regs.rax = 0x1234_5678_0000_0000 | base;
            vcpu.sregs.fs.base = fs_base;
            let mut indices = [0; 64];
            put_lane(&mut indices, 0, shape.index_bytes, signed_index as u64);
            put_vector(&mut vcpu, INDEX, &indices);
            vcpu.regs.k[MASK] = 1;
            let original = vector(&vcpu, DEST);
            let value = 0x1234_5678_90AB_CDEF & shape.data_mask();
            write_phys(&memory, expected_address, value, shape.data_bytes);
            vcpu.mmu.set_mem_recording(true);
            assert!(vcpu.step().unwrap().is_none(), "{shape:?}: {code:02X?}");
            let expected_value = if shape.scatter {
                lane(&original, 0, shape.data_bytes)
            } else {
                value
            };
            assert_eq!(
                data_records(&mut vcpu),
                vec![(
                    if shape.scatter {
                        MemAccess::Write
                    } else {
                        MemAccess::Read
                    },
                    expected_address,
                    shape.data_bytes as u8,
                    expected_value,
                )],
                "{shape:?}: base={base:#x}, index={signed_index}, disp8={disp8}"
            );
            assert_eq!(vcpu.regs.rip, CODE + code.len() as u64, "{shape:?}");
        }
    }
}

#[test]
fn vsib_no_base_disp32_ignores_evex_b_and_consumes_the_entire_displacement() {
    for shape in shapes() {
        for ignored_b in [false, true] {
            let mut code = shape.encoding(DEST, INDEX);
            code[6] |= 5; // mod=00 and SIB.base=101: disp32, no base register.
            if ignored_b {
                code[1] &= !0x20;
            }
            code.extend_from_slice(&(DATA as u32).to_le_bytes());
            let (mut vcpu, memory) = cpu(&code, false);
            vcpu.regs.rax = 0xDEAD_0000;
            vcpu.regs.r13 = 0xBEEF_0000;
            put_vector(&mut vcpu, INDEX, &[0; 64]);
            vcpu.regs.k[MASK] = 1;
            let original = vector(&vcpu, DEST);
            let value = 0x8976_5432_10FE_DCBA & shape.data_mask();
            write_phys(&memory, DATA, value, shape.data_bytes);
            vcpu.mmu.set_mem_recording(true);
            assert!(vcpu.step().unwrap().is_none(), "{shape:?}: {code:02X?}");
            assert_eq!(vcpu.regs.rip, CODE + code.len() as u64, "{shape:?}");
            assert_eq!(
                data_records(&mut vcpu),
                vec![(
                    if shape.scatter {
                        MemAccess::Write
                    } else {
                        MemAccess::Read
                    },
                    DATA,
                    shape.data_bytes as u8,
                    if shape.scatter {
                        lane(&original, 0, shape.data_bytes)
                    } else {
                        value
                    },
                )],
                "{shape:?}: ignored EVEX.B={ignored_b}"
            );
        }
    }
}

#[test]
fn vsib_32bit_mode_uses_default_ds_or_ss_and_rejects_16bit_addresses() {
    for shape in shapes() {
        for stack_base in [false, true] {
            let mut code = shape.encoding(1, 2);
            code[5] |= 0x40;
            code[6] |= if stack_base { 5 } else { 0 };
            code.push(0); // disp8=0 allows EBP to be an actual base register.
            let (mut vcpu, memory) = cpu(&code, false);
            vcpu.sregs.efer = 0;
            vcpu.sregs.cr0 = 0x11;
            vcpu.sregs.cs.l = false;
            vcpu.sregs.cs.db = true;
            vcpu.sregs.ds.base = 0x2000;
            vcpu.sregs.ss.base = 0x4000;
            vcpu.regs.rax = 0x40;
            vcpu.regs.rbp = 0x40;
            put_vector(&mut vcpu, 2, &[0; 64]);
            vcpu.regs.k[MASK] = 1;
            let original = vector(&vcpu, 1);
            let address = if stack_base { 0x4040 } else { 0x2040 };
            let value = 0x0123_4567_89AB_CDEF & shape.data_mask();
            write_phys(&memory, address, value, shape.data_bytes);
            vcpu.mmu.set_mem_recording(true);
            assert!(
                vcpu.step().unwrap().is_none(),
                "{shape:?}: EBP base={stack_base}"
            );
            assert_eq!(
                data_records(&mut vcpu),
                vec![(
                    if shape.scatter {
                        MemAccess::Write
                    } else {
                        MemAccess::Read
                    },
                    address,
                    shape.data_bytes as u8,
                    if shape.scatter {
                        lane(&original, 0, shape.data_bytes)
                    } else {
                        value
                    },
                )],
                "{shape:?}: EBP base={stack_base}"
            );

            // In protected 32-bit mode, 67 changes the effective address size
            // to 16 bits. Type E12 rejects that form before a memory access.
            code.insert(0, 0x67);
            let (mut invalid, _) = cpu(&code, false);
            invalid.sregs.efer = 0;
            invalid.sregs.cr0 = 0x11;
            invalid.sregs.cs.l = false;
            invalid.sregs.cs.db = true;
            invalid.regs.k[MASK] = 0;
            let result = invalid.step();
            assert!(
                matches!(&result, Err(Error::Emulator(message)) if message.contains("IDT entry 6 not present")),
                "{shape:?}: 16-bit address size must #UD: {result:?}"
            );
            assert_eq!(invalid.regs.rip, CODE, "{shape:?}");
        }
    }
}

#[test]
fn vsib_32bit_mode_ignores_r_prime_and_b_but_rejects_v_prime_zero() {
    // SDM 086 Vol. 2A Table 2-41: outside 64-bit mode, R' and B are ignored,
    // while V'=0 is #UD. Keep R=X=1: RX!=11 selects legacy BOUND instead.
    for shape in shapes() {
        for ignored_bits in [0, 0x10, 0x20, 0x30] {
            let mut code = shape.encoding(1, 2);
            code[1] &= !ignored_bits;
            let (mut vcpu, memory) = cpu(&code, false);
            vcpu.sregs.efer = 0;
            vcpu.sregs.cr0 = 0x11;
            vcpu.sregs.cs.l = false;
            vcpu.sregs.cs.db = true;
            vcpu.regs.r8 = 0xDEAD_0000;
            put_vector(&mut vcpu, 2, &[0; 64]);
            vcpu.regs.k[MASK] = 1;
            let mut expected = vector(&vcpu, 1);
            let high_register = vector(&vcpu, 17);
            let value = 0xCDEF_0123_4567_89AB & shape.data_mask();
            write_phys(&memory, DATA, value, shape.data_bytes);
            assert!(vcpu.step().unwrap().is_none(), "{shape:?}: {code:02X?}");
            if shape.scatter {
                assert_eq!(
                    read_phys(&memory, DATA, shape.data_bytes),
                    lane(&expected, 0, shape.data_bytes),
                    "{shape:?}: ignored R'/B={ignored_bits:#x}"
                );
            } else {
                put_lane(&mut expected, 0, shape.data_bytes, value);
                expected[shape.lanes() * shape.data_bytes..].fill(0);
            }
            assert_eq!(vector(&vcpu, 1), expected, "{shape:?}: {code:02X?}");
            assert_eq!(vector(&vcpu, 17), high_register, "{shape:?}: {code:02X?}");
            assert_eq!(vcpu.regs.k[MASK], 0, "{shape:?}");
            assert_eq!(vcpu.regs.rip, CODE + code.len() as u64, "{shape:?}");

            code[3] &= !0x08;
            let (mut invalid, _) = cpu(&code, false);
            invalid.sregs.efer = 0;
            invalid.sregs.cr0 = 0x11;
            invalid.sregs.cs.l = false;
            invalid.sregs.cs.db = true;
            invalid.regs.k[MASK] = 0;
            let original = vector(&invalid, 1);
            let result = invalid.step();
            assert!(
                matches!(&result, Err(Error::Emulator(message)) if message.contains("IDT entry 6 not present")),
                "{shape:?}: non-64-bit V'=0 must #UD: {result:?}"
            );
            assert_eq!(invalid.regs.rip, CODE, "{shape:?}");
            assert_eq!(vector(&invalid, 1), original, "{shape:?}");
            assert_eq!(invalid.regs.k[MASK], 0, "{shape:?}");
        }
    }
}

#[test]
fn vsib_apx_b4_selects_egpr_bases_without_changing_vector_index_or_mask_semantics() {
    // Intel APX 355828-007US §3.1.2.3.3/Table 3.3: BASE uses B4/B3;
    // VIDX uses V4/X3. The unused X4 encoding must not extend VIDX.
    for shape in shapes() {
        for base in [16u8, 21, 24, 29, 31] {
            for addr32 in [false, true] {
                for raw_x4 in [false, true] {
                    let mut code = shape.encoding(DEST, INDEX);
                    code[1] |= 0x08;
                    if base & 8 != 0 {
                        code[1] &= !0x20;
                    }
                    if raw_x4 {
                        code[2] &= !0x04;
                    }
                    code[3] = (code[3] & !7) | 7; // K7, not APX NF semantics.
                    code[5] |= 0x40;
                    code[6] |= base & 7;
                    code.push(0); // Keep R21/R29 as actual bases rather than disp32.
                    if addr32 {
                        code.insert(0, 0x67);
                    }
                    let (mut vcpu, memory) = cpu(&code, false);
                    vcpu.set_apx_enabled(true);
                    vcpu.set_reg(base & 15, 0xDEAD_0000, 8);
                    vcpu.set_reg(
                        base,
                        DATA | if addr32 { 0x1234_5678_0000_0000 } else { 0 },
                        8,
                    );
                    put_vector(&mut vcpu, INDEX, &[0; 64]);
                    vcpu.regs.k[7] = HIGH_MASK | 1;
                    let k3 = vcpu.regs.k[3];
                    let flags = vcpu.regs.rflags;
                    let mut expected = vector(&vcpu, DEST);
                    let value = 0x0123_4567_89AB_CDEF & shape.data_mask();
                    write_phys(&memory, DATA, value, shape.data_bytes);
                    vcpu.mmu.set_mem_recording(true);
                    assert!(vcpu.step().unwrap().is_none(), "{shape:?}: {code:02X?}");
                    let expected_value = if shape.scatter {
                        lane(&expected, 0, shape.data_bytes)
                    } else {
                        value
                    };
                    if !shape.scatter {
                        put_lane(&mut expected, 0, shape.data_bytes, value);
                        expected[shape.lanes() * shape.data_bytes..].fill(0);
                    }
                    assert_eq!(vector(&vcpu, DEST), expected, "{shape:?}: {code:02X?}");
                    assert_eq!(vcpu.regs.k[7], 0, "{shape:?}: {code:02X?}");
                    assert_eq!(vcpu.regs.k[3], k3, "{shape:?}: wrong opmask");
                    assert_eq!(vcpu.regs.rflags, flags, "{shape:?}");
                    assert_eq!(
                        data_records(&mut vcpu),
                        vec![(
                            if shape.scatter {
                                MemAccess::Write
                            } else {
                                MemAccess::Read
                            },
                            DATA,
                            shape.data_bytes as u8,
                            expected_value
                        )],
                        "{shape:?}: {code:02X?}"
                    );
                }
            }
        }
    }
}

#[test]
fn vsib_apx_actual_egpr_base_requires_apx_and_64bit_mode_even_when_mask_is_zero() {
    for shape in shapes() {
        // Low vector registers keep RX=11, making non-64-bit payloads EVEX.
        let mut code = shape.encoding(1, 2);
        code[1] |= 0x08; // R16 base.
        for (long_mode, apx, mask) in [(true, false, 0), (true, false, u64::MAX), (false, true, 0)]
        {
            let (mut vcpu, _) = cpu(&code, false);
            vcpu.set_apx_enabled(apx);
            if !long_mode {
                vcpu.sregs.efer = 0;
                vcpu.sregs.cr0 = 0x11;
                vcpu.sregs.cs.l = false;
                vcpu.sregs.cs.db = true;
            }
            vcpu.regs.k[MASK] = mask;
            let original = vector(&vcpu, 1);
            let result = vcpu.step();
            assert!(
                matches!(&result, Err(Error::Emulator(message)) if message.contains("IDT entry 6 not present")),
                "{shape:?}: APX={apx}, long_mode={long_mode}: {result:?}"
            );
            assert_eq!(vcpu.regs.rip, CODE);
            assert_eq!(vcpu.regs.k[MASK], mask);
            assert_eq!(vector(&vcpu, 1), original);
        }
    }
}

#[test]
fn vsib_unused_b4_and_x4_do_not_require_apx_or_modify_vector_indices() {
    for shape in shapes() {
        for no_base in [false, true] {
            for raw_x4 in [false, true] {
                let mut code = shape.encoding(DEST, INDEX);
                if raw_x4 {
                    code[2] &= !0x04;
                }
                if no_base {
                    code[1] |= 0x08; // B4 ignored when no base is present.
                    code[1] &= !0x20; // B3 likewise ignored.
                    code[6] |= 5;
                    code.extend_from_slice(&(DATA as u32).to_le_bytes());
                }
                let (mut vcpu, memory) = cpu(&code, false);
                vcpu.set_apx_enabled(false);
                vcpu.regs.r29 = 0xDEAD_0000;
                put_vector(&mut vcpu, INDEX, &[0; 64]);
                vcpu.regs.k[MASK] = 1;
                let mut expected = vector(&vcpu, DEST);
                let value = 0xFEDC_BA98_7654_3210 & shape.data_mask();
                write_phys(&memory, DATA, value, shape.data_bytes);
                assert!(vcpu.step().unwrap().is_none(), "{shape:?}: {code:02X?}");
                if shape.scatter {
                    assert_eq!(
                        read_phys(&memory, DATA, shape.data_bytes),
                        lane(&expected, 0, shape.data_bytes)
                    );
                } else {
                    put_lane(&mut expected, 0, shape.data_bytes, value);
                    expected[shape.lanes() * shape.data_bytes..].fill(0);
                }
                assert_eq!(vector(&vcpu, DEST), expected, "{shape:?}: {code:02X?}");
                assert_eq!(vcpu.regs.k[MASK], 0, "{shape:?}");
                assert_eq!(vcpu.regs.rip, CODE + code.len() as u64, "{shape:?}");
            }
        }
    }
}
