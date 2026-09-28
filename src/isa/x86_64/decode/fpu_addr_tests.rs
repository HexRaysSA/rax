//! x87 ModR/M address forms, distinguished by CS.L rather than address size.
//!
//! Intel SDM Vol. 2 §2.2.1.6, Table 2-7: mod=00/rm=101 is absolute disp32
//! in compatibility mode and RIP+disp32 in 64-bit mode. The SIB no-base form
//! remains absolute in both modes.

use super::*;
use crate::isa::x86_64::cpu::MAX_INSN_LEN;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const CODE: u64 = 0x1000;
const ABSOLUTE: u64 = 0x2000;

fn cpu(cs_l: bool, cs_db: bool, rip: u64) -> X86_64Vcpu {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
    let mut cpu = X86_64Vcpu::new(0, memory);
    cpu.sregs.cs.l = cs_l;
    cpu.sregs.cs.db = cs_db;
    cpu.regs.rip = rip;
    cpu
}

/// Decode the address of a complete D9 /5 (FLDCW) or /7 (FNSTCW) instruction.
/// The helper advances exactly as the x87 escape path does after consuming D9
/// and its ModR/M byte, then checks that the displacement was fully consumed.
fn x87_address(cpu: &X86_64Vcpu, instruction: &[u8]) -> u64 {
    let mut bytes = [0; MAX_INSN_LEN];
    bytes[..instruction.len()].copy_from_slice(instruction);
    let mut context = Decoder::decode_prefixes(bytes, instruction.len(), false, cpu.sregs.cs.l)
        .expect("decode x87 prefixes");
    let opcode = context.cursor;
    assert_eq!(instruction[opcode], 0xD9);
    let modrm = instruction[opcode + 1];
    assert!(matches!((modrm >> 3) & 7, 5 | 7));
    context.cursor += 2;
    let address = cpu
        .decode_fpu_modrm_addr(&mut context, modrm)
        .expect("decode x87 memory operand");
    assert_eq!(context.cursor, instruction.len());
    address
}

#[test]
fn compat32_fldcw_and_fnstcw_use_absolute_disp32() {
    let cpu = cpu(false, true, CODE);
    for modrm in [0x2D, 0x3D] {
        assert_eq!(
            x87_address(&cpu, &[0xD9, modrm, 0x00, 0x20, 0x00, 0x00]),
            ABSOLUTE,
            "D9 {modrm:02X}"
        );
    }
    assert_eq!(
        x87_address(&cpu, &[0xD9, 0x2D, 0xFC, 0xFF, 0xFF, 0xFF]),
        0xFFFF_FFFC,
        "negative disp32 is a 32-bit offset, not a 64-bit signed address"
    );
}

#[test]
fn compat16_address_override_selects_absolute_disp32() {
    let cpu = cpu(false, false, CODE);
    assert_eq!(
        x87_address(&cpu, &[0x67, 0xD9, 0x2D, 0x00, 0x20, 0x00, 0x00]),
        ABSOLUTE
    );
    assert_eq!(
        x87_address(&cpu, &[0x67, 0xD9, 0x3D, 0x00, 0x20, 0x00, 0x00]),
        ABSOLUTE
    );
    // The unprefixed 16-bit address form uses mod=00/rm=110 and disp16.
    assert_eq!(x87_address(&cpu, &[0xD9, 0x2E, 0x00, 0x20]), ABSOLUTE);
}

#[test]
fn long_mode_retains_rip_relative_addressing_with_or_without_67() {
    let low_cpu = cpu(true, false, CODE);
    assert_eq!(
        x87_address(&low_cpu, &[0xD9, 0x2D, 0x00, 0x20, 0x00, 0x00]),
        0x3006
    );
    let high_cpu = cpu(true, false, 0x1_0000_1000);
    assert_eq!(
        x87_address(&high_cpu, &[0xD9, 0x2D, 0x00, 0x20, 0x00, 0x00]),
        0x1_0000_3006
    );
    assert_eq!(
        x87_address(&high_cpu, &[0x67, 0xD9, 0x3D, 0x00, 0x20, 0x00, 0x00]),
        0x3007,
        "67h truncates EIP-relative offset to 32 bits; it does not make disp32 absolute"
    );
}

#[test]
fn sib_no_base_remains_absolute_in_both_modes() {
    let sib_absolute = [0xD9, 0x2C, 0x25, 0x00, 0x20, 0x00, 0x00];
    for cpu in [cpu(false, true, CODE), cpu(true, false, CODE)] {
        assert_eq!(x87_address(&cpu, &sib_absolute), ABSOLUTE);
    }
    assert_eq!(
        x87_address(
            &cpu(false, false, CODE),
            &[0x67, 0xD9, 0x2C, 0x25, 0x00, 0x20, 0x00, 0x00]
        ),
        ABSOLUTE
    );
}

#[test]
fn compat_disp32_uses_data_segment_or_explicit_override_after_offset() {
    let mut cpu = cpu(false, true, CODE);
    cpu.sregs.ds.base = 0x4000;
    cpu.sregs.fs.base = 0x8000;
    assert_eq!(
        x87_address(&cpu, &[0xD9, 0x2D, 0x00, 0x20, 0x00, 0x00]),
        0x6000
    );
    assert_eq!(
        x87_address(&cpu, &[0x64, 0xD9, 0x3D, 0x00, 0x20, 0x00, 0x00]),
        0xA000
    );
}

fn execution_cpu(code: &[u8], sparse: bool) -> (X86_64Vcpu, Arc<GuestMemoryMmap>) {
    let regions = if sparse {
        vec![(GuestAddress(CODE), 0x1000), (GuestAddress(0x3000), 0x1000)]
    } else {
        vec![(GuestAddress(0), 0x10000)]
    };
    let memory = Arc::new(GuestMemoryMmap::<()>::from_ranges(&regions).unwrap());
    memory.write_slice(code, GuestAddress(CODE)).unwrap();
    let mut cpu = X86_64Vcpu::new(0, memory.clone());
    cpu.sregs.cr0 = 0x21;
    cpu.sregs.efer = 1 << 10;
    cpu.sregs.cs.l = false;
    cpu.sregs.cs.db = true;
    cpu.regs.rip = CODE;
    (cpu, memory)
}

fn word(memory: &GuestMemoryMmap, address: u64) -> u16 {
    let mut bytes = [0; 2];
    memory
        .read_slice(&mut bytes, GuestAddress(address))
        .unwrap();
    u16::from_le_bytes(bytes)
}

#[test]
fn compat32_fldcw_load_and_fnstcw_store_touch_only_absolute_operands() {
    let (mut cpu, memory) = execution_cpu(
        &[
            0xD9, 0x2D, 0x00, 0x20, 0x00, 0x00, // FLDCW [0x2000]
            0xD9, 0x3D, 0x02, 0x20, 0x00, 0x00, // FNSTCW [0x2002]
        ],
        false,
    );
    memory
        .write_slice(&0x027Fu16.to_le_bytes(), GuestAddress(0x2000))
        .unwrap();
    memory
        .write_slice(&0x037Fu16.to_le_bytes(), GuestAddress(0x3006))
        .unwrap();
    memory
        .write_slice(&0xA5A5u16.to_le_bytes(), GuestAddress(0x300E))
        .unwrap();
    assert!(cpu.step().unwrap().is_none());
    assert_eq!(cpu.fpu.control_word, 0x027F);
    assert_eq!(cpu.regs.rip, CODE + 6);
    assert!(cpu.step().unwrap().is_none());
    assert_eq!(word(&memory, 0x2002), 0x027F);
    assert_eq!(word(&memory, 0x300E), 0xA5A5);
}

#[test]
fn compat32_absolute_operand_faults_even_if_rip_relative_decoy_is_mapped() {
    for modrm in [0x2D, 0x3D] {
        let (mut cpu, memory) = execution_cpu(&[0xD9, modrm, 0x00, 0x20, 0x00, 0x00], true);
        memory
            .write_slice(&0x037Fu16.to_le_bytes(), GuestAddress(0x3006))
            .unwrap();
        let initial_control = cpu.fpu.control_word;
        assert!(
            cpu.step().is_err(),
            "D9 {modrm:02X} accessed the mapped RIP-relative decoy"
        );
        assert_eq!(cpu.regs.rip, CODE, "faulting instruction retired");
        assert_eq!(cpu.fpu.control_word, initial_control);
        assert_eq!(word(&memory, 0x3006), 0x037F);
    }
}
