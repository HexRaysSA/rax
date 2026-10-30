//! GDB's mandatory amd64 core bank: integer registers and exact x87 state.
use super::protocol::{decode_hex, encode_hex};
use super::registers::{REGISTER_DATA_SIZE, pack_registers, unpack_registers};
use crate::error::{Error, Result};
use crate::vm::snapshot::FpuSnapshot;
use crate::vm::vcpu::VCpu;
const FULL_SIZE: usize = REGISTER_DATA_SIZE + 8 * 10 + 8 * 4;

pub(super) fn location(index: usize) -> Option<(usize, usize)> {
    match index {
        0..=16 => Some((index * 8, 8)),
        17..=23 => Some((17 * 8 + (index - 17) * 4, 4)),
        24..=31 => Some((REGISTER_DATA_SIZE + (index - 24) * 10, 10)),
        32..=39 => Some((REGISTER_DATA_SIZE + 80 + (index - 32) * 4, 4)),
        _ => None,
    }
}
pub(crate) fn read(cpu: &dyn VCpu) -> Result<Option<String>> {
    let crate::vm::vcpu::CpuState::X86_64(state) = cpu.get_state()? else {
        return Ok(None);
    };
    let mut raw = pack_registers(&state);
    if let Some(emulator) = cpu.get_emulator_state() {
        let fpu = emulator.fpu;
        for index in 0..8 {
            raw.push_str(&encode_hex(&fpu.st[(usize::from(fpu.top) + index) & 7]));
        }
        let status = (fpu.status_word & !0x3800) | (u16::from(fpu.top) << 11);
        for value in [
            u32::from(fpu.control_word),
            u32::from(status),
            u32::from(fpu.tag_word),
            (fpu.instr_ptr >> 32) as u32,
            fpu.instr_ptr as u32,
            (fpu.data_ptr >> 32) as u32,
            fpu.data_ptr as u32,
            u32::from(fpu.last_opcode),
        ] {
            raw.push_str(&encode_hex(&value.to_le_bytes()));
        }
    } else {
        // Hardware banks without an export contract are explicitly unavailable,
        // never fabricated zero-valued registers.
        raw.push_str(&"x".repeat((FULL_SIZE - REGISTER_DATA_SIZE) * 2));
    }
    Ok(Some(raw))
}
fn fpu_from_bytes(raw: &[u8]) -> Option<FpuSnapshot> {
    if raw.len() != 112 {
        return None;
    }
    let words: Vec<_> = raw[80..]
        .chunks_exact(4)
        .map(|v| u32::from_le_bytes(v.try_into().unwrap()))
        .collect();
    if [0, 1, 2, 7]
        .into_iter()
        .any(|i| words[i] > u32::from(u16::MAX))
    {
        return None;
    }
    let mut fpu = FpuSnapshot {
        control_word: words[0] as u16,
        status_word: words[1] as u16,
        tag_word: words[2] as u16,
        instr_ptr: (u64::from(words[3]) << 32) | u64::from(words[4]),
        data_ptr: (u64::from(words[5]) << 32) | u64::from(words[6]),
        last_opcode: words[7] as u16,
        top: ((words[1] >> 11) & 7) as u8,
        ..Default::default()
    };
    for index in 0..8 {
        fpu.st[(usize::from(fpu.top) + index) & 7]
            .copy_from_slice(&raw[index * 10..index * 10 + 10]);
    }
    Some(fpu)
}
pub(crate) fn write(cpu: &mut dyn VCpu, raw: &[u8]) -> Result<bool> {
    if ![REGISTER_DATA_SIZE, FULL_SIZE].contains(&raw.len()) {
        return Ok(false);
    }
    let crate::vm::vcpu::CpuState::X86_64(mut state) = cpu.get_state()? else {
        return Ok(false);
    };
    let fpu = if raw.len() == FULL_SIZE {
        if cpu.get_emulator_state().is_none() {
            return Ok(false);
        }
        let Some(fpu) = fpu_from_bytes(&raw[REGISTER_DATA_SIZE..]) else {
            return Ok(false);
        };
        Some(fpu)
    } else {
        None
    };
    if !unpack_registers(&encode_hex(&raw[..REGISTER_DATA_SIZE]), &mut state) {
        return Ok(false);
    }
    cpu.update_state(&crate::vm::vcpu::CpuState::X86_64(state))?;
    if let Some(fpu) = fpu {
        // Read after the integer update so a new RFLAGS value cannot be replaced
        // by the prior lazy-flag image when installing only the new x87 bank.
        let Some(mut emulator) = cpu.get_emulator_state() else {
            return Err(Error::Emulator(
                "x87 export disappeared after an integer update".into(),
            ));
        };
        emulator.fpu = fpu;
        cpu.set_emulator_state(&emulator)?;
    }
    Ok(true)
}
fn patch_fpu(fpu: &mut FpuSnapshot, index: usize, value: &[u8]) -> bool {
    if (24..=31).contains(&index) {
        if value.len() != 10 {
            return false;
        }
        fpu.st[(usize::from(fpu.top) + index - 24) & 7].copy_from_slice(value);
        return true;
    }
    let Ok(raw) = <&[u8; 4]>::try_from(value) else {
        return false;
    };
    let value = u32::from_le_bytes(*raw);
    if matches!(index, 32 | 33 | 34 | 39) && value > u32::from(u16::MAX) {
        return false;
    }
    match index {
        32 => fpu.control_word = value as u16,
        33 => {
            fpu.status_word = value as u16;
            fpu.top = ((value >> 11) & 7) as u8;
        }
        34 => fpu.tag_word = value as u16,
        35 => fpu.instr_ptr = (u64::from(value) << 32) | (fpu.instr_ptr & 0xffff_ffff),
        36 => fpu.instr_ptr = (fpu.instr_ptr & 0xffff_ffff_0000_0000) | u64::from(value),
        37 => fpu.data_ptr = (u64::from(value) << 32) | (fpu.data_ptr & 0xffff_ffff),
        38 => fpu.data_ptr = (fpu.data_ptr & 0xffff_ffff_0000_0000) | u64::from(value),
        39 => fpu.last_opcode = value as u16,
        _ => return false,
    }
    true
}
pub(crate) fn write_one(cpu: &mut dyn VCpu, index: usize, value: &[u8]) -> Result<bool> {
    let Some((offset, width)) = location(index) else {
        return Ok(false);
    };
    if value.len() != width {
        return Ok(false);
    }
    if index >= 24 {
        let Some(mut emulator) = cpu.get_emulator_state() else {
            return Ok(false);
        };
        if !patch_fpu(&mut emulator.fpu, index, value) {
            return Ok(false);
        }
        cpu.set_emulator_state(&emulator)?;
        return Ok(true);
    }
    let crate::vm::vcpu::CpuState::X86_64(state) = cpu.get_state()? else {
        return Ok(false);
    };
    let mut bytes =
        decode_hex(&pack_registers(&state)).expect("packed integer registers are hexadecimal");
    bytes[offset..offset + width].copy_from_slice(value);
    write(cpu, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn status_top_write_preserves_physical_payloads_and_single_st_write_selects_top() {
        let mut fpu = FpuSnapshot::default();
        for i in 0..8 {
            fpu.st[i] = [i as u8; 10];
        }
        let physical = fpu.st;
        assert!(patch_fpu(&mut fpu, 33, &0x3800u32.to_le_bytes()));
        assert_eq!(fpu.top, 7);
        assert_eq!(fpu.st, physical);
        assert!(patch_fpu(&mut fpu, 24, &[0xa5; 10]));
        assert_eq!(fpu.st[7], [0xa5; 10]);
        for i in 0..7 {
            assert_eq!(fpu.st[i], physical[i]);
        }
    }
    #[test]
    fn x87_decode_preserves_top_full_pointers_and_exact_physical_payloads() {
        let mut bytes = vec![0; 112];
        for i in 0..80 {
            bytes[i] = i as u8;
        }
        let words = [
            0x37f, 0x3800, 0xfffd, 0x12345678, 0x9abcdef0, 0xabcdefff, 0x12345678, 0x321,
        ];
        for (i, v) in words.iter().enumerate() {
            bytes[80 + i * 4..84 + i * 4].copy_from_slice(&u32::to_le_bytes(*v));
        }
        let f = fpu_from_bytes(&bytes).unwrap();
        assert_eq!(f.top, 7);
        assert_eq!(f.instr_ptr, 0x123456789abcdef0);
        assert_eq!(f.data_ptr, 0xabcdefff12345678);
        for i in 0..8 {
            assert_eq!(f.st[(7 + i) & 7], bytes[i * 10..i * 10 + 10]);
        }
        bytes[83] = 1;
        assert!(fpu_from_bytes(&bytes).is_none());
        for n in 0..112 {
            assert!(fpu_from_bytes(&bytes[..n]).is_none());
        }
    }
}
