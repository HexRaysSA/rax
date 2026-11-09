//! Recover argument slots hidden by a recognized ARM64EC syscall guard frame.
//! The actual SP and native guard cookie remain owned by the executing stub.

use super::{Proc, Thread};
use crate::user::windows::arch::WinArch;
use crate::user::windows::memory::Mem;

const SUB_SP_16: u32 = 0xd100_43ff;
const WORDS: usize = 13;
const BYTES: usize = WORDS * 4;

pub(super) fn entry_sp(p: &Proc, t: &Thread, number: u32, pc: u64, sp: u64) -> Result<u64, String> {
    if p.arch != WinArch::X64 || !t.cpu.is_arm64ec() || t.cpu.instruction_arch() != WinArch::Arm64 {
        return Ok(sp);
    }
    let Some((index, _)) = &p.modules.nt_services else {
        return Ok(sp);
    };
    let Some(module) = p.modules.list.get(*index) else {
        return Ok(sp);
    };
    scoped_entry_sp(&p.space, module.base, module.size, number, pc, sp)
}

fn scoped_entry_sp(
    memory: &impl Mem,
    base: u64,
    size: u64,
    number: u32,
    pc: u64,
    sp: u64,
) -> Result<u64, String> {
    let Some(end) = base.checked_add(size) else {
        return Err("native NTDLL image extent overflows".into());
    };
    let Some(start) = pc
        .checked_sub(16)
        .filter(|&start| start >= base && pc < end)
    else {
        return Ok(sp);
    };
    let first = memory
        .u32(start)
        .map_err(|fault| format!("native NTDLL stub prefix is unreadable: {fault:?}"))?;
    if first != SUB_SP_16 {
        return Ok(sp);
    }
    if !start
        .checked_add(BYTES as u64)
        .is_some_and(|limit| limit <= end)
    {
        return Err("guarded NTDLL stub extends outside the selected image".into());
    }
    let mut bytes = [0; BYTES];
    memory
        .rd(start, &mut bytes)
        .map_err(|fault| format!("guarded NTDLL stub is unreadable: {fault:?}"))?;
    let cookie = guard_cookie(&bytes, start, number)
        .filter(|&address| address >= base && address < end)
        .ok_or_else(|| "unrecognized guarded ARM64EC NTDLL syscall wrapper".to_owned())?;
    let _ = cookie; // The native postlude checks its cookie; no guest write here.
    sp.checked_add(16)
        .ok_or_else(|| "guarded ARM64EC argument stack overflows".into())
}

fn guard_cookie(bytes: &[u8; BYTES], start: u64, number: u32) -> Option<u64> {
    let mut words = [0; WORDS];
    for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().ok()?);
    }
    if words[0] != SUB_SP_16
        || words[3] != 0xf900_03f0 // STR X16,[SP]
        || words[4] & 0xffe0_001f != 0xd400_0001
        || (words[4] >> 5) & 0xffff != number
        || words[5] != 0xf940_03e9 // LDR X9,[SP]
        || words[8] != 0xeb09_0210 // SUBS X16,X16,X9
        || words[9] != 0x9100_43ff // ADD SP,SP,#16
        || words[10] & 0xff00_001f != 0x5400_0001 // B.NE
        || words[11] != 0xd280_0009 // MOV X9,#0
        || words[12] != 0xd65f_03c0
    // RET
    {
        return None;
    }
    let saved = adrp_add(words[1], words[2], start.checked_add(4)?)?;
    let checked = adrp_add(words[6], words[7], start.checked_add(24)?)?;
    (saved == checked).then_some(saved)
}

fn adrp_add(adrp: u32, add: u32, pc: u64) -> Option<u64> {
    if adrp & 0x9f00_001f != 0x9000_0010 || add & 0xff80_03ff != 0x9100_0210 {
        return None;
    }
    let encoded = ((adrp >> 5) & 0x7ffff) << 2 | ((adrp >> 29) & 3);
    let signed = ((encoded as i32) << 11) >> 11;
    let page = i128::from(pc & !0xfff) + (i128::from(signed) << 12);
    let immediate = i128::from((add >> 10) & 0xfff) << if add & (1 << 22) != 0 { 12 } else { 0 };
    u64::try_from(page + immediate).ok()
}

#[cfg(test)]
mod tests;
