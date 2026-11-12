use super::*;
use crate::error::MemoryAccessKind;
use crate::user::windows::memory::MemFault;

pub(super) struct State {
    address: u64,
    length: usize,
    mask: u64,
}

pub(super) fn capture(
    c: &Ctx,
    address: u64,
    arch: WinArch,
    flags: u32,
) -> Result<Result<Option<State>, u32>, ApiErr> {
    if arch == WinArch::Arm64 {
        return Ok(if flags & 0x00ff_0020 == 0x0040_0020 {
            Err(STATUS_NOT_SUPPORTED)
        } else {
            Ok(None)
        });
    }
    if flags & 0x40 == 0 || (arch == WinArch::X64 && flags & 0x0010_0000 == 0) {
        return Ok(Ok(None));
    }
    let Some(base) = address.checked_add(RegContext::size(arch) as u64) else {
        return Ok(Err(STATUS_ACCESS_VIOLATION));
    };
    let header = c.mem().bytes(base, 24)?;
    let offset = i32::from_le_bytes(header[16..20].try_into().unwrap());
    let length = u32::from_le_bytes(header[20..24].try_into().unwrap()) as usize;
    let all_offset = i32::from_le_bytes(header[..4].try_into().unwrap());
    let all_length = u32::from_le_bytes(header[4..8].try_into().unwrap());
    let all_end = i64::from(all_offset) + i64::from(all_length);
    let contained = offset >= all_offset && i64::from(offset) + length as i64 <= all_end;
    if arch == WinArch::X86 {
        if offset < 24 {
            return Ok(Err(STATUS_INVALID_PARAMETER));
        }
        if length < 64 {
            return Ok(Err(STATUS_BUFFER_OVERFLOW));
        }
        if !contained {
            return Ok(Err(STATUS_INVALID_PARAMETER));
        }
    } else if length > 320 || !contained {
        return Ok(Err(STATUS_ACCESS_VIOLATION));
    }
    let Some(start) = base.checked_add_signed(i64::from(offset)) else {
        return Ok(Err(STATUS_ACCESS_VIOLATION));
    };
    if arch == WinArch::X86 && start % 64 != 0 {
        return Ok(Err(STATUS_DATATYPE_MISALIGNMENT));
    }
    let length = if arch == WinArch::X64 { 320 } else { length };
    c.mem()
        .probe(start, length, MemoryAccessKind::Read)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: false,
        })?;
    let mask = c.mem().u64(start)?;
    if arch == WinArch::X86 && mask & !7 != 0 {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    Ok(Ok(Some(State {
        address: start,
        length,
        mask,
    })))
}

impl State {
    pub(super) fn get(&self, c: &Ctx, cpu: &WinCpu, arch: WinArch) -> Result<(), ApiErr> {
        probe_write(c, self.address, self.length)?;
        let high = cpu
            .kernel_ymm_high()
            .map_err(|status| c.unsupported(format!("YMM context status {status:#x}")))?;
        let count = if arch == WinArch::X86 { 8 } else { 16 };
        let present = arch != WinArch::X86
            || self.mask & 4 != 0 && high[..count].iter().any(|pair| *pair != [0; 2]);
        if present {
            for (n, value) in high.into_iter().take(count).enumerate() {
                c.mem().w64(self.address + 64 + n as u64 * 16, value[0])?;
                c.mem().w64(self.address + 72 + n as u64 * 16, value[1])?;
            }
        }
        c.mem().w64(
            self.address,
            if arch == WinArch::X86 {
                if present { 4 } else { 0 }
            } else {
                self.mask | 4
            },
        )?;
        Ok(())
    }

    pub(super) fn input(&self, c: &Ctx, arch: WinArch) -> Result<Option<[[u64; 2]; 16]>, ApiErr> {
        if self.mask & 4 == 0 {
            return Ok(None);
        }
        let count = if arch == WinArch::X86 { 8 } else { 16 };
        let bytes = c.mem().bytes(self.address + 64, count * 16)?;
        let mut values = [[0; 2]; 16];
        for (n, pair) in values.iter_mut().take(count).enumerate() {
            pair[0] = u64::from_le_bytes(bytes[n * 16..n * 16 + 8].try_into().unwrap());
            pair[1] = u64::from_le_bytes(bytes[n * 16 + 8..n * 16 + 16].try_into().unwrap());
        }
        Ok(Some(values))
    }
}
