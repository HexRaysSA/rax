//! MemoryBasicInformationCapped input contract measured on Windows 29704.
use super::*;

pub(super) enum Input {
    End(u64),
    InvalidInput,
    InvalidRange,
}

/// Return the exclusive, page-aligned scan bound. Native callers supply an
/// otherwise zero MEMORY_BASIC_INFORMATION; WoW64 extracts only RegionSize.
/// Time and scratch space are constant, independent of the caller's cap.
pub(super) fn read_end(c: &Ctx, address: u64, output: u64) -> Result<Input, ApiErr> {
    let width = c.psize();
    let cap = if width == 4 {
        u64::from(c.mem().u32(output.checked_add(12).ok_or_else(|| {
            crate::user::windows::memory::MemFault {
                addr: output,
                write: false,
            }
        })?)?)
    } else {
        let bytes = c.mem().bytes(output, 48)?;
        if bytes[..24]
            .iter()
            .chain(bytes[32..].iter())
            .any(|&byte| byte != 0)
        {
            return Ok(Input::InvalidInput);
        }
        u64::from_le_bytes(bytes[24..32].try_into().unwrap())
    };
    if cap == 0 {
        return Ok(Input::InvalidInput);
    }
    // A non-LAA x86 image's allocation ceiling does not narrow the kernel's
    // cap validation. The native WoW64 oracle accepts a span to 0xffff0000.
    let high = crate::user::windows::layout::user_limit(c.arch(), true);
    Ok(address
        .checked_add(cap)
        .filter(|&end| end <= high)
        .and_then(|end| end.checked_add(crate::user::mm::PAGE_SIZE - 1))
        .map(|end| Input::End(end & !(crate::user::mm::PAGE_SIZE - 1)))
        .unwrap_or(Input::InvalidRange))
}

pub(super) fn information(c: &Ctx, address: u64, end: u64) -> RegionInfo {
    if address >= c.p.vm.high() {
        // The 64-bit kernel reserves the non-LAA WoW64 allocation fence.
        // It is query metadata, never a mapping or permission to access bytes.
        debug_assert_eq!(c.arch(), WinArch::X86);
        debug_assert_eq!(
            c.p.vm.high(),
            crate::user::windows::layout::user_limit(WinArch::X86, false)
        );
        let base = address & !(crate::user::mm::PAGE_SIZE - 1);
        return RegionInfo {
            base,
            allocation_base: c.p.vm.high(),
            allocation_protect: crate::user::windows::memory::prot::READONLY,
            size: end - base,
            state: crate::user::windows::memory::mem::RESERVE,
            protect: 0,
            kind: crate::user::windows::memory::mem::PRIVATE,
        };
    }
    c.p.vm
        .query_capped(address, end)
        .expect("validated guest capped range")
}
