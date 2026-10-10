//! MemoryWorkingSetExInformation: guest state, never a host kernel query.
use super::{compatibility_length, process_status};
use crate::error::MemoryAccessKind;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::{MemFault, prot};
use crate::user::windows::nt::status::{STATUS_NO_MEMORY, STATUS_SUCCESS};

pub(super) fn query(
    c: &mut Ctx,
    process: u64,
    output: u64,
    length: u64,
    returned: u64,
) -> ApiResult {
    let wow = c.arch() == WinArch::X86;
    let width = c.psize();
    let count = length / (width * 2);
    let prefix = count * width * 2;
    if wow {
        // WoW64 allocates a native 16-byte record for each 8-byte guest one
        // before reading input. Model that conversion against guest backing
        // capacity, without allocating guest-controlled scratch on the host.
        // Its exact host-kernel exhaustion threshold is deliberately not used.
        if count
            .checked_mul(16)
            .is_none_or(|bytes| bytes > c.p.vm.commit_limit())
        {
            return Flow::ret(STATUS_NO_MEMORY.into());
        }
        // Capture precedes the kernel's process-handle check; read-only input
        // with an invalid handle differs from the native output-first probe.
        probe(c, output, prefix, MemoryAccessKind::Read)?;
    }
    let status = process_status(c, process)?;
    if status != STATUS_SUCCESS {
        // Class4 WoW64 leaves ReturnLength unchanged on kernel failure, unlike
        // the class0/6 fixed-record conversion.
        return Flow::ret(status.into());
    }
    if wow {
        probe(c, output, prefix, MemoryAccessKind::Write)?;
    }
    // All addresses reside in the checked input extent. No scheduler yield or
    // callback occurs here, and writing flags cannot overwrite a later address.
    // Therefore conversion is O(1) auxiliary space rather than an unbounded Vec.
    for index in 0..count {
        let at = output + index * width * 2;
        let address = c.read_ptr(at)?;
        c.write_ptr(at + width, attributes(c, address))?;
    }
    if wow {
        compatibility_length(c, returned, Some(prefix as u32));
    } else if returned != 0 {
        c.write_ptr(returned, length)?;
    }
    Flow::ret(STATUS_SUCCESS.into())
}

fn probe(c: &Ctx, address: u64, bytes: u64, access: MemoryAccessKind) -> Result<(), MemFault> {
    let write = access == MemoryAccessKind::Write;
    let bytes = usize::try_from(bytes).map_err(|_| MemFault {
        addr: address,
        write,
    })?;
    c.mem()
        .probe(address, bytes, access)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write,
        })
}

fn attributes(c: &Ctx, address: u64) -> u64 {
    // This lookup does not translate/read the target, allocate a frame, consume
    // its guard, or touch the host process. Untouched committed pages are absent
    // from the guest working set even though their virtual commitment exists.
    if !c.p.space.is_resident(address) {
        return 0;
    }
    let Some(allocation) = c.p.vm.allocation(address) else {
        return 0;
    };
    let page = (address - allocation.base) / PAGE_SIZE;
    let Some((_, state)) = allocation.pages.range(..=page).next_back() else {
        return 0;
    };
    if !state.committed {
        return 0;
    }
    // Normal priority5; current Windows owners use private anonymous frames,
    // one node, base pages, no page locks/graphics/standby list/paging file.
    // Image/NLS classification alone does not prove physical frame sharing.
    const PRIORITY_NORMAL: u64 = 5 << 24;
    if state.protect & (prot::GUARD | prot::NOACCESS) != 0 {
        // Invalid.Location=MemoryLocationResident; protection fields belong to
        // the Valid union and must not be exposed in this branch.
        return PRIORITY_NORMAL | (1 << 22);
    }
    let protect = state.reported.unwrap_or(state.protect);
    PRIORITY_NORMAL | 1 | (u64::from(protect & 0x7FF) << 4)
}
