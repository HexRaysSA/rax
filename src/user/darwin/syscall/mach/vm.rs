//! Mach VM traps: `mach_vm_allocate`, `mach_vm_deallocate`,
//! `mach_vm_protect`, and `mach_vm_map` on the calling task's own map
//! (`osfmk/ipc/mach_kernelrpc.c`, `osfmk/vm/vm_user.c`,
//! `osfmk/vm/vm_kern.c`).
//!
//! Addresses and sizes are rounded to the map's page size as the VM
//! sanitizers do: the start truncated, the end rounded up. New memory is
//! zero-filled with current protection read/write (or the caller's for
//! `mach_vm_map`) and maximum protection `VM_PROT_ALL`.

use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::vm::{self, VmFlags};
use crate::user::mm::{Mapping, MmError};

/// `VM_FLAGS_ANYWHERE`.
pub const VM_FLAGS_ANYWHERE: u32 = 0x1;
/// `VM_FLAGS_OVERWRITE`.
pub const VM_FLAGS_OVERWRITE: u32 = 0x4000;
/// `VM_FLAGS_USER_ALLOCATE`.
const VM_FLAGS_USER_ALLOCATE: u32 = 0x1
    | 0x2
    | 0x4
    | 0x8
    | 0x10
    | 0x80
    | 0x4000
    | 0x40_0000
    | 0x7_0000
    | 0x1000
    | 0x2000
    | 0xFF00_0000;
/// `VM_FLAGS_USER_MAP`.
const VM_FLAGS_USER_MAP: u32 = VM_FLAGS_USER_ALLOCATE | 0x80_0000 | 0x10_0000;
/// `VM_PROT_COPY`.
const VM_PROT_COPY: u32 = 0x10;

fn mm_kr(e: MmError) -> KernReturn {
    match e {
        MmError::OutOfMemory => kr::KERN_RESOURCE_SHORTAGE,
        MmError::OutOfRange | MmError::NotMapped { .. } => kr::KERN_INVALID_ADDRESS,
        MmError::InvalidArgument(_) => kr::KERN_INVALID_ARGUMENT,
    }
}

/// Truncates `addr` and rounds `addr + size` to pages: the page range, or
/// `None` when the end overflows.
fn page_range(ctx: &Ctx<'_>, addr: u64, size: u64) -> Option<(u64, u64)> {
    let mask = ctx.proc.vm.page - 1;
    let start = addr & !mask;
    let end = addr.checked_add(size)?.checked_add(mask)? & !mask;
    Some((start, end - start))
}

/// Enters zero-fill memory: anywhere (first fit at or above `addr`,
/// aligned to `mask + 1`, as vm_map_locate_space_anywhere searches from
/// its hint without wrapping) or at `addr` (replacing with `OVERWRITE`).
fn enter(
    ctx: &mut Ctx<'_>,
    addr: u64,
    size: u64,
    mask: u64,
    flags: u32,
    cur: u32,
) -> Result<u64, KernReturn> {
    let vmx = ctx.proc.vm;
    let page_mask = vmx.page - 1;
    let size = (size
        .checked_add(page_mask)
        .ok_or(kr::KERN_INVALID_ARGUMENT)?)
        & !page_mask;
    let tag = flags >> 24;
    let mapping = Mapping {
        flags: VmFlags::new(vm::VM_PROT_ALL, vm::VM_INHERIT_COPY, tag).bits(),
        ..Mapping::anonymous(vm::perms(cur))
    };
    let at = if flags & VM_FLAGS_ANYWHERE != 0 {
        let align = (mask | page_mask) + 1;
        let from = (addr & !page_mask).max(vmx.min);
        ctx.proc
            .space
            .find_free_bottom_up(size, align, from, vmx.max)
            .ok_or(kr::KERN_NO_SPACE)?
    } else {
        let start = addr & !page_mask;
        if start & mask != 0 {
            return Err(kr::KERN_NO_SPACE);
        }
        if !vmx.contains(start, size) {
            return Err(kr::KERN_INVALID_ADDRESS);
        }
        if flags & VM_FLAGS_OVERWRITE == 0 && !ctx.proc.space.is_free(start, size) {
            return Err(kr::KERN_NO_SPACE);
        }
        start
    };
    ctx.proc.space.map(at, size, mapping).map_err(mm_kr)?;
    Ok(at)
}

/// `VM_MEMORY_MACH_MSG`: memory the kernel allocates for out-of-line
/// message data.
pub const VM_MEMORY_MACH_MSG: u32 = 20;

/// Allocates zero-filled, read/write memory anywhere in `proc`'s map on
/// the kernel's behalf (`mach_vm_allocate_kernel` with
/// `VM_FLAGS_ANYWHERE`), tagged `tag`.
pub fn allocate_kernel(
    proc: &mut crate::user::darwin::process::Proc,
    size: u64,
    tag: u32,
) -> Result<u64, KernReturn> {
    let vmx = proc.vm;
    let page_mask = vmx.page - 1;
    let size = size
        .checked_add(page_mask)
        .ok_or(kr::KERN_RESOURCE_SHORTAGE)?
        & !page_mask;
    let at = proc
        .space
        .find_free_bottom_up(size, vmx.page, vmx.min, vmx.max)
        .ok_or(kr::KERN_NO_SPACE)?;
    let mapping = Mapping {
        flags: VmFlags::new(vm::VM_PROT_ALL, vm::VM_INHERIT_COPY, tag).bits(),
        ..Mapping::anonymous(vm::perms(vm::VM_PROT_DEFAULT))
    };
    proc.space.map(at, size, mapping).map_err(mm_kr)?;
    Ok(at)
}

/// `mach_vm_allocate`: the address it chose (`addr` itself when fixed).
pub fn allocate_at(ctx: &mut Ctx<'_>, addr: u64, size: u64, flags: u32) -> Result<u64, KernReturn> {
    if flags & !VM_FLAGS_USER_ALLOCATE != 0 {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    if size == 0 {
        // A zero-sized allocation succeeds at address zero.
        return Ok(0);
    }
    // An anywhere allocation searches up from the map's minimum
    // (mach_vm_allocate_kernel_sanitize zeroes the address).
    let hint = if flags & VM_FLAGS_ANYWHERE != 0 {
        ctx.proc.vm.min
    } else {
        addr
    };
    enter(ctx, hint, size, 0, flags, vm::VM_PROT_DEFAULT)
}

/// `_kernelrpc_mach_vm_allocate_trap(target, addr, size, flags)`.
pub fn allocate(ctx: &mut Ctx<'_>, addr_ptr: u64, size: u64, flags: u32) -> KernReturn {
    let Ok(addr) = ctx.read_u64(addr_ptr) else {
        return kr::KERN_MEMORY_ERROR;
    };
    match allocate_at(ctx, addr, size, flags) {
        Ok(a) => match ctx.write_u64(addr_ptr, a) {
            Ok(()) => kr::KERN_SUCCESS,
            Err(_) => kr::KERN_MEMORY_ERROR,
        },
        Err(e) => e,
    }
}

/// `mach_vm_map` of anonymous memory: the address it chose.
pub fn map_at(
    ctx: &mut Ctx<'_>,
    addr: u64,
    size: u64,
    mask: u64,
    flags: u32,
    cur: u32,
) -> Result<u64, KernReturn> {
    if flags & !VM_FLAGS_USER_MAP != 0 {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    if cur & !vm::VM_PROT_ALL != 0 {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    if size == 0 {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    // An anywhere mapping searches up from the caller's address
    // (vm_map_enter_mem_object passes it to vm_map_locate_space_anywhere
    // as the hint).
    enter(ctx, addr, size, mask, flags, cur)
}

/// `_kernelrpc_mach_vm_map_trap(target, addr, size, mask, flags,
/// cur_protection)`: anonymous memory, maximum protection `VM_PROT_ALL`.
pub fn map(
    ctx: &mut Ctx<'_>,
    addr_ptr: u64,
    size: u64,
    mask: u64,
    flags: u32,
    cur: u32,
) -> KernReturn {
    let Ok(addr) = ctx.read_u64(addr_ptr) else {
        return kr::KERN_MEMORY_ERROR;
    };
    match map_at(ctx, addr, size, mask, flags, cur) {
        Ok(a) => match ctx.write_u64(addr_ptr, a) {
            Ok(()) => kr::KERN_SUCCESS,
            Err(_) => kr::KERN_MEMORY_ERROR,
        },
        Err(e) => e,
    }
}

/// `_kernelrpc_mach_vm_deallocate_trap(target, address, size)`.
pub fn deallocate(ctx: &mut Ctx<'_>, addr: u64, size: u64) -> KernReturn {
    if size == 0 {
        return kr::KERN_SUCCESS;
    }
    let Some((start, len)) = page_range(ctx, addr, size) else {
        return kr::KERN_INVALID_ARGUMENT;
    };
    if start
        .checked_add(len)
        .is_none_or(|e| e > ctx.proc.space.va_limit())
    {
        return kr::KERN_INVALID_ARGUMENT;
    }
    match ctx.proc.space.unmap(start, len) {
        Ok(()) => kr::KERN_SUCCESS,
        Err(e) => mm_kr(e),
    }
}

/// `_kernelrpc_mach_vm_protect_trap(target, address, size, set_maximum,
/// new_protection)`.
pub fn protect(ctx: &mut Ctx<'_>, addr: u64, size: u64, set_max: bool, prot: u32) -> KernReturn {
    if prot & !(vm::VM_PROT_ALL | VM_PROT_COPY) != 0 {
        return kr::KERN_INVALID_ARGUMENT;
    }
    if size == 0 {
        return kr::KERN_SUCCESS;
    }
    let Some((start, len)) = page_range(ctx, addr, size) else {
        return kr::KERN_INVALID_ARGUMENT;
    };
    let end = start + len;
    if ctx.proc.space.first_unmapped(start, len).is_some() {
        return kr::KERN_INVALID_ADDRESS;
    }
    let new = prot & vm::VM_PROT_ALL;
    let vmas = ctx.proc.space.vmas_in(start, end);
    if !set_max && prot & VM_PROT_COPY == 0 {
        for v in &vmas {
            if new & !VmFlags::from_bits(v.flags).max_prot() != 0 {
                return kr::KERN_PROTECTION_FAILURE;
            }
        }
    }
    for v in vmas {
        let lo = v.start.max(start);
        let hi = v.end.min(end);
        let f = VmFlags::from_bits(v.flags);
        let (cur, max) = if set_max {
            // The current protection is limited by the new maximum.
            (vm::prot(v.perms) & new, new)
        } else if prot & VM_PROT_COPY != 0 {
            // A private copy: the maximum grows to include the request.
            (new, f.max_prot() | new)
        } else {
            (new, f.max_prot())
        };
        if let Err(e) =
            ctx.proc
                .space
                .set_flags(lo, hi - lo, 0x7, f.with_max_prot(max).bits() & 0x7)
        {
            return mm_kr(e);
        }
        if let Err(e) = ctx.proc.space.protect(lo, hi - lo, vm::perms(cur)) {
            return mm_kr(e);
        }
    }
    kr::KERN_SUCCESS
}
