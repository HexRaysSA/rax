//! Installed NTDLL loader entry and the native thread-start scheduling boundary.
//!
//! The host's private heap/module lists never stand in for RTL-owned PEB data.
//! Selected suspended-child contexts and NTDLL entry bytes are recorded in
//! `native-runtime.md`; compatibility-only OS entry thunks are not file exports.

use super::{Proc, Thread};
use crate::user::windows::arch::{WinArch, WinCpu};
use crate::user::windows::context::RegContext;
use crate::user::windows::loader::{self, ModuleKind, SymRef};
use crate::user::windows::memory::{Mem, mem, perms_of};
use crate::user::windows::nt::status::*;

#[derive(Clone, Copy, Debug)]
pub(crate) struct EntryPoints {
    pub(crate) loader: u64,
    pub(crate) thread: u64,
    pub(crate) module: u64,
}

fn entry_points(p: &mut Proc) -> Result<EntryPoints, u32> {
    if let Some(entries) = p.native.as_ref().and_then(|runtime| runtime.startup) {
        return Ok(entries);
    }
    let index = p.modules.by_name("ntdll.dll").ok_or(STATUS_DLL_NOT_FOUND)?;
    let module = &p.modules.list[index];
    if !matches!(module.kind, ModuleKind::Native) {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    let base = module.base;
    let end = base
        .checked_add(module.size)
        .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    let mut resolve = |name: &[u8]| {
        let address = loader::lookup(p, index, &SymRef::Name(name.to_vec(), None))
            .map_err(|error| error.status)?
            .ok_or(STATUS_ENTRYPOINT_NOT_FOUND)?;
        if !(base..end).contains(&address)
            || !p.vm.query(address).is_some_and(|region| {
                region.state == mem::COMMIT
                    && perms_of(region.protect).contains(crate::user::mm::Perms::EXEC)
            })
        {
            return Err(STATUS_INVALID_IMAGE_FORMAT);
        }
        Ok(address)
    };
    let entries = EntryPoints {
        loader: resolve(b"LdrInitializeThunk")?,
        thread: resolve(b"RtlUserThreadStart")?,
        module: base,
    };
    p.native.as_mut().ok_or(STATUS_INVALID_PARAMETER)?.startup = Some(entries);
    Ok(entries)
}

pub(super) fn prepare(p: &mut Proc, cpu: &mut WinCpu, main: bool) -> Result<(), u32> {
    let entries = entry_points(p)?;
    enter(p, cpu, main, entries)
}

fn enter(p: &Proc, cpu: &mut WinCpu, main: bool, entries: EntryPoints) -> Result<(), u32> {
    let arch = p.arch;
    let mut saved = RegContext::capture(cpu);
    saved.set_pc(entries.thread);
    if main {
        // The native main-thread start parameter is the process PEB.
        saved.set_gpr(
            if arch == WinArch::X86 {
                3
            } else if arch == WinArch::X64 {
                2
            } else {
                1
            },
            p.peb,
        );
    }
    if arch == WinArch::X64 {
        // An AMD64 callable entry has an eight-byte return-address slot.
        saved.set_sp(saved.sp().checked_sub(8).ok_or(STATUS_NO_MEMORY)?);
    }
    let context = saved
        .sp()
        .checked_sub(RegContext::size(arch) as u64)
        .ok_or(STATUS_NO_MEMORY)?
        & !(RegContext::align(arch) - 1);
    let frame = context.checked_sub(64).ok_or(STATUS_NO_MEMORY)? & !15;
    let sp = if arch == WinArch::X64 {
        frame.checked_sub(8).ok_or(STATUS_NO_MEMORY)?
    } else {
        frame
    };
    // Probe the complete scratch before publishing any context/frame bytes.
    // Its address lies below the saved application SP, so native loader calls
    // cannot overwrite CONTEXT. No caller-sized host allocation is involved.
    let extent = context
        .checked_add(RegContext::size(arch) as u64)
        .and_then(|end| end.checked_sub(sp))
        .ok_or(STATUS_NO_MEMORY)?;
    p.space
        .probe(
            sp,
            usize::try_from(extent).map_err(|_| STATUS_NO_MEMORY)?,
            crate::error::MemoryAccessKind::Write,
        )
        .map_err(|_| STATUS_NO_MEMORY)?;
    saved
        .write(&p.space, context)
        .map_err(|_| STATUS_NO_MEMORY)?;
    let frame_bytes = usize::try_from(context - sp).map_err(|_| STATUS_NO_MEMORY)?;
    let zeros = [0u8; 80];
    p.space
        .wr(sp, &zeros[..frame_bytes])
        .map_err(|_| STATUS_NO_MEMORY)?;
    match arch {
        WinArch::X86 => {
            // LdrInitializeThunk reads the two stdcall arguments at ESP+4/+8.
            p.space
                .w32(sp + 4, context as u32)
                .map_err(|_| STATUS_NO_MEMORY)?;
            p.space
                .w32(sp + 8, entries.module as u32)
                .map_err(|_| STATUS_NO_MEMORY)?;
        }
        WinArch::X64 => {
            cpu.set_gpr(1, context);
            cpu.set_gpr(2, entries.module);
        }
        WinArch::Arm64 => {
            cpu.set_gpr(0, context);
            cpu.set_gpr(1, entries.module);
            cpu.set_gpr(30, 0);
        }
    }
    cpu.set_sp(sp);
    cpu.set_pc(entries.loader);
    Ok(())
}

/// NtContinue resumes the saved native start entry before the next CPU slice.
/// No host DLL/TLS callbacks are dispatched at this boundary.
pub(super) fn observe_resume(p: &Proc, t: &mut Thread) {
    if !t.attached
        && p.native
            .as_ref()
            .and_then(|runtime| runtime.startup)
            .is_some_and(|entries| t.cpu.pc() == entries.thread)
    {
        t.attached = true;
    }
}

#[cfg(test)]
mod tests;
