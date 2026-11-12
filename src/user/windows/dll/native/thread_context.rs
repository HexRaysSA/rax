//! Native thread contexts stay within the guest scheduler and CPU views.
use super::query::{guard_result, probe_write};
use crate::user::windows::arch::{WinArch, WinCpu};
use crate::user::windows::context::RegContext;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, ObjId, Object};

mod compat;
mod extended;
mod groups;

pub(super) fn get(c: &mut Ctx) -> ApiResult {
    let arch = c.arch();
    let result = get_checked(c, arch, false);
    guard_result(c, result)
}

pub(super) fn set(c: &mut Ctx) -> ApiResult {
    let arch = c.arch();
    let result = set_checked(c, arch, false);
    guard_result(c, result)
}

fn target(c: &Ctx, handle: u64, access: u32) -> Result<ObjId, u32> {
    if handle == c.arch().ptr(CURRENT_THREAD) {
        return Ok(c.t.obj);
    }
    if handle == c.arch().ptr(CURRENT_PROCESS) {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    let id = c.p.objects.id(handle).ok_or(STATUS_INVALID_HANDLE)?;
    if !matches!(c.p.objects.obj(id), Some(Object::Thread { .. })) {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    if c.p.objects.access(handle).unwrap_or(0) & access == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(id)
}

fn cpu<'a>(c: &'a Ctx, id: ObjId) -> Result<&'a WinCpu, ApiErr> {
    if id == c.t.obj {
        return Ok(&c.t.cpu);
    }
    let Some(Object::Thread { tid, .. }) = c.p.objects.obj(id) else {
        unreachable!("validated thread object")
    };
    c.p.threads
        .get(tid)
        .filter(|thread| thread.obj == id)
        .map(|thread| &thread.cpu)
        .ok_or_else(|| c.unsupported("thread context belongs to an external or retired thread"))
}

fn retired(c: &Ctx, id: ObjId) -> bool {
    matches!(
        c.p.objects.obj(id),
        Some(Object::Thread {
            exit_code: Some(_),
            ..
        })
    )
}

fn reported(c: &Ctx, id: ObjId) -> u32 {
    if id == c.t.obj {
        return 0x1000_0000;
    }
    let Some(Object::Thread { tid, .. }) = c.p.objects.obj(id) else {
        unreachable!("validated thread")
    };
    let Some(thread) = c.p.threads.get(tid) else {
        return 0;
    };
    if matches!(
        thread.state,
        crate::user::windows::process::thread::ThreadState::Waiting(_)
    ) {
        0x1000_0000
    } else if !thread.attached
        || thread
            .frames
            .iter()
            .any(|frame| frame.exception_caller.is_some())
    {
        0x0800_0000
    } else {
        0
    }
}

pub(super) fn get_with_arch(c: &mut Ctx, arch: WinArch) -> ApiResult {
    let result = get_checked(c, arch, true);
    guard_result(c, result)
}

fn get_checked(c: &mut Ctx, arch: WinArch, raw: bool) -> ApiResult {
    if raw && compat::selected(c, arch)? {
        return compat::get(c);
    }
    let (handle, address) = (c.ptr(0)?, c.ptr(1)?);
    if arch == WinArch::X86 && address % 4 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    let id = match target(c, handle, 8) {
        Ok(id) => id,
        Err(status) => return Flow::ret(status.into()),
    };
    let Some(flags_address) = address.checked_add(groups::flags_offset(arch)) else {
        return Flow::ret(STATUS_ACCESS_VIOLATION.into());
    };
    let flags = c.mem().u32(flags_address)?;
    let extended = match extended::capture(c, address, arch, flags)? {
        Ok(state) => state,
        Err(status) => return Flow::ret(status.into()),
    };
    if address % RegContext::align(arch) != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    let bytes = if arch == WinArch::X86 && flags & 0x20 == 0 {
        204
    } else {
        RegContext::size(arch)
    };
    probe_write(c, address, bytes)?;
    if retired(c, id) {
        return Flow::ret(STATUS_UNSUCCESSFUL.into());
    }
    let target = cpu(c, id)?;
    if let Some(state) = &extended {
        state.get(c, target, arch)?;
    }
    let mut context = if arch == WinArch::Arm64 {
        match target.arm64_kernel_context() {
            Ok(context) => context,
            Err(status) => return Flow::ret(status.into()),
        }
    } else {
        RegContext::capture(target)
    };
    if groups::has_debug(arch, flags) {
        let debug = match target.kernel_debug_context(arch) {
            Ok(debug) => debug,
            Err(status) => return Flow::ret(status.into()),
        };
        let mut bytes = context.bytes().to_vec();
        bytes[groups::debug_range(arch)].copy_from_slice(&debug);
        context = RegContext::from_bytes(arch, bytes);
    }
    context.set_flags(
        groups::returned_flags(arch, flags, reported(c, id))
            | if extended.is_some() { 0x40 } else { 0 },
    );
    for range in groups::ranges(arch, flags) {
        c.mem()
            .wr(address + range.start as u64, &context.bytes()[range])?;
    }
    c.mem()
        .w32(address + groups::flags_offset(arch), context.flags())?;
    Flow::ret(0)
}

pub(super) fn set_with_arch(c: &mut Ctx, arch: WinArch) -> ApiResult {
    let result = set_checked(c, arch, true);
    guard_result(c, result)
}

fn set_checked(c: &mut Ctx, arch: WinArch, raw: bool) -> ApiResult {
    if raw && compat::selected(c, arch)? {
        return compat::set(c);
    }
    let (handle, address) = (c.ptr(0)?, c.ptr(1)?);
    if arch == WinArch::X86 && address % 4 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    let id = match target(c, handle, 16) {
        Ok(id) => id,
        Err(status) => return Flow::ret(status.into()),
    };
    if arch == WinArch::X86 && retired(c, id) {
        return Flow::ret(0xc000_004bu64);
    }
    let Some(flags_address) = address.checked_add(groups::flags_offset(arch)) else {
        return Flow::ret(STATUS_ACCESS_VIOLATION.into());
    };
    let flags = c.mem().u32(flags_address)?;
    let extended = match extended::capture(c, address, arch, flags)? {
        Ok(state) => state,
        Err(status) => return Flow::ret(status.into()),
    };
    if address % RegContext::align(arch) != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    let ranges = groups::ranges(arch, flags);
    let mut input = vec![0; RegContext::size(arch)];
    for range in &ranges {
        let bytes = c.mem().bytes(address + range.start as u64, range.len())?;
        input[range.clone()].copy_from_slice(&bytes);
    }
    if retired(c, id) {
        return Flow::ret(STATUS_UNSUCCESSFUL.into());
    }
    let ymm = match &extended {
        Some(state) => state.input(c, arch)?,
        None => None,
    };
    let target = cpu(c, id)?;
    let mut context = if arch == WinArch::Arm64 {
        match target.arm64_kernel_context() {
            Ok(context) => context,
            Err(status) => return Flow::ret(status.into()),
        }
    } else {
        RegContext::capture(target)
    };
    let mut bytes = context.bytes().to_vec();
    for range in ranges {
        bytes[range.clone()].copy_from_slice(&input[range]);
    }
    context = RegContext::from_bytes(arch, bytes);
    let debug =
        groups::has_debug(arch, flags).then(|| context.bytes()[groups::debug_range(arch)].to_vec());
    let mut selected = flags & RegContext::all_flags(arch);
    if arch == WinArch::Arm64 && flags & 0xc0 != 0 {
        selected |= 4;
    }
    context.set_flags(selected | RegContext::arch_flag(arch));
    let user_limit = c.p.vm.high();
    let target = cpu(c, id)?;
    if let Err(status) = target.validate_kernel_context(&context) {
        return Flow::ret(status.into());
    }
    if let Some(debug) = &debug {
        let mut copy = target.new_thread();
        if let Err(status) = copy.apply_kernel_debug_context(arch, debug, user_limit) {
            return Flow::ret(status.into());
        }
    }
    if selected & 0xffff == 0 && debug.is_none() && ymm.is_none() {
        return Flow::ret(0);
    }
    if id == c.t.obj && selected & 1 != 0 {
        if let Some(ymm) = ymm {
            if let Err(status) = c.t.cpu.apply_kernel_ymm_high(ymm) {
                return Flow::ret(status.into());
            }
        }
        if let Some(debug) = &debug {
            if let Err(status) = c.t.cpu.apply_kernel_debug_context(arch, debug, user_limit) {
                return Flow::ret(status.into());
            }
        }
        return Ok(Flow::Resume(Box::new(context)));
    }
    let target = if id == c.t.obj {
        &mut c.t.cpu
    } else {
        let Some(Object::Thread { tid, .. }) = c.p.objects.obj(id) else {
            unreachable!("validated thread object")
        };
        &mut c
            .p
            .threads
            .get_mut(tid)
            .expect("validated guest thread")
            .cpu
    };
    if selected & 0xffff != 0 {
        if let Err(status) = target.apply_kernel_context(&context) {
            return Flow::ret(status.into());
        }
    }
    if let Some(debug) = &debug {
        if let Err(status) = target.apply_kernel_debug_context(arch, debug, user_limit) {
            return Flow::ret(status.into());
        }
    }
    if let Some(ymm) = ymm {
        if let Err(status) = target.apply_kernel_ymm_high(ymm) {
            return Flow::ret(status.into());
        }
    }
    Flow::ret(0)
}
