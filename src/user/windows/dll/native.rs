//! Native DLL services whose numbers are independent of an NT syscall table.

use super::super::hle::{ApiResult, Archs, Arg::*, Conv::Stdcall, Ctx, Export, Flow};
use super::super::memory::Mem;
use super::super::nt::status::*;

mod events;
mod hotpatch;
mod nls;
mod process_query;
mod query;
mod registry;

pub(super) static EXPORTS: &[Export] = &[
    Export::func("RtlNtStatusToDosError", Stdcall, &[I32], status_error),
    Export::func(
        "NtTerminateProcess",
        Stdcall,
        &[Ptr, I32],
        terminate_process,
    ),
    Export::func("NtTerminateThread", Stdcall, &[Ptr, I32], terminate_thread),
    Export::func("NtClose", Stdcall, &[Ptr], close),
    Export::func(
        "NtAllocateVirtualMemory",
        Stdcall,
        &[Ptr, Ptr, Ptr, Ptr, I32, I32],
        alloc,
    ),
    Export::func("NtFreeVirtualMemory", Stdcall, &[Ptr, Ptr, Ptr, I32], free),
    Export::func(
        "NtProtectVirtualMemory",
        Stdcall,
        &[Ptr, Ptr, Ptr, I32, Ptr],
        protect,
    ),
    Export::func("NtContinue", Stdcall, &[Ptr, I32], continue_context),
    Export::func("RtlCaptureContext", Stdcall, &[Ptr], capture_context),
    Export::func(
        "RtlUnwind",
        Stdcall,
        &[Ptr, Ptr, Ptr, Ptr],
        crate::user::windows::seh::x86::rtl_unwind,
    )
    .only(Archs::X86),
    Export::func(
        "NtQuerySystemInformation",
        Stdcall,
        &[I32, Ptr, I32, Ptr],
        query::system_information,
    ),
    Export::func(
        "NtQueryInformationProcess",
        Stdcall,
        &[Ptr, I32, Ptr, I32, Ptr],
        process_query::information,
    ),
    Export::func(
        "NtCreateEvent",
        Stdcall,
        &[Ptr, I32, Ptr, I32, I32],
        events::create,
    ),
    Export::func("NtSetEvent", Stdcall, &[Ptr, Ptr], events::set),
    Export::func("NtResetEvent", Stdcall, &[Ptr, Ptr], events::reset),
    Export::func(
        "NtManageHotPatch",
        Stdcall,
        &[I32, Ptr, I32, Ptr],
        hotpatch::manage,
    ),
    Export::func("NtOpenKey", Stdcall, &[Ptr, I32, Ptr], registry::open),
    Export::func(
        "NtQueryValueKey",
        Stdcall,
        &[Ptr, Ptr, I32, Ptr, I32, Ptr],
        registry::query,
    ),
    Export::func(
        "NtGetNlsSectionPtr",
        Stdcall,
        &[I32, I32, Ptr, Ptr, Ptr],
        nls::get,
    ),
    Export::func("NtUnmapViewOfSection", Stdcall, &[Ptr, Ptr], nls::unmap),
];
fn status_error(c: &mut Ctx) -> ApiResult {
    Flow::ret(u64::from(super::super::nt::status_to_error(c.u32(0)?)))
}
fn self_process(c: &Ctx, handle: u64) -> bool {
    handle == c.arch().ptr(u64::MAX)
}
fn terminate_process(c: &mut Ctx) -> ApiResult {
    let (handle, status) = (c.ptr(0)?, c.u32(1)?);
    if !self_process(c, handle) && handle != 0 {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    }
    Ok(Flow::TerminateProcess(status))
}
fn terminate_thread(c: &mut Ctx) -> ApiResult {
    let (handle, status) = (c.ptr(0)?, c.u32(1)?);
    if handle != c.arch().ptr(u64::MAX - 1) && handle != 0 {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    }
    Ok(Flow::TerminateThread(status))
}
fn close(c: &mut Ctx) -> ApiResult {
    let handle = c.ptr(0)?;
    Flow::ret(
        if c.p.objects.close(handle).is_ok() {
            STATUS_SUCCESS
        } else {
            STATUS_INVALID_HANDLE
        }
        .into(),
    )
}
fn alloc(c: &mut Ctx) -> ApiResult {
    let (handle, base_ptr, zero, size_ptr, flags, protection) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.ptr(2)?,
        c.ptr(3)?,
        c.u32(4)?,
        c.u32(5)?,
    );
    if !self_process(c, handle) {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    }
    if zero != 0 {
        return Err(c.unsupported("NtAllocateVirtualMemory ZeroBits"));
    }
    let (base, size) = (c.read_ptr(base_ptr)?, c.read_ptr(size_ptr)?);
    c.write_ptr(base_ptr, base)?;
    c.write_ptr(size_ptr, size)?;
    match c
        .p
        .vm
        .allocate((base != 0).then_some(base), size, flags, protection)
    {
        Ok((base, size)) => {
            c.write_ptr(base_ptr, base)?;
            c.write_ptr(size_ptr, size)?;
            Flow::ret(0)
        }
        Err(e) => Flow::ret(e.status().into()),
    }
}
fn free(c: &mut Ctx) -> ApiResult {
    let (handle, base_ptr, size_ptr, flags) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?, c.u32(3)?);
    if !self_process(c, handle) {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    }
    let (base, size) = (c.read_ptr(base_ptr)?, c.read_ptr(size_ptr)?);
    c.write_ptr(base_ptr, base)?;
    c.write_ptr(size_ptr, size)?;
    match c.p.vm.free(base, size, flags) {
        Ok((base, size)) => {
            c.write_ptr(base_ptr, base)?;
            c.write_ptr(size_ptr, size)?;
            Flow::ret(0)
        }
        Err(e) => Flow::ret(e.status().into()),
    }
}
fn protect(c: &mut Ctx) -> ApiResult {
    let (handle, base_ptr, size_ptr, protection, old_ptr) =
        (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?, c.u32(3)?, c.ptr(4)?);
    if !self_process(c, handle) {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    }
    let (base, size) = (c.read_ptr(base_ptr)?, c.read_ptr(size_ptr)?);
    c.write_ptr(base_ptr, base)?;
    c.write_ptr(size_ptr, size)?;
    c.mem().w32(old_ptr, c.mem().u32(old_ptr)?)?;
    match c.p.vm.protect(base, size, protection) {
        Ok(old) => {
            let start = base & !0xFFF;
            let end = base
                .checked_add(size)
                .and_then(|v| v.checked_add(0xFFF))
                .ok_or(super::super::memory::MemFault {
                    addr: u64::MAX,
                    write: false,
                })?
                & !0xFFF;
            c.write_ptr(base_ptr, start)?;
            c.write_ptr(size_ptr, end - start)?;
            c.mem().w32(old_ptr, old)?;
            Flow::ret(0)
        }
        Err(e) => {
            if c.p.vm.is_nls_view(base) && e == super::super::memory::VmError::InvalidProtection {
                c.mem().w32(old_ptr, super::super::memory::prot::NOACCESS)?;
            }
            Flow::ret(e.status().into())
        }
    }
}
fn continue_context(c: &mut Ctx) -> ApiResult {
    if c.u32(1)? != 0 {
        return Err(c.unsupported("NtContinue alertable APC delivery"));
    }
    let address = c.ptr(0)?;
    if address % super::super::context::RegContext::align(c.arch()) != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let context = super::super::context::RegContext::read(c.mem(), c.arch(), address)?;
    if let Err(status) = context.validate(&c.t.cpu) {
        return Flow::ret(status.into());
    }
    Ok(Flow::Resume(Box::new(context)))
}
fn capture_context(c: &mut Ctx) -> ApiResult {
    let addr = c.ptr(0)?;
    let mut context = super::super::context::RegContext::capture(&c.t.cpu);
    context.set_pc(c.ret_addr);
    context.set_sp(
        c.entry_sp
            + if c.arch().is64() {
                if c.arch() == super::super::arch::WinArch::X64 {
                    8
                } else {
                    0
                }
            } else {
                8
            },
    );
    context.write(c.mem(), addr)?;
    Flow::void()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::arch::WinArch;
    use crate::user::windows::context::{INTEGER, RegContext};
    use crate::user::windows::hle::{ApiErr, Item, Value};
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};

    #[test]
    fn nt_termination_self_paths_are_forced_all_abis() {
        for arch in WinArch::ALL {
            let image: &[u8] = match arch {
                WinArch::X86 => {
                    include_bytes!("../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
                }
                WinArch::X64 => {
                    include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
                }
                WinArch::Arm64 => {
                    include_bytes!("../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
                }
            };
            let mut config = WindowsConfig::new("terminate-test.exe", vec![]);
            config.seed = Some(1);
            config.arena_bytes = 64 << 20;
            let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
            let p = process.state_mut();
            let tid = *p.threads.keys().next().unwrap();
            let mut t = p.threads.remove(&tid).unwrap();
            let sp = t.cpu.sp();
            for (name, pseudo, process_exit) in [
                ("NtTerminateProcess", arch.ptr(u64::MAX), true),
                ("NtTerminateThread", arch.ptr(u64::MAX - 1), false),
            ] {
                let api = EXPORTS
                    .iter()
                    .find_map(|e| match &e.item {
                        Item::Func(api) if api.name == name => Some(api),
                        _ => None,
                    })
                    .unwrap();
                for handle in [pseudo, 0, 0x1234] {
                    match arch {
                        WinArch::X86 => {
                            p.space.w32(sp + 4, handle as u32).unwrap();
                            p.space.w32(sp + 8, 0xDEAD_BEEF).unwrap();
                        }
                        WinArch::X64 => {
                            t.cpu.set_gpr(1, handle);
                            t.cpu.set_gpr(2, 0xDEAD_BEEF);
                        }
                        WinArch::Arm64 => {
                            t.cpu.set_gpr(0, handle);
                            t.cpu.set_gpr(1, 0xDEAD_BEEF);
                        }
                    }
                    let mut c = Ctx {
                        p,
                        t: &mut t,
                        api,
                        entry_pc: 0,
                        entry_sp: sp,
                        ret_addr: 0,
                        cursor: sp,
                    };
                    c.set_last_error(0x7654_3210).unwrap();
                    let flow = (api.imp)(&mut c).unwrap();
                    if handle == 0x1234 {
                        assert!(
                            matches!(flow, Flow::Ret(Value::Int(status))
                            if status == u64::from(STATUS_INVALID_HANDLE)),
                            "{arch}: {name}"
                        );
                    } else if process_exit {
                        assert!(
                            matches!(flow, Flow::TerminateProcess(0xDEAD_BEEF)),
                            "{arch}: {name}"
                        );
                    } else {
                        assert!(
                            matches!(flow, Flow::TerminateThread(0xDEAD_BEEF)),
                            "{arch}: {name}"
                        );
                    }
                    assert_eq!(c.last_error().unwrap(), 0x7654_3210);
                }
            }
        }
    }

    #[test]
    fn ntcontinue_rejects_invalid_state_and_explicitly_rejects_alert_delivery() {
        let mut cfg = WindowsConfig::new("context-api-test.exe", Vec::new());
        cfg.seed = Some(1);
        cfg.arena_bytes = 64 << 20;
        let mut process = WindowsProcess::spawn_image(
            cfg,
            include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe").to_vec(),
        )
        .unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let api = EXPORTS
            .iter()
            .find_map(|export| match &export.item {
                Item::Func(api) if api.name == "NtContinue" => Some(api),
                _ => None,
            })
            .unwrap();
        let sp = t.cpu.sp();
        let address = sp - 0x800;
        let mut saved = RegContext::capture(&t.cpu);
        saved.set_gpr(0, 0x1234_5678);
        saved.set_flags(RegContext::arch_flag(p.arch) | 0x10);
        saved.write(&p.space, address).unwrap();
        t.cpu.set_gpr(1, address);
        t.cpu.set_gpr(2, 0);
        let old = RegContext::capture(&t.cpu);
        let mut c = Ctx {
            p,
            t: &mut t,
            api,
            entry_pc: 0,
            entry_sp: sp,
            ret_addr: 0,
            cursor: sp,
        };
        assert!(matches!(
            continue_context(&mut c).unwrap(),
            Flow::Ret(Value::Int(status)) if status == u64::from(STATUS_INVALID_PARAMETER)
        ));
        assert_eq!(RegContext::capture(&c.t.cpu).bytes(), old.bytes());
        saved.set_flags(RegContext::arch_flag(c.arch()) | INTEGER);
        saved.write(c.mem(), address).unwrap();
        assert!(matches!(continue_context(&mut c).unwrap(), Flow::Resume(_)));
        c.t.cpu.set_gpr(1, address + 1);
        assert!(matches!(
            continue_context(&mut c).unwrap(),
            Flow::Ret(Value::Int(status)) if status == u64::from(STATUS_INVALID_PARAMETER)
        ));
        c.t.cpu.set_gpr(1, address);
        c.t.cpu.set_gpr(2, 1);
        assert!(matches!(
            continue_context(&mut c),
            Err(ApiErr::Unimplemented(_))
        ));
        c.t.cpu.set_gpr(2, 0);
        c.t.cpu.set_gpr(1, u64::MAX - 15);
        assert!(matches!(continue_context(&mut c), Err(ApiErr::Fault(_))));
    }
}
