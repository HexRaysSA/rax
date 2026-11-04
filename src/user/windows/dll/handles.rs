//! Same-process handle duplication and handle flags.
//!
//! Contract: Microsoft handleapi.h documentation retained with thread services.
//! Same-access and reduced-grant duplication preserve object identity/cursors.
//! Access escalation for non-file objects requires unmodeled token/ACL state
//! and is rejected explicitly, rather than approximating an access check.

use super::super::hle::{ApiResult, Arg::*, Conv::Stdcall, Ctx, Export, Flow};
use super::super::memory::{Mem, MemFault};
use super::super::nt::error::*;
use super::super::objects::{ObjId, Object};
use crate::error::MemoryAccessKind;

pub(super) static EXPORTS: &[Export] = &[
    Export::func(
        "DuplicateHandle",
        Stdcall,
        &[Ptr, Ptr, Ptr, Ptr, I32, I32, I32],
        duplicate,
    ),
    Export::func(
        "GetHandleInformation",
        Stdcall,
        &[Ptr, Ptr],
        get_information,
    ),
    Export::func(
        "SetHandleInformation",
        Stdcall,
        &[Ptr, I32, I32],
        set_information,
    ),
];

fn probe(c: &Ctx, at: u64, size: usize) -> Result<(), MemFault> {
    c.mem()
        .probe(at, size, MemoryAccessKind::Write)
        .map_err(|f| MemFault {
            addr: f.address,
            write: true,
        })
}

fn pseudo(c: &Ctx, value: u64, offset: u32) -> bool {
    value
        == if c.psize() == 4 {
            u64::from(u32::MAX - offset)
        } else {
            u64::MAX - u64::from(offset)
        }
}

fn process_handle(c: &Ctx, handle: u64) -> Result<(), u32> {
    if pseudo(c, handle, 0) {
        return Ok(());
    }
    match c.p.objects.get(handle) {
        Some(Object::Process { pid, .. }) if *pid == c.p.pid => {
            if c.p.objects.access(handle).unwrap_or(0) & 0x40 != 0 {
                Ok(())
            } else {
                Err(ERROR_ACCESS_DENIED)
            }
        }
        _ => Err(ERROR_INVALID_HANDLE),
    }
}

fn source(c: &mut Ctx, handle: u64) -> Result<(ObjId, u32, bool), u32> {
    if pseudo(c, handle, 1) {
        return Ok((c.t.obj, 0x001F_FFFF, false));
    }
    if pseudo(c, handle, 0) {
        if let Some(id) = c.p.objects.iter().find_map(|(id, object)| {
            matches!(object, Object::Process { pid, .. } if *pid == c.p.pid).then_some(id)
        }) {
            return Ok((id, 0x001F_FFFF, false));
        }
        let id =
            c.p.objects
                .try_create(Object::Process {
                    pid: c.p.pid,
                    exit_code: c.p.exit_code,
                })
                .ok_or(ERROR_NOT_ENOUGH_MEMORY)?;
        return Ok((id, 0x001F_FFFF, true));
    }
    let id = c.p.objects.id(handle).ok_or(ERROR_INVALID_HANDLE)?;
    let grant = c.p.objects.access(handle).ok_or(ERROR_INVALID_HANDLE)?;
    Ok((id, grant, false))
}

fn duplicate(c: &mut Ctx) -> ApiResult {
    let (from, handle, to, out, desired, inherit, options) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.ptr(2)?,
        c.ptr(3)?,
        c.u32(4)?,
        c.u32(5)? != 0,
        c.u32(6)?,
    );
    if let Err(error) = process_handle(c, from) {
        return c.fail(error, 0);
    }
    if matches!(
        c.p.objects.get(handle),
        Some(
            Object::Directory(_)
                | Object::SymbolicLink(_)
                | Object::ImageSection(_)
                | Object::DataSection(_)
                | Object::FileSection(_)
        )
    ) {
        return duplicate_directory(c, handle, to, out, desired, inherit, options);
    }
    if options & 1 != 0 && c.p.objects.flags(handle).is_some_and(|f| f & 2 != 0) {
        return Err(
            c.unsupported("DUPLICATE_CLOSE_SOURCE with protected handle; native behavior unknown")
        );
    }
    if matches!(
        c.p.objects.get(handle),
        Some(Object::EtwRegistration { .. })
    ) {
        return duplicate_etw(c, handle, to, out, desired, options);
    }
    let result = (|| {
        if options & !3 != 0 {
            return c.fail(ERROR_INVALID_PARAMETER, 0);
        }
        if to == 0 {
            return if options & 1 != 0 {
                Flow::bool(true)
            } else {
                c.fail(ERROR_INVALID_PARAMETER, 0)
            };
        }
        if let Err(error) = process_handle(c, to) {
            return c.fail(error, 0);
        }
        // Probe before creating a process object or opening a new handle.
        if out != 0 {
            probe(c, out, c.psize() as usize)?;
        }
        let (id, grant, created) = match source(c, handle) {
            Ok(v) => v,
            Err(error) => return c.fail(error, 0),
        };
        let requested = if options & 2 != 0 {
            grant
        } else if matches!(c.p.objects.obj(id), Some(Object::File(_))) {
            super::files::effective_access(desired)
        } else {
            desired
        };
        if requested & !grant != 0 {
            if created {
                c.p.objects.release(id);
            }
            return if matches!(c.p.objects.obj(id), Some(Object::File(_))) {
                c.fail(ERROR_ACCESS_DENIED, 0)
            } else {
                Err(c.unsupported("duplicate access escalation requires token/ACL state"))
            };
        }
        let Some(new) = c.p.objects.open_access(id, inherit, requested) else {
            if created {
                c.p.objects.release(id);
            }
            return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
        };
        if out != 0
            && let Err(fault) = c.write_ptr(out, u64::from(new))
        {
            // Defensive rollback under the required stable mapping contract.
            let _ = c.p.objects.close(u64::from(new));
            return Err(fault.into());
        }
        Flow::bool(true)
    })();
    if options & 1 != 0
        && !pseudo(c, handle, 0)
        && !pseudo(c, handle, 1)
        && !c.p.objects.assigned_desktop_handle(handle)
    {
        match c.p.objects.close(handle) {
            Ok(object) => {
                if let Err(error) = super::files::finish_close(object) {
                    return c.fail(error, 0);
                }
            }
            Err(()) => return c.fail(ERROR_INVALID_HANDLE, 0),
        }
    }
    result
}

/// Measured KernelBase wrapper plus EtwRegistration duplication semantics.
/// Wrapper output initialization/fault handling precedes the kernel operation.
/// Unsupported option bits are ignored by the installed wrapper. WoW64's
/// output-copy failure may follow source close; native64 probes first.
fn duplicate_etw(
    c: &mut Ctx,
    handle: u64,
    to: u64,
    out: u64,
    desired: u32,
    options: u32,
) -> ApiResult {
    let denied = options & 2 == 0 && desired & !0x804 != 0;
    if out != 0 {
        if let Err(fault) = probe(c, out, c.psize() as usize) {
            let guard = c.p.vm.take_guard(fault.addr);
            // The measured WoW64 path reaches CLOSE_SOURCE for admissible
            // desired rights despite final wrapper output-copy failure.
            if c.psize() == 4 && !denied && options & 1 != 0 {
                match c.p.objects.close(handle) {
                    Ok(object) => {
                        if let Err(error) = super::files::finish_close(object) {
                            return c.fail(error, 0);
                        }
                    }
                    Err(()) => return c.fail(ERROR_INVALID_HANDLE, 0),
                }
            }
            return c.fail(
                if guard {
                    super::super::nt::status::STATUS_GUARD_PAGE_VIOLATION
                } else {
                    ERROR_NOACCESS
                },
                0,
            );
        }
        c.write_ptr(out, 0)?;
    }
    if denied {
        return c.fail(ERROR_ACCESS_DENIED, 0);
    }
    // No handle is duplicated. CLOSE_SOURCE is nevertheless honored after
    // a reached kernel operation, even when its result is an error.
    let close_source = options & 1 != 0;
    if close_source {
        match c.p.objects.close(handle) {
            Ok(object) => {
                if let Err(error) = super::files::finish_close(object) {
                    return c.fail(error, 0);
                }
            }
            Err(()) => return c.fail(ERROR_INVALID_HANDLE, 0),
        }
    }
    if to == 0 {
        return if close_source {
            Flow::bool(true)
        } else {
            c.fail(ERROR_INVALID_PARAMETER, 0)
        };
    }
    if let Err(error) = process_handle(c, to) {
        return c.fail(error, 0);
    }
    c.fail(ERROR_NOT_SUPPORTED, 0)
}

/// Measured Directory wrapper: native64 probes before the kernel operation;
/// WoW64 performs it before copy-out, including CLOSE_SOURCE on denied access.
/// No duplicate retains or forwards a host handle or authorization callback.
fn duplicate_directory(
    c: &mut Ctx,
    handle: u64,
    to: u64,
    out: u64,
    desired: u32,
    inherit: bool,
    options: u32,
) -> ApiResult {
    let fault = if out == 0 {
        None
    } else {
        probe(c, out, c.psize() as usize).err()
    };
    if c.psize() != 4 {
        if let Some(f) = fault {
            let guard = c.p.vm.take_guard(f.addr);
            return c.fail(
                if guard {
                    super::super::nt::status::STATUS_GUARD_PAGE_VIOLATION
                } else {
                    ERROR_NOACCESS
                },
                0,
            );
        }
        if out != 0 {
            c.write_ptr(out, 0)?;
        }
    }
    if to != 0 {
        if let Err(e) = process_handle(c, to) {
            return c.fail(e, 0);
        }
    }
    // The measured kernel rejects unknown desired-access bits before honoring
    // CLOSE_SOURCE. Authorization/privilege failures occur after that point.
    if options & 2 == 0
        && desired & !(0xF000_0000 | 0x0200_0000 | 0x0100_0000 | 0x0010_0000 | 0x000F_FFFF) != 0
    {
        if c.psize() == 4 {
            if let Some(f) = fault {
                let guard = c.p.vm.take_guard(f.addr);
                return c.fail(
                    if guard {
                        super::super::nt::status::STATUS_GUARD_PAGE_VIOLATION
                    } else {
                        ERROR_NOACCESS
                    },
                    0,
                );
            }
            if out != 0 {
                c.write_ptr(out, 0)?;
            }
        }
        return c.fail(ERROR_ACCESS_DENIED, 0);
    }
    let source_flags = c.p.objects.flags(handle).expect("selected directory flags");
    let inherit = if options & 4 != 0 {
        source_flags & 1 != 0
    } else {
        inherit
    };
    let id = c.p.objects.id(handle).expect("selected directory handle");
    let original =
        c.p.objects
            .access(handle)
            .expect("selected directory grant");
    let grant = if options & 2 != 0 {
        Ok(original)
    } else {
        match c.p.objects.obj(id) {
            Some(Object::Directory(d)) => d.grant(desired, true),
            Some(Object::SymbolicLink(l)) => l.grant(desired, true),
            Some(Object::ImageSection(s)) => match s.grant(desired, true) {
                Ok(grant) => Ok(grant),
                Err(crate::user::windows::object_namespace::SectionGrantError::Status(status)) => {
                    Err(status)
                }
                Err(crate::user::windows::object_namespace::SectionGrantError::Unavailable(
                    reason,
                )) => return Err(c.unsupported(reason)),
            },
            Some(Object::DataSection(s)) => s.grant(desired, true),
            Some(Object::FileSection(s)) => match s.grant(desired) {
                Ok(grant) => Ok(grant),
                Err(crate::user::windows::object_namespace::SectionGrantError::Status(status)) => {
                    Err(status)
                }
                Err(crate::user::windows::object_namespace::SectionGrantError::Unavailable(
                    reason,
                )) => return Err(c.unsupported(reason)),
            },
            _ => unreachable!("selected namespace resource"),
        }
    };
    // Protected native directory sources remain live, while duplication and
    // SAME_ATTRIBUTES still succeed. The flag does not deny the operation.
    let close = options & 1 != 0 && source_flags & 2 == 0;
    // Pin before closing the source. Its numeric slot may be reused by the new
    // handle, while the same directory object keeps its logical identity.
    if grant.is_ok() && to != 0 {
        if c.p.objects.retain_many(&[id]).is_err() {
            return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
        }
    }
    if close {
        if c.p.objects.close(handle).is_err() {
            if grant.is_ok() && to != 0 {
                c.p.objects.release(id);
            }
            return c.fail(ERROR_INVALID_HANDLE, 0);
        }
    }
    let result = if to == 0 {
        if close {
            Ok(None)
        } else {
            Err(ERROR_INVALID_PARAMETER)
        }
    } else {
        match grant {
            Err(s) => Err(super::super::nt::status_to_error(s)),
            Ok(grant) => {
                let h = c.p.objects.open_access(id, inherit, grant);
                if options & 4 != 0 {
                    if let Some(h) = h {
                        c.p.objects.set_flags(u64::from(h), 3, source_flags);
                    }
                }
                c.p.objects.release(id);
                h.map(Some).ok_or(ERROR_NOT_ENOUGH_MEMORY)
            }
        }
    };
    if c.psize() == 4 {
        if let Some(f) = fault {
            if let Ok(Some(h)) = &result {
                // Native copy-out cleanup cannot close a protected duplicate.
                // Its unreturned handle remains in the process-local table.
                let _ = c.p.objects.close(u64::from(*h));
            }
            let guard = c.p.vm.take_guard(f.addr);
            return c.fail(
                if guard {
                    super::super::nt::status::STATUS_GUARD_PAGE_VIOLATION
                } else {
                    ERROR_NOACCESS
                },
                0,
            );
        }
        if out != 0 {
            c.write_ptr(out, 0)?;
        }
    }
    match result {
        Err(e) => c.fail(e, 0),
        Ok(h) => {
            if out != 0 {
                if let Some(h) = h {
                    if let Err(e) = c.write_ptr(out, u64::from(h)) {
                        let _ = c.p.objects.close(u64::from(h));
                        return Err(e.into());
                    }
                }
            }
            Flow::bool(true)
        }
    }
}

fn get_information(c: &mut Ctx) -> ApiResult {
    let (handle, out) = (c.ptr(0)?, c.ptr(1)?);
    let Some(flags) = c.p.objects.flags(handle) else {
        return c.fail(ERROR_INVALID_HANDLE, 0);
    };
    c.mem().w32(out, flags)?;
    Flow::bool(true)
}

fn set_information(c: &mut Ctx) -> ApiResult {
    let (handle, mask, flags) = (c.ptr(0)?, c.u32(1)?, c.u32(2)?);
    if mask & !3 != 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    if !c.p.objects.set_flags(handle, mask, flags) {
        return c.fail(ERROR_INVALID_HANDLE, 0);
    }
    Flow::bool(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::arch::WinArch;
    use crate::user::windows::hle::{ApiErr, Item, Value};
    use crate::user::windows::process::{Proc, Thread, WindowsConfig, WindowsProcess};

    fn process(arch: WinArch) -> WindowsProcess {
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
        let mut cfg = WindowsConfig::new("handles.exe", vec![]);
        cfg.seed = Some(1);
        cfg.arena_bytes = 64 << 20;
        WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap()
    }

    fn call(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64]) -> ApiResult {
        let api = EXPORTS
            .iter()
            .find_map(|e| match &e.item {
                Item::Func(api) if api.name == name => Some(api),
                _ => None,
            })
            .unwrap();
        let sp = t.cpu.sp();
        for (i, &arg) in args.iter().enumerate() {
            match p.arch {
                WinArch::X86 => p.space.w32(sp + 4 + 4 * i as u64, arg as u32).unwrap(),
                WinArch::X64 if i < 4 => t.cpu.set_gpr([1, 2, 8, 9][i], arg),
                WinArch::X64 => p.space.w64(sp + 0x28 + 8 * (i - 4) as u64, arg).unwrap(),
                WinArch::Arm64 => t.cpu.set_gpr(i, arg),
            }
        }
        let mut c = Ctx {
            p,
            t,
            api,
            entry_pc: 0x1234,
            entry_sp: sp,
            ret_addr: 0,
            cursor: sp - 256,
        };
        (api.imp)(&mut c)
    }

    fn value(result: ApiResult) -> u64 {
        match result.unwrap() {
            Flow::Ret(Value::Int(v)) => v,
            _ => panic!("expected integer return"),
        }
    }

    #[test]
    fn duplicate_preserves_identity_grants_flags_and_rolls_back_output_faults() {
        for arch in WinArch::ALL {
            let mut process = process(arch);
            let p = process.state_mut();
            let tid = *p.threads.keys().next().unwrap();
            let mut t = p.threads.remove(&tid).unwrap();
            let id = p.objects.create(Object::Event {
                manual: true,
                signaled: 0,
            });
            let h = p.objects.open_access(id, false, 0x0010_0002).unwrap();
            let pseudo_process = if arch == WinArch::X86 {
                u64::from(u32::MAX)
            } else {
                u64::MAX
            };
            let out = t.cpu.sp() - 128;
            assert_eq!(
                value(call(
                    p,
                    &mut t,
                    "DuplicateHandle",
                    &[pseudo_process, h as u64, pseudo_process, out, 0, 1, 2]
                )),
                1
            );
            let d = p.space.ptr(out, arch.ptr_size()).unwrap();
            assert_eq!(p.objects.id(d), Some(id));
            assert_eq!(p.objects.access(d), Some(0x0010_0002));
            assert_eq!(p.objects.flags(d), Some(1));
            let before = p.objects.handle_count();
            assert!(matches!(
                call(
                    p,
                    &mut t,
                    "DuplicateHandle",
                    &[pseudo_process, h as u64, pseudo_process, 0, 0, 0, 2]
                ),
                Ok(Flow::Ret(Value::Int(1)))
            ));
            assert_eq!(
                p.objects.handle_count(),
                before + 1,
                "documented null-output compatibility branch"
            );
            let before = p.objects.handle_count();
            assert!(matches!(
                call(
                    p,
                    &mut t,
                    "DuplicateHandle",
                    &[pseudo_process, h as u64, pseudo_process, 0x1000, 0, 0, 2]
                ),
                Err(ApiErr::Fault(_))
            ));
            assert_eq!(p.objects.handle_count(), before);
            assert_eq!(
                value(call(p, &mut t, "SetHandleInformation", &[d, 2, 2])),
                1
            );
            assert_eq!(value(call(p, &mut t, "GetHandleInformation", &[d, out])), 1);
            assert_eq!(p.space.u32(out).unwrap(), 3);
            assert!(p.objects.close(d).is_err());
            p.threads.insert(tid, t);
        }
    }

    #[test]
    fn close_source_applies_on_output_fault_and_current_thread_becomes_real_handle() {
        for arch in WinArch::ALL {
            let mut process = process(arch);
            let p = process.state_mut();
            let tid = *p.threads.keys().next().unwrap();
            let mut t = p.threads.remove(&tid).unwrap();
            let h = p.objects.insert(Object::Null);
            let process_handle = if arch == WinArch::X86 {
                u64::from(u32::MAX)
            } else {
                u64::MAX
            };
            assert!(matches!(
                call(
                    p,
                    &mut t,
                    "DuplicateHandle",
                    &[process_handle, h as u64, process_handle, 0x1000, 0, 0, 3]
                ),
                Err(ApiErr::Fault(_))
            ));
            assert!(p.objects.id(h as u64).is_none());
            let out = t.cpu.sp() - 128;
            assert_eq!(
                value(call(
                    p,
                    &mut t,
                    "DuplicateHandle",
                    &[
                        process_handle,
                        process_handle - 1,
                        process_handle,
                        out,
                        0,
                        0,
                        2
                    ]
                )),
                1
            );
            let h = p.space.ptr(out, arch.ptr_size()).unwrap();
            assert_eq!(p.objects.id(h), Some(t.obj));
            assert!(matches!(p.objects.get(h), Some(Object::Thread { tid: v, .. }) if *v == tid));
            p.threads.insert(tid, t);
        }
    }
}
