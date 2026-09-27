//! Win32 process, virtual-memory, heap, loader, console, and TLS services.

use super::super::heap::{HEAP_GENERATE_EXCEPTIONS, HeapError};
use super::super::hle::{ApiResult, Arg::*, Conv::Stdcall, Ctx, Export, Flow};
use super::super::layout::offsets;
use super::super::memory::Mem;
use super::super::nt::error::*;

pub(super) static EXPORTS: &[Export] = &[
    Export::func("ExitProcess", Stdcall, &[I32], exit_process),
    Export::func("ExitThread", Stdcall, &[I32], exit_thread),
    Export::func("TerminateProcess", Stdcall, &[Ptr, I32], terminate_process),
    Export::func("GetLastError", Stdcall, &[], get_last_error),
    Export::func("SetLastError", Stdcall, &[I32], set_last_error),
    Export::func("GetCurrentProcess", Stdcall, &[], current_process),
    Export::func("GetCurrentThread", Stdcall, &[], current_thread),
    Export::func("GetCurrentProcessId", Stdcall, &[], process_id),
    Export::func("GetCurrentThreadId", Stdcall, &[], thread_id),
    Export::func(
        "VirtualAlloc",
        Stdcall,
        &[Ptr, Ptr, I32, I32],
        virtual_alloc,
    ),
    Export::func("VirtualFree", Stdcall, &[Ptr, Ptr, I32], virtual_free),
    Export::func(
        "VirtualProtect",
        Stdcall,
        &[Ptr, Ptr, I32, Ptr],
        virtual_protect,
    ),
    Export::func("VirtualQuery", Stdcall, &[Ptr, Ptr, Ptr], virtual_query),
    Export::func(
        "FlushInstructionCache",
        Stdcall,
        &[Ptr, Ptr, Ptr],
        flush_icache,
    ),
    Export::func("GetProcessHeap", Stdcall, &[], process_heap),
    Export::func("HeapCreate", Stdcall, &[I32, Ptr, Ptr], heap_create),
    Export::func("HeapDestroy", Stdcall, &[Ptr], heap_destroy),
    Export::func("HeapAlloc", Stdcall, &[Ptr, I32, Ptr], heap_alloc),
    Export::func("HeapFree", Stdcall, &[Ptr, I32, Ptr], heap_free),
    Export::func("HeapSize", Stdcall, &[Ptr, I32, Ptr], heap_size),
    Export::func("HeapReAlloc", Stdcall, &[Ptr, I32, Ptr, Ptr], heap_realloc),
    Export::func("GetStdHandle", Stdcall, &[I32], get_std_handle),
    Export::func("SetStdHandle", Stdcall, &[I32, Ptr], set_std_handle),
    Export::func("GetCommandLineW", Stdcall, &[], command_line_w),
    Export::func("GetCommandLineA", Stdcall, &[], command_line_a),
    Export::func("TlsAlloc", Stdcall, &[], tls_alloc),
    Export::func("TlsFree", Stdcall, &[I32], tls_free),
    Export::func("TlsGetValue", Stdcall, &[I32], tls_get),
    Export::func("TlsSetValue", Stdcall, &[I32, Ptr], tls_set),
    Export::func("GetTickCount", Stdcall, &[], tick_count),
    Export::func("GetTickCount64", Stdcall, &[], tick_count64),
    Export::func(
        "QueryPerformanceCounter",
        Stdcall,
        &[Ptr],
        performance_counter,
    ),
    Export::func(
        "QueryPerformanceFrequency",
        Stdcall,
        &[Ptr],
        performance_frequency,
    ),
    Export::func("IsDebuggerPresent", Stdcall, &[], is_debugger_present),
    Export::func(
        "RaiseException",
        Stdcall,
        &[I32, I32, I32, Ptr],
        raise_exception,
    ),
    Export::func("SetUnhandledExceptionFilter", Stdcall, &[Ptr], set_filter),
    Export::func("AddVectoredExceptionHandler", Stdcall, &[I32, Ptr], add_veh),
    Export::func(
        "RemoveVectoredExceptionHandler",
        Stdcall,
        &[Ptr],
        remove_veh,
    ),
];

fn exit_process(c: &mut Ctx) -> ApiResult {
    Ok(Flow::ExitProcess(c.u32(0)?))
}
fn exit_thread(c: &mut Ctx) -> ApiResult {
    Ok(Flow::ExitThread(c.u32(0)?))
}
fn terminate_process(c: &mut Ctx) -> ApiResult {
    let (handle, code) = (c.ptr(0)?, c.u32(1)?);
    if handle == c.arch().ptr(u64::MAX) {
        return Ok(Flow::TerminateProcess(code));
    }
    match c.p.objects.get(handle) {
        Some(super::super::objects::Object::Process { pid, exit_code }) if *pid == c.p.pid => {
            if exit_code.is_some() || c.p.objects.access(handle).unwrap_or(0) & 1 == 0 {
                return c.fail(ERROR_ACCESS_DENIED, 0);
            }
            Ok(Flow::TerminateProcess(code))
        }
        _ => c.fail(ERROR_INVALID_HANDLE, 0),
    }
}
fn get_last_error(c: &mut Ctx) -> ApiResult {
    Flow::ret(u64::from(c.last_error()?))
}
fn set_last_error(c: &mut Ctx) -> ApiResult {
    c.set_last_error(c.u32(0)?)?;
    Flow::void()
}
fn current_process(_: &mut Ctx) -> ApiResult {
    Flow::ret(u64::MAX)
}
fn current_thread(_: &mut Ctx) -> ApiResult {
    Flow::ret(u64::MAX - 1)
}
fn process_id(c: &mut Ctx) -> ApiResult {
    Flow::ret(u64::from(c.p.pid))
}
fn thread_id(c: &mut Ctx) -> ApiResult {
    Flow::ret(u64::from(c.t.tid))
}
fn virtual_alloc(c: &mut Ctx) -> ApiResult {
    let (base, size, flags, protect) = (c.ptr(0)?, c.ptr(1)?, c.u32(2)?, c.u32(3)?);
    match c
        .p
        .vm
        .allocate((base != 0).then_some(base), size, flags, protect)
    {
        Ok((addr, _)) => Flow::ret(addr),
        Err(e) => c.fail(super::super::nt::status_to_error(e.status()), 0),
    }
}
fn virtual_free(c: &mut Ctx) -> ApiResult {
    let (base, size, flags) = (c.ptr(0)?, c.ptr(1)?, c.u32(2)?);
    match c.p.vm.free(base, size, flags) {
        Ok(_) => Flow::bool(true),
        Err(e) => c.fail(super::super::nt::status_to_error(e.status()), 0),
    }
}
fn virtual_protect(c: &mut Ctx) -> ApiResult {
    let (addr, size, protect, old) = (c.ptr(0)?, c.ptr(1)?, c.u32(2)?, c.ptr(3)?);
    // Validate the output before mutating page protections.
    let bytes = c.mem().bytes(old, 4)?;
    c.mem().wr(old, &bytes)?;
    match c.p.vm.protect(addr, size, protect) {
        Ok(value) => {
            c.mem().w32(old, value)?;
            Flow::bool(true)
        }
        Err(e) => c.fail(super::super::nt::status_to_error(e.status()), 0),
    }
}
fn virtual_query(c: &mut Ctx) -> ApiResult {
    let (addr, out, len) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?);
    let size = if c.arch().is64() { 48 } else { 28 };
    if len < size {
        return c.fail(ERROR_BAD_LENGTH, 0);
    }
    let Some(r) = c.p.vm.query(addr) else {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    };
    let mut bytes = vec![0; size as usize];
    let mut put = |off: usize, value: u64, width: usize| {
        bytes[off..off + width].copy_from_slice(&value.to_le_bytes()[..width])
    };
    if c.arch().is64() {
        put(0, r.base, 8);
        put(8, r.allocation_base, 8);
        put(16, r.allocation_protect.into(), 4);
        put(24, r.size, 8);
        put(32, r.state.into(), 4);
        put(36, r.protect.into(), 4);
        put(40, r.kind.into(), 4);
    } else {
        put(0, r.base, 4);
        put(4, r.allocation_base, 4);
        put(8, r.allocation_protect.into(), 4);
        put(12, r.size, 4);
        put(16, r.state.into(), 4);
        put(20, r.protect.into(), 4);
        put(24, r.kind.into(), 4);
    }
    c.mem().wr(out, &bytes)?;
    Flow::ret(size)
}
fn flush_icache(c: &mut Ctx) -> ApiResult {
    let handle = c.ptr(0)?;
    if handle != c.arch().ptr(u64::MAX) {
        return c.fail(ERROR_INVALID_HANDLE, 0);
    }
    // All CPU adapters consume AddressSpace's executable-write epochs on resume.
    Flow::bool(true)
}
fn process_heap(c: &mut Ctx) -> ApiResult {
    Flow::ret(c.p.process_heap)
}
fn heap_create(c: &mut Ctx) -> ApiResult {
    let (flags, initial, maximum) = (c.u32(0)?, c.ptr(1)?, c.ptr(2)?);
    match c.p.heaps.create(&mut c.p.vm, flags, initial, maximum) {
        Some(handle) => Flow::ret(handle),
        None => c.fail(ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}
fn heap_destroy(c: &mut Ctx) -> ApiResult {
    let handle = c.ptr(0)?;
    if handle == c.p.process_heap {
        return c.fail(ERROR_INVALID_HANDLE, 0);
    }
    Flow::bool(c.p.heaps.destroy(&mut c.p.vm, handle))
}
fn heap_alloc(c: &mut Ctx) -> ApiResult {
    let (handle, flags, size) = (c.ptr(0)?, c.u32(1)?, c.ptr(2)?);
    let result =
        c.p.heaps
            .alloc_checked(&mut c.p.vm, handle, size, flags & 8 != 0);
    match result {
        Ok(addr) => Flow::ret(addr),
        Err(HeapError::MemoryFault(fault)) => Err(fault.into()),
        Err(HeapError::BadHeap | HeapError::BadBlock) => Ok(Flow::TerminateProcess(
            super::super::nt::status::STATUS_HEAP_CORRUPTION,
        )),
        Err(HeapError::NoMemory) => heap_failure(c, handle, flags),
    }
}

fn heap_failure(c: &mut Ctx, heap: u64, flags: u32) -> ApiResult {
    if (flags | c.p.heaps.flags(heap).unwrap_or(0)) & HEAP_GENERATE_EXCEPTIONS != 0 {
        Ok(Flow::Raise(super::super::context::ExceptionRecord::new(
            super::super::nt::status::STATUS_NO_MEMORY,
            0,
            Vec::new(),
        )))
    } else {
        // HeapAlloc/HeapReAlloc do not set the calling thread's last error.
        Flow::ret(0)
    }
}
fn heap_free(c: &mut Ctx) -> ApiResult {
    let (heap, addr) = (c.ptr(0)?, c.ptr(2)?);
    if addr == 0 {
        return Flow::bool(true);
    }
    match c.p.heaps.free(heap, addr) {
        Ok(()) => Flow::bool(true),
        Err(_) => Ok(Flow::TerminateProcess(
            super::super::nt::status::STATUS_HEAP_CORRUPTION,
        )),
    }
}
fn heap_size(c: &mut Ctx) -> ApiResult {
    let (heap, addr) = (c.ptr(0)?, c.ptr(2)?);
    Flow::ret(c.p.heaps.size(heap, addr).unwrap_or(u64::MAX))
}
fn heap_realloc(c: &mut Ctx) -> ApiResult {
    let (heap, flags, addr, size) = (c.ptr(0)?, c.u32(1)?, c.ptr(2)?, c.ptr(3)?);
    match c.p.heaps.realloc(
        &mut c.p.vm,
        heap,
        addr,
        size,
        flags & 0x10 != 0,
        flags & 8 != 0,
    ) {
        Ok(value) => Flow::ret(value),
        Err(HeapError::MemoryFault(fault)) => Err(fault.into()),
        Err(HeapError::BadHeap | HeapError::BadBlock) => Ok(Flow::TerminateProcess(
            super::super::nt::status::STATUS_HEAP_CORRUPTION,
        )),
        Err(HeapError::NoMemory) => heap_failure(c, heap, flags),
    }
}
fn std_offset(c: &Ctx, value: u32) -> Option<u64> {
    let o = offsets(c.arch());
    match value {
        0xFFFF_FFF6 => Some(o.pp_std_input),
        0xFFFF_FFF5 => Some(o.pp_std_output),
        0xFFFF_FFF4 => Some(o.pp_std_error),
        _ => None,
    }
}
fn get_std_handle(c: &mut Ctx) -> ApiResult {
    let value = c.u32(0)?;
    let Some(off) = std_offset(c, value) else {
        return c.fail(ERROR_INVALID_PARAMETER, u64::MAX);
    };
    Flow::ret(c.read_ptr(c.p.params + off)?)
}
fn set_std_handle(c: &mut Ctx) -> ApiResult {
    let (value, handle) = (c.u32(0)?, c.ptr(1)?);
    let Some(off) = std_offset(c, value) else {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    };
    c.write_ptr(c.p.params + off, handle)?;
    Flow::bool(true)
}
fn command_line_w(c: &mut Ctx) -> ApiResult {
    Flow::ret(c.read_ptr(c.p.params + offsets(c.arch()).pp_command_line + c.psize())?)
}
fn command_line_a(c: &mut Ctx) -> ApiResult {
    let address = c.read_ptr(c.p.params + offsets(c.arch()).pp_command_line + c.psize())?;
    let wide = c.mem().wstr(address, 32768)?;
    // The personality's current ANSI code page is Windows-1252.
    let text = String::from_utf16_lossy(&wide);
    if !text.is_ascii() {
        return Err(c.unsupported("non-ASCII ANSI command line conversion"));
    }
    let Some(out) =
        c.p.heaps
            .alloc(&mut c.p.vm, c.p.process_heap, text.len() as u64 + 1, false)
    else {
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
    };
    c.mem().put_cstr(out, text.as_bytes())?;
    Flow::ret(out)
}
fn tls_alloc(c: &mut Ctx) -> ApiResult {
    Flow::ret(c.p.tls.alloc().map_or(0xFFFF_FFFF, u64::from))
}
/// TLS array addressing follows the guest pointer width. x86 effective-address
/// addition wraps at 32 bits; a wrapped address is still checked by Mem, even
/// when it is zero. On 64-bit guests overflow is an inaccessible address, not
/// a host integer overflow. `write` describes the subsequent slot access.
fn tls_expansion_address(
    arch: super::super::arch::WinArch,
    array: u64,
    slot: u32,
    write: bool,
) -> Result<u64, super::super::memory::MemFault> {
    let fault = super::super::memory::MemFault {
        addr: u64::MAX,
        write,
    };
    let offset = u64::from(slot.checked_sub(64).ok_or(fault)?) * arch.ptr_size();
    if arch == super::super::arch::WinArch::X86 {
        Ok(u64::from((array as u32).wrapping_add(offset as u32)))
    } else {
        array.checked_add(offset).ok_or(fault)
    }
}

fn tls_slot(
    c: &mut Ctx,
    slot: u32,
    allocate: bool,
    write: bool,
) -> Result<Option<u64>, super::super::hle::ApiErr> {
    let o = offsets(c.arch());
    if slot < 64 {
        return Ok(Some(c.t.teb + o.teb_tls_slots + u64::from(slot) * o.ptr));
    }
    let pointer = c.t.teb + o.teb_tls_expansion_slots;
    let mut array = c.read_ptr(pointer)?;
    if array == 0 && allocate {
        // Host-tracked addresses, not mutable guest TLS pointers, determine
        // thread teardown. Reserve tracking capacity before publication.
        c.t.tls_blocks.try_reserve(1).map_err(|_| {
            super::super::hle::ApiErr::Raise(super::super::context::ExceptionRecord::new(
                super::super::nt::status::STATUS_NO_MEMORY,
                c.entry_pc,
                vec![],
            ))
        })?;
        array =
            c.p.heaps
                .alloc_checked(&mut c.p.vm, c.p.process_heap, 1024 * o.ptr, true)
                .map_err(|error| match error {
                    HeapError::MemoryFault(fault) => super::super::hle::ApiErr::Fault(fault),
                    HeapError::NoMemory => super::super::hle::ApiErr::Raise(
                        super::super::context::ExceptionRecord::new(
                            super::super::nt::status::STATUS_NO_MEMORY,
                            c.entry_pc,
                            vec![],
                        ),
                    ),
                    _ => super::super::hle::ApiErr::Internal("invalid process heap for TLS".into()),
                })?;
        if let Err(fault) = c.write_ptr(pointer, array) {
            // This block has not been published to the guest TEB or any
            // other TLS owner. Keep a failed publication from leaking it.
            let _ = c.p.heaps.free(c.p.process_heap, array);
            return Err(fault.into());
        }
        c.t.tls_blocks.push(array);
    }
    Ok(if array == 0 {
        None
    } else {
        Some(tls_expansion_address(c.arch(), array, slot, write)?)
    })
}
fn tls_free(c: &mut Ctx) -> ApiResult {
    let slot = c.u32(0)?;
    if !c.p.tls.free(slot) {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let o = offsets(c.arch());
    if let Some(address) = tls_slot(c, slot, false, true)? {
        c.write_ptr(address, 0)?;
    }
    for thread in c.p.threads.values() {
        let address = if slot < 64 {
            Some(thread.teb + o.teb_tls_slots + u64::from(slot) * o.ptr)
        } else {
            let array = c.read_ptr(thread.teb + o.teb_tls_expansion_slots)?;
            if array == 0 {
                None
            } else {
                Some(tls_expansion_address(c.arch(), array, slot, true)?)
            }
        };
        if let Some(address) = address {
            c.write_ptr(address, 0)?;
        }
    }
    Flow::bool(true)
}
fn tls_get(c: &mut Ctx) -> ApiResult {
    let slot = c.u32(0)?;
    if !c.p.tls.allocated(slot) {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let value = match tls_slot(c, slot, false, false)? {
        None => 0,
        Some(address) => c.read_ptr(address)?,
    };
    c.set_last_error(0)?;
    Flow::ret(value)
}
fn tls_set(c: &mut Ctx) -> ApiResult {
    let (slot, value) = (c.u32(0)?, c.ptr(1)?);
    if !c.p.tls.allocated(slot) {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let address = tls_slot(c, slot, true, true)?.ok_or_else(|| {
        super::super::hle::ApiErr::Internal("TLS expansion allocation was not published".into())
    })?;
    c.write_ptr(address, value)?;
    Flow::bool(true)
}
fn tick_count(c: &mut Ctx) -> ApiResult {
    Flow::ret(c.p.uptime_ms() as u32 as u64)
}
fn tick_count64(c: &mut Ctx) -> ApiResult {
    Flow::ret64(c.p.uptime_ms())
}
fn performance_counter(c: &mut Ctx) -> ApiResult {
    let out = c.ptr(0)?;
    c.mem()
        .w64(out, c.p.start_time.elapsed().as_nanos() as u64)?;
    Flow::bool(true)
}
fn performance_frequency(c: &mut Ctx) -> ApiResult {
    let out = c.ptr(0)?;
    c.mem().w64(out, 1_000_000_000)?;
    Flow::bool(true)
}
fn is_debugger_present(_: &mut Ctx) -> ApiResult {
    Flow::bool(false)
}
fn raise_exception(c: &mut Ctx) -> ApiResult {
    let (code, flags, count, args) = (c.u32(0)?, c.u32(1)?, c.u32(2)?, c.ptr(3)?);
    if count > 15 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let mut values = Vec::new();
    for i in 0..count {
        values.push(c.read_ptr(args + u64::from(i) * c.psize())?);
    }
    let mut record = super::super::context::ExceptionRecord::new(code, c.entry_pc + 8, values);
    record.flags = flags & 1;
    Ok(Flow::Raise(record))
}
fn set_filter(c: &mut Ctx) -> ApiResult {
    let handler = c.ptr(0)?;
    let prev = std::mem::replace(&mut c.p.seh.unhandled_filter, handler);
    Flow::ret(prev)
}
fn add_veh(c: &mut Ctx) -> ApiResult {
    let (first, handler) = (c.u32(0)? != 0, c.ptr(1)?);
    c.p.seh.next_handle += 4;
    let handle = c.p.seh.next_handle;
    if first {
        c.p.seh.veh.insert(0, (handle, handler));
    } else {
        c.p.seh.veh.push((handle, handler));
    }
    Flow::ret(handle)
}
fn remove_veh(c: &mut Ctx) -> ApiResult {
    let handle = c.ptr(0)?;
    let old = c.p.seh.veh.len();
    c.p.seh.veh.retain(|(h, _)| *h != handle);
    Flow::bool(c.p.seh.veh.len() != old)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::hle::{Item, Value};
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};

    #[test]
    fn terminate_process_checks_current_handles_and_remains_distinct_from_exit_all_abis() {
        use crate::user::windows::arch::WinArch;
        use crate::user::windows::objects::Object;
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
            let current = p.objects.create(Object::Process {
                pid: p.pid,
                exit_code: None,
            });
            let granted = p.objects.open_access(current, false, 1).unwrap();
            let denied = p.objects.open_access(current, false, 0).unwrap();
            let dead = p.objects.insert(Object::Process {
                pid: p.pid,
                exit_code: Some(1),
            });
            let foreign = p.objects.insert(Object::Process {
                pid: p.pid + 1,
                exit_code: None,
            });
            let wrong = p.objects.insert(Object::Event {
                manual: true,
                signaled: false,
            });
            let api = |name| {
                EXPORTS
                    .iter()
                    .find_map(|e| match &e.item {
                        Item::Func(api) if api.name == name => Some(api),
                        _ => None,
                    })
                    .unwrap()
            };
            for (handle, error) in [
                (arch.ptr(u64::MAX), None),
                (u64::from(granted), None),
                (u64::from(denied), Some(ERROR_ACCESS_DENIED)),
                (u64::from(dead), Some(ERROR_ACCESS_DENIED)),
                (u64::from(foreign), Some(ERROR_INVALID_HANDLE)),
                (u64::from(wrong), Some(ERROR_INVALID_HANDLE)),
                (0, Some(ERROR_INVALID_HANDLE)),
            ] {
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
                    api: api("TerminateProcess"),
                    entry_pc: 0,
                    entry_sp: sp,
                    ret_addr: 0,
                    cursor: sp,
                };
                c.set_last_error(0x1234_5678).unwrap();
                let flow = terminate_process(&mut c).unwrap();
                if let Some(error) = error {
                    assert!(matches!(flow, Flow::Ret(Value::Int(0))), "{arch}");
                    assert_eq!(c.last_error().unwrap(), error);
                } else {
                    assert!(
                        matches!(flow, Flow::TerminateProcess(0xDEAD_BEEF)),
                        "{arch}"
                    );
                    assert_eq!(c.last_error().unwrap(), 0x1234_5678);
                }
            }
            match arch {
                WinArch::X86 => p.space.w32(sp + 4, 0xDEAD_BEEF).unwrap(),
                WinArch::X64 => t.cpu.set_gpr(1, 0xDEAD_BEEF),
                WinArch::Arm64 => t.cpu.set_gpr(0, 0xDEAD_BEEF),
            }
            let mut c = Ctx {
                p,
                t: &mut t,
                api: api("ExitProcess"),
                entry_pc: 0,
                entry_sp: sp,
                ret_addr: 0,
                cursor: sp,
            };
            assert!(
                matches!(
                    exit_process(&mut c).unwrap(),
                    Flow::ExitProcess(0xDEAD_BEEF)
                ),
                "{arch}"
            );
            assert!(c.p.exit_code.is_none());
        }
    }

    #[test]
    fn tls_expansion_address_uses_guest_width_and_checked_64_bit_addition() {
        use crate::user::windows::arch::WinArch;
        use crate::user::windows::memory::MemFault;

        for write in [false, true] {
            for arch in [WinArch::X64, WinArch::Arm64] {
                assert_eq!(
                    tls_expansion_address(arch, u64::MAX, 65, write),
                    Err(MemFault {
                        addr: u64::MAX,
                        write
                    })
                );
                assert_eq!(
                    tls_expansion_address(arch, 0x10000, 1087, write),
                    Ok(0x11FF8)
                );
            }
            assert_eq!(
                tls_expansion_address(WinArch::X86, 0xFFFF_FFFC, 65, write),
                Ok(0)
            );
            assert_eq!(
                tls_expansion_address(WinArch::X86, 0xFFFF_FFF8, 67, write),
                Ok(4)
            );
        }
    }

    #[test]
    fn forged_tls_pointer_faults_and_failed_expansion_publication_frees_block() {
        use crate::user::windows::arch::WinArch;
        use crate::user::windows::hle::ApiErr;
        use crate::user::windows::memory::{MemFault, prot};

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
            let mut config = WindowsConfig::new("tls-api-test.exe", Vec::new());
            config.seed = Some(1);
            config.arena_bytes = 64 << 20;
            let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
            let p = process.state_mut();
            for slot in 0..=65 {
                assert_eq!(p.tls.alloc(), Some(slot));
            }
            let tid = *p.threads.keys().next().unwrap();
            let mut t = p.threads.remove(&tid).unwrap();
            let api = |name| {
                EXPORTS
                    .iter()
                    .find_map(|export| match &export.item {
                        Item::Func(api) if api.name == name => Some(api),
                        _ => None,
                    })
                    .unwrap()
            };
            let pointer = t.teb + offsets(arch).teb_tls_expansion_slots;
            let forged = if arch == WinArch::X86 {
                0xFFFF_FFFC
            } else {
                u64::MAX
            };
            let fault_addr = if arch == WinArch::X86 { 0 } else { u64::MAX };
            p.space.wptr(pointer, arch.ptr_size(), forged).unwrap();
            let sp = t.cpu.sp();
            match arch {
                WinArch::X86 => {
                    p.space.w32(sp + 4, 65).unwrap();
                    p.space.w32(sp + 8, 0x1234).unwrap();
                }
                WinArch::X64 => {
                    t.cpu.set_gpr(1, 65);
                    t.cpu.set_gpr(2, 0x1234);
                }
                WinArch::Arm64 => {
                    t.cpu.set_gpr(0, 65);
                    t.cpu.set_gpr(1, 0x1234);
                }
            }
            let mut c = Ctx {
                p,
                t: &mut t,
                api: api("TlsGetValue"),
                entry_pc: 0,
                entry_sp: sp,
                ret_addr: 0,
                cursor: sp,
            };
            assert!(
                matches!(tls_get(&mut c), Err(ApiErr::Fault(MemFault { addr, write: false })) if addr == fault_addr)
            );
            c.api = api("TlsSetValue");
            assert!(
                matches!(tls_set(&mut c), Err(ApiErr::Fault(MemFault { addr, write: true })) if addr == fault_addr)
            );

            // The expansion pointer is readable but cannot be published.
            c.write_ptr(pointer, 0).unwrap();
            let before = c.p.heaps.blocks(c.p.process_heap);
            c.p.vm
                .protect(pointer, arch.ptr_size(), prot::READONLY)
                .unwrap();
            assert!(
                matches!(tls_set(&mut c), Err(ApiErr::Fault(MemFault { addr, write: true })) if addr == pointer)
            );
            assert_eq!(
                c.p.heaps.blocks(c.p.process_heap),
                before,
                "{arch}: unpublished expansion block leaked"
            );
            assert_eq!(c.read_ptr(pointer).unwrap(), 0);

            c.p.vm
                .protect(pointer, arch.ptr_size(), prot::READWRITE)
                .unwrap();
            c.write_ptr(pointer, forged).unwrap();
            c.api = api("TlsFree");
            assert!(
                matches!(tls_free(&mut c), Err(ApiErr::Fault(MemFault { addr, write: true })) if addr == fault_addr)
            );
        }
    }

    #[test]
    fn heap_failure_honors_call_and_creation_exception_flags_without_last_error() {
        let mut config = WindowsConfig::new("heap-api-test.exe", Vec::new());
        config.seed = Some(1);
        config.arena_bytes = 64 << 20;
        let mut process = WindowsProcess::spawn_image(
            config,
            include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe").to_vec(),
        )
        .unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let api = EXPORTS
            .iter()
            .find_map(|export| match &export.item {
                Item::Func(api) if api.name == "HeapAlloc" => Some(api),
                _ => None,
            })
            .unwrap();
        let inherited = p
            .heaps
            .create(&mut p.vm, HEAP_GENERATE_EXCEPTIONS, 0, 0)
            .unwrap();
        for (heap, flags, exception) in [
            (p.process_heap, 0, false),
            (p.process_heap, HEAP_GENERATE_EXCEPTIONS, true),
            (inherited, 0, true),
        ] {
            t.cpu.set_gpr(1, heap);
            t.cpu.set_gpr(2, u64::from(flags));
            t.cpu.set_gpr(8, u64::MAX);
            let sp = t.cpu.sp();
            let mut context = Ctx {
                p,
                t: &mut t,
                api,
                entry_pc: 0,
                entry_sp: sp,
                ret_addr: 0,
                cursor: sp,
            };
            context.set_last_error(0x1234_5678).unwrap();
            match heap_alloc(&mut context).unwrap() {
                Flow::Raise(record) if exception => {
                    assert_eq!(
                        record.code,
                        super::super::super::nt::status::STATUS_NO_MEMORY
                    );
                }
                Flow::Ret(Value::Int(0)) if !exception => {}
                _ => panic!("incorrect allocation failure flow"),
            }
            assert_eq!(context.last_error().unwrap(), 0x1234_5678);
        }

        p.vm.protect(t.teb, 0x1000, super::super::super::memory::prot::NOACCESS)
            .unwrap();
        let sp = t.cpu.sp();
        let mut context = Ctx {
            p,
            t: &mut t,
            api,
            entry_pc: 0,
            entry_sp: sp,
            ret_addr: 0,
            cursor: sp,
        };
        assert!(context.last_error().is_err());
        assert!(context.set_last_error(0).is_err());
        assert!(context.fail(ERROR_INVALID_PARAMETER, 0).is_err());
    }
}
