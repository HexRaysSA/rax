//! Native DLL services whose numbers are independent of an NT syscall table.

use super::super::hle::{ApiResult, Archs, Arg::*, Conv::Stdcall, Ctx, Export, Flow};
use super::super::memory::Mem;
use super::super::nt::status::*;

mod access_check;
mod alert;
mod allocate;
mod alpc;
mod apphelp;
mod directory;
mod events;
mod file_attributes;
mod file_open;
mod file_write;
mod hotpatch;
mod io_completion;
mod memory_prefetch;
mod mutant;
mod named_object;
mod nls;
mod object_create;
mod performance_counter;
mod process_basic;
mod process_console;
mod process_mitigation;
mod process_query;
mod process_set;
mod process_tls;
mod process_token;
mod query;
mod raise;
mod read_memory;
mod registry;
mod section_create;
mod section_map;
mod secure_connect;
mod semaphore;
mod symbolic_link;
mod system_time;
mod thread_open;
mod thread_set;
mod timers;
mod token;
mod token_attributes;
mod token_query;
mod topology;
mod trace;
mod virtual_memory;
mod volume_query;
mod wait;
mod wait_packet;
mod wnf;
mod wnf_query;
mod worker_factory;
mod wow64_csr;

pub(super) static EXPORTS: &[Export] = &[
    Export::func(
        "NtWriteFile",
        Stdcall,
        &[Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, I32, Ptr, Ptr],
        file_write::write,
    ),
    Export::func(
        "NtAlpcSendWaitReceivePort",
        Stdcall,
        &[Ptr, I32, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr],
        alpc::send_wait_receive,
    ),
    Export::func(
        "NtOpenFile",
        Stdcall,
        &[Ptr, I32, Ptr, Ptr, I32, I32],
        file_open::open,
    ),
    Export::func(
        "NtQueryVolumeInformationFile",
        Stdcall,
        &[Ptr, Ptr, Ptr, I32, I32],
        volume_query::query,
    ),
    Export::func(
        "NtQueryAttributesFile",
        Stdcall,
        &[Ptr, Ptr],
        file_attributes::basic,
    ),
    Export::func(
        "NtQueryFullAttributesFile",
        Stdcall,
        &[Ptr, Ptr],
        file_attributes::full,
    ),
    Export::func(
        "NtCreateMutant",
        Stdcall,
        &[Ptr, I32, Ptr, I32],
        mutant::create,
    ),
    Export::func("NtOpenMutant", Stdcall, &[Ptr, I32, Ptr], mutant::open),
    Export::func("NtReleaseMutant", Stdcall, &[Ptr, Ptr], mutant::release),
    Export::func(
        "NtQueryMutant",
        Stdcall,
        &[Ptr, I32, Ptr, I32, Ptr],
        mutant::query,
    ),
    Export::func(
        "NtApphelpCacheControl",
        Stdcall,
        &[I32, Ptr],
        apphelp::control,
    ),
    Export::func("RtlNtStatusToDosError", Stdcall, &[I32], status_error),
    Export::func(
        "NtTerminateProcess",
        Stdcall,
        &[Ptr, I32],
        terminate_process,
    ),
    Export::func("NtTerminateThread", Stdcall, &[Ptr, I32], terminate_thread),
    Export::func("NtClose", Stdcall, &[Ptr], close),
    // Installed x86 leaf returns with RET12; the fourth PHNT parameter is
    // absent from that ABI. Native64 accepts the declared fourth unused slot.
    Export::func(
        "NtInitializeNlsFiles",
        Stdcall,
        &[Ptr, Ptr, Ptr],
        nls::initialize::initialize,
    )
    .only(Archs::X86),
    Export::func(
        "NtInitializeNlsFiles",
        Stdcall,
        &[Ptr, Ptr, Ptr, Ptr],
        nls::initialize::initialize,
    )
    .only(Archs::WIN64),
    Export::func(
        "NtConnectPort",
        Stdcall,
        &[Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr],
        secure_connect::connect_plain,
    ),
    Export::func(
        "NtSecureConnectPort",
        Stdcall,
        &[Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr],
        secure_connect::connect,
    ),
    Export::func(
        "NtCreateSection",
        Stdcall,
        &[Ptr, I32, Ptr, Ptr, I32, I32, Ptr],
        section_create::create,
    ),
    Export::func(
        "NtOpenDirectoryObject",
        Stdcall,
        &[Ptr, I32, Ptr],
        directory::open,
    ),
    Export::func(
        "NtOpenSymbolicLinkObject",
        Stdcall,
        &[Ptr, I32, Ptr],
        directory::open_link,
    ),
    Export::func(
        "NtQuerySymbolicLinkObject",
        Stdcall,
        &[Ptr, Ptr, Ptr],
        symbolic_link::query,
    ),
    Export::func(
        "NtAllocateVirtualMemory",
        Stdcall,
        &[Ptr, Ptr, Ptr, Ptr, I32, I32],
        alloc,
    ),
    Export::func("NtFreeVirtualMemory", Stdcall, &[Ptr, Ptr, Ptr, I32], free),
    Export::func(
        "NtAllocateVirtualMemoryEx",
        Stdcall,
        &[Ptr, Ptr, Ptr, I32, I32, Ptr, I32],
        allocate::extended,
    ),
    Export::func(
        "NtProtectVirtualMemory",
        Stdcall,
        &[Ptr, Ptr, Ptr, I32, Ptr],
        protect,
    ),
    Export::func("NtContinue", Stdcall, &[Ptr, I32], continue_context),
    Export::func("RtlCaptureContext", Stdcall, &[Ptr], capture_context),
    Export::func("NtRaiseException", Stdcall, &[Ptr, Ptr, I32], raise::raise),
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
        "NtQuerySystemInformationEx",
        Stdcall,
        &[I32, Ptr, I32, Ptr, I32, Ptr],
        topology::information,
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
        "NtTraceControl",
        Stdcall,
        &[I32, Ptr, I32, Ptr, I32, Ptr],
        trace::control,
    ),
    Export::func(
        "NtSetWnfProcessNotificationEvent",
        Stdcall,
        &[Ptr],
        wnf::register_event,
    ),
    Export::func(
        "NtSubscribeWnfStateChange",
        Stdcall,
        &[Ptr, I32, I32, Ptr],
        wnf::subscribe,
    ),
    Export::func(
        "NtUnsubscribeWnfStateChange",
        Stdcall,
        &[Ptr],
        wnf::unsubscribe,
    ),
    Export::func(
        "NtCreateIoCompletion",
        Stdcall,
        &[Ptr, I32, Ptr, I32],
        io_completion::create,
    ),
    Export::func(
        "NtCreateWorkerFactory",
        Stdcall,
        &[Ptr, I32, Ptr, Ptr, Ptr, Ptr, Ptr, I32, Ptr, Ptr],
        worker_factory::create,
    ),
    Export::func(
        "NtSetInformationWorkerFactory",
        Stdcall,
        &[Ptr, I32, Ptr, I32],
        worker_factory::set_information,
    ),
    Export::func(
        "NtCreateWaitCompletionPacket",
        Stdcall,
        &[Ptr, I32, Ptr],
        wait_packet::create,
    ),
    Export::func(
        "NtAssociateWaitCompletionPacket",
        Stdcall,
        &[Ptr, Ptr, Ptr, Ptr, Ptr, I32, Ptr, Ptr],
        wait_packet::associate,
    ),
    Export::func(
        "NtCancelWaitCompletionPacket",
        Stdcall,
        &[Ptr, I32],
        wait_packet::cancel,
    ),
    Export::func(
        "NtCreateTimer2",
        Stdcall,
        &[Ptr, Ptr, Ptr, I32, I32],
        timers::create,
    ),
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
    Export::func(
        "NtGetMUIRegistryInfo",
        Stdcall,
        &[I32, Ptr, Ptr],
        nls::mui::query,
    ),
    Export::func("NtUnmapViewOfSection", Stdcall, &[Ptr, Ptr], nls::unmap),
    Export::func(
        "NtQueryVirtualMemory",
        Stdcall,
        &[Ptr, Ptr, I32, Ptr, Ptr, Ptr],
        virtual_memory::query,
    ),
    Export::func(
        "NtSetInformationProcess",
        Stdcall,
        &[Ptr, I32, Ptr, I32],
        process_set::information,
    ),
    Export::func(
        "NtSetInformationThread",
        Stdcall,
        &[Ptr, I32, Ptr, I32],
        thread_set::information,
    ),
    Export::func(
        "NtOpenProcessToken",
        Stdcall,
        &[Ptr, I32, Ptr],
        process_token::open,
    ),
    Export::func(
        "NtOpenThreadToken",
        Stdcall,
        &[Ptr, I32, I32, Ptr],
        token::open_thread,
    ),
    Export::func(
        "NtOpenSection",
        Stdcall,
        &[Ptr, I32, Ptr],
        directory::open_section,
    ),
    Export::func(
        "NtMapViewOfSection",
        Stdcall,
        &[Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, I32, I32, I32],
        section_map::map,
    ),
    Export::func(
        "NtQueryPerformanceCounter",
        Stdcall,
        &[Ptr, Ptr],
        performance_counter::query,
    ),
    Export::func("NtQuerySystemTime", Stdcall, &[Ptr], system_time::query),
    Export::func("NtTestAlert", Stdcall, &[], alert::test),
    Export::func(
        "NtQueryInformationToken",
        Stdcall,
        &[Ptr, I32, Ptr, I32, Ptr],
        token_query::information,
    ),
    Export::func(
        "NtQuerySecurityAttributesToken",
        Stdcall,
        &[Ptr, Ptr, I32, Ptr, I32, Ptr],
        token_attributes::query,
    ),
    Export::func(
        "NtAccessCheck",
        Stdcall,
        &[Ptr, Ptr, I32, Ptr, Ptr, Ptr, Ptr, Ptr],
        access_check::access,
    ),
    Export::func(
        "NtQueryWnfStateData",
        Stdcall,
        &[Ptr, Ptr, Ptr, Ptr, Ptr, Ptr],
        wnf_query::query,
    ),
];

// Append this table after all existing NTDLL families to preserve their
// synthetic PE ordinals and trap addresses. Kernel lookup shares this table.
pub(super) static WAIT_EXPORTS: &[Export] = &[Export::func(
    "NtWaitForSingleObject",
    Stdcall,
    &[Ptr, I32, Ptr],
    wait::single,
)];
// Appended after the native wait table: existing ordinals and trap RVAs stay stable.
pub(super) static SEMAPHORE_EXPORTS: &[Export] = &[
    Export::func(
        "NtCreateSemaphore",
        Stdcall,
        &[Ptr, I32, Ptr, I32, I32],
        semaphore::create,
    ),
    Export::func(
        "NtOpenSemaphore",
        Stdcall,
        &[Ptr, I32, Ptr],
        semaphore::open,
    ),
    Export::func(
        "NtReleaseSemaphore",
        Stdcall,
        &[Ptr, I32, Ptr],
        semaphore::release,
    ),
    Export::func(
        "NtQuerySemaphore",
        Stdcall,
        &[Ptr, I32, Ptr, I32, Ptr],
        semaphore::query,
    ),
];

// Append after every prior family: existing ordinals and trap RVAs are stable.
pub(super) static TIMER2_EXPORTS: &[Export] = &[
    Export::func("NtSetTimer2", Stdcall, &[Ptr, Ptr, Ptr, Ptr], timers::set),
    Export::func("NtCancelTimer2", Stdcall, &[Ptr, Ptr], timers::cancel),
];

fn status_error(c: &mut Ctx) -> ApiResult {
    Flow::ret(u64::from(super::super::nt::status_to_error(c.u32(0)?)))
}
// Keep preceding synthetic PE ordinals and trap addresses unchanged.
pub(super) static READ_MEMORY_EXPORTS: &[Export] = &[Export::func(
    "NtReadVirtualMemory",
    Stdcall,
    &[Ptr, Ptr, Ptr, Ptr, Ptr],
    read_memory::read,
)];

// Separate tail table: retain every existing synthetic export ordinal.
pub(super) static PROCESSOR_FEATURE_EXPORTS: &[Export] = &[Export::func(
    "NtWow64IsProcessorFeaturePresent",
    Stdcall,
    &[I32],
    super::sysinfo::is_processor_feature_present,
)
.only(Archs::X86)];

// Append a new family so prior ordinals and native service trap slots survive.
pub(super) static NATIVE_SYSTEM_EXPORTS: &[Export] = &[Export::func(
    "NtWow64GetNativeSystemInformation",
    Stdcall,
    &[I32, Ptr, I32, Ptr],
    query::wow64_information,
)
.only(Archs::X86)];

// Tail family preserves existing synthetic export ordinals and trap slots.
// The installed x86 leaf takes five slots, including a scalar length, RET20.
pub(super) static WOW64_CSR_EXPORTS: &[Export] = &[Export::func(
    "NtWow64CsrClientConnectToServer",
    Stdcall,
    &[Ptr, I32, Ptr, I32, Ptr],
    wow64_csr::connect,
)
.only(Archs::X86)];

// Append to preserve all prior synthetic export ordinals and trap addresses.
pub(super) static THREAD_OPEN_EXPORTS: &[Export] = &[Export::func(
    "NtOpenThread",
    Stdcall,
    &[Ptr, I32, Ptr, Ptr],
    thread_open::open,
)];

// Append a family rather than moving existing synthetic ordinals/trap slots.
pub(super) static MEMORY_PREFETCH_EXPORTS: &[Export] = &[Export::func(
    "NtSetInformationVirtualMemory",
    Stdcall,
    &[Ptr, I32, Ptr, Ptr, Ptr, I32],
    memory_prefetch::set,
)];

// A tail family preserves every preceding synthetic ordinal and trap slot.
pub(super) static KEY_QUERY_EXPORTS: &[Export] = &[Export::func(
    "NtQueryKey",
    Stdcall,
    &[Ptr, I32, Ptr, I32, Ptr],
    registry::query_key,
)];

// Keep existing synthetic ordinals and trap slots stable.
pub(super) static KEY_OPEN_EX_EXPORTS: &[Export] = &[Export::func(
    "NtOpenKeyEx",
    Stdcall,
    &[Ptr, I32, Ptr, I32],
    registry::open_ex,
)];

// Append rather than changing prior synthetic ordinals or syscall slots.
pub(super) static KEY_ENUMERATION_EXPORTS: &[Export] = &[Export::func(
    "NtEnumerateKey",
    Stdcall,
    &[Ptr, I32, I32, Ptr, I32, Ptr],
    registry::enumerate_key,
)];

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
    if c.p.objects.assigned_desktop_handle(handle) {
        return Flow::ret(STATUS_HANDLE_NOT_CLOSABLE.into());
    }
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
            if e == super::super::memory::VmError::NotCommitted
                && c.p
                    .vm
                    .intersects_image_extension(base, base.saturating_add(size))
            {
                c.mem().w32(old_ptr, super::super::memory::prot::NOACCESS)?;
            }
            if c.p.vm.is_nls_view(base) && e == super::super::memory::VmError::InvalidProtection
                || c.p.vm.is_data_view(base)
                    && matches!(
                        e,
                        super::super::memory::VmError::SectionProtection
                            | super::super::memory::VmError::InvalidParameter4
                    )
            {
                c.mem().w32(old_ptr, super::super::memory::prot::NOACCESS)?;
            }
            Flow::ret(e.status().into())
        }
    }
}
fn continue_context(c: &mut Ctx) -> ApiResult {
    // NT BOOLEAN is eight bits. Validate the complete context before any alert
    // or queue mutation; dispatch applies it before starting an APC frame.
    let test_alert = c.u32(1)? as u8 != 0;
    let address = c.ptr(0)?;
    if address % super::super::context::RegContext::align(c.arch()) != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let context = super::super::context::RegContext::read(c.mem(), c.arch(), address)?;
    if let Err(status) = context.validate(&c.t.cpu) {
        return Flow::ret(status.into());
    }
    Ok(if test_alert {
        Flow::ResumeAlertable(Box::new(context))
    } else {
        Flow::Resume(Box::new(context))
    })
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
    fn ntcontinue_validates_state_before_selecting_context_resume_and_alert_check() {
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
            continue_context(&mut c).unwrap(),
            Flow::ResumeAlertable(_)
        ));
        c.t.cpu.set_gpr(2, 0);
        c.t.cpu.set_gpr(1, u64::MAX - 15);
        assert!(matches!(continue_context(&mut c), Err(ApiErr::Fault(_))));
    }
}
