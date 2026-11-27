//! Portable GameOS system services.
//!
//! The guest system and title partitions share the emulator's memory budget.
//! Named tools partitions and operations that change memory ownership are absent.

pub(super) mod wnf;

use super::super::{
    WinArch,
    hle::{ApiErr, ApiResult, Archs, Arg::*, Conv::Stdcall, Ctx, Export, Flow},
    memory::{Mem, MemFault},
    nt::error::{
        ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER,
        ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_SUPPORTED,
    },
    nt::status::*,
    objects::Object,
    process::thread::UserApc,
};
use crate::error::MemoryAccessKind;
use crate::user::mm::PAGE_SIZE;

const SE_LOCK_MEMORY: u32 = 4;
const RTL_ACQUIRE_PRIVILEGE_PROCESS: u32 = 2;
const PARTITION_QUERY_ACCESS: u32 = 1;
const PARTITION_ALL_ACCESS: u32 = 0x001f_0003;
const OBJ_INHERIT: u32 = 2;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const CONFIGURATION_BYTES: usize = 0xf0;

pub(super) static EXPORTS: &[Export] = &[
    Export::func(
        "RtlAcquirePrivilege",
        Stdcall,
        &[Ptr, I32, I32, Ptr],
        acquire,
    )
    .only(Archs::X64),
    Export::func("RtlReleasePrivilege", Stdcall, &[Ptr], release).only(Archs::X64),
    Export::func("NtOpenPartition", Stdcall, &[Ptr, I32, Ptr], open).only(Archs::X64),
    Export::func(
        "NtManagePartition",
        Stdcall,
        &[Ptr, Ptr, I32, Ptr, I32],
        manage,
    )
    .only(Archs::X64),
    Export::func(
        "NtQueryLicenseValue",
        Stdcall,
        &[Ptr, Ptr, Ptr, I32, Ptr],
        product_info,
    )
    .only(Archs::X64),
];

pub(super) fn enabled(c: &Ctx) -> bool {
    c.p.cfg.gameos && c.p.native.is_none() && c.arch() == WinArch::X64
}

pub(super) static GRAPHICS_EXPORTS: &[Export] = &[Export::func(
    "NtDirectGraphicsCall",
    Stdcall,
    &[I32, Ptr, I32, Ptr, I32],
    direct_graphics_call,
)
.only(Archs::X64)];

pub(super) static ANALYSIS_WER_EXPORTS: &[Export] = &[
    Export::func("WerRegisterMemoryBlock", Stdcall, &[Ptr, I32], analysis_wer),
    Export::func("WerUnregisterMemoryBlock", Stdcall, &[Ptr], analysis_wer),
];

pub(super) static ANALYSIS_DEVELOPER_MODE_EXPORTS: &[Export] = &[Export::func(
    "IsDeveloperModeEnabled",
    Stdcall,
    &[Ptr],
    analysis_developer_mode,
)
.only(Archs::X64)];

pub(super) static ANALYSIS_EDP_EXPORTS: &[Export] =
    &[Export::func("GetIsEdpEnabled", Stdcall, &[], |c| {
        if !c.p.cfg.gameos_analysis {
            return Err(c.unsupported("GetIsEdpEnabled"));
        }
        // Enterprise data protection is absent from the offline guest.
        Flow::bool(false)
    })
    .only(Archs::X64)];

fn analysis_developer_mode(c: &mut Ctx) -> ApiResult {
    if !c.p.cfg.gameos_analysis {
        return Err(c.unsupported("IsDeveloperModeEnabled"));
    }
    let enabled = c.ptr(0)?;
    if enabled == 0 {
        return Flow::ret(0x8000_4003);
    }
    c.mem().w32(enabled, 0)?;
    Flow::ret(0)
}

fn analysis_wer(c: &mut Ctx) -> ApiResult {
    if c.p.cfg.gameos_analysis {
        // The offline profile has no report collector.
        Flow::ret(0x8000_4001)
    } else {
        Err(c.unsupported("Windows Error Reporting"))
    }
}

const ANALYSIS_SCM: &str = "GameOS analysis service manager";
const ANALYSIS_RPCSS: &str = "GameOS analysis RpcSs";
const SC_MANAGER_CONNECT: u32 = 1;
const SC_MANAGER_ENUMERATE_SERVICE: u32 = 4;
const SERVICE_QUERY_CONFIG: u32 = 1;
const SERVICE_QUERY_STATUS: u32 = 4;
const SERVICE_NOTIFY_RUNNING: u32 = 8;

pub(super) static ANALYSIS_SERVICE_EXPORTS: &[Export] = &[
    Export::func(
        "OpenSCManagerA",
        Stdcall,
        &[Ptr, Ptr, I32],
        analysis_open_manager,
    )
    .only(Archs::X64),
    Export::func(
        "OpenServiceA",
        Stdcall,
        &[Ptr, Ptr, I32],
        analysis_open_service,
    )
    .only(Archs::X64),
    Export::func(
        "NotifyServiceStatusChangeA",
        Stdcall,
        &[Ptr, I32, Ptr],
        analysis_notify_service,
    )
    .only(Archs::X64),
    Export::func(
        "CloseServiceHandle",
        Stdcall,
        &[Ptr],
        analysis_close_service,
    )
    .only(Archs::X64),
];

pub(super) static ANALYSIS_COM_EXPORTS: &[Export] = &[
    Export::func(
        "CoInitializeSecurity",
        Stdcall,
        &[Ptr, I32, Ptr, Ptr, I32, I32, Ptr, I32, Ptr],
        analysis_com_security,
    )
    .only(Archs::X64),
    Export::func(
        "CoCreateInstanceEx",
        Stdcall,
        &[Ptr, Ptr, I32, Ptr, I32, Ptr],
        analysis_com_activate,
    )
    .only(Archs::X64),
];

const COMPANION_VM: &str = "C12A416B-F347-405C-B765-2DE027A6249E";

fn analysis_com_activate(c: &mut Ctx) -> ApiResult {
    let (class, outer, context, server, count, results) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.u32(2)?,
        c.ptr(3)?,
        c.u32(4)?,
        c.ptr(5)?,
    );
    const CLSCTX_REMOTE_SERVER: u32 = 0x10;
    if !c.p.cfg.gameos_analysis {
        return Err(c.unsupported("CoCreateInstanceEx"));
    }
    if outer == 0 && context == CLSCTX_REMOTE_SERVER && server != 0 && count == 1 && results != 0 {
        let name_address = server.checked_add(8).ok_or(MemFault {
            addr: server,
            write: false,
        })?;
        let name = c.read_ptr(name_address)?;
        if name != 0
            && c.mem().wstr(name, COMPANION_VM.len() + 1)?
                == COMPANION_VM.encode_utf16().collect::<Vec<_>>()
        {
            let unavailable = 0x8007_0000 | ERROR_NOT_SUPPORTED;
            // Only the companion VM transport is absent. Publish no interface
            // and let the runtime decide whether this service is optional.
            let output = results.checked_add(8).ok_or(MemFault {
                addr: results,
                write: true,
            })?;
            c.mem()
                .probe(output, 12, MemoryAccessKind::Write)
                .map_err(|fault| MemFault {
                    addr: fault.address,
                    write: true,
                })?;
            c.write_ptr(output, 0)?;
            c.mem().w32(output + 8, unavailable)?;
            return Flow::ret(unavailable.into());
        }
    }
    let module =
        c.p.modules
            .by_name("combase.dll")
            .ok_or_else(|| c.unsupported("CoCreateInstanceEx requires guest combase.dll"))?;
    let symbol = super::super::loader::SymRef::Name(b"CoCreateInstanceEx".to_vec(), None);
    let target = super::super::loader::lookup(c.p, module, &symbol)
        .map_err(|error| c.unsupported(error.message))?
        .ok_or_else(|| c.unsupported("guest combase.dll has no CoCreateInstanceEx"))?;
    Flow::call_checked(
        target,
        vec![class, outer, context.into(), server, count.into(), results],
        |_, result| Flow::ret(result),
    )
}

fn analysis_com_security(c: &mut Ctx) -> ApiResult {
    if !c.p.cfg.gameos_analysis {
        return Err(c.unsupported("CoInitializeSecurity"));
    }
    const RPC_E_TOO_LATE: u64 = 0x8001_0119;
    if c.p.gameos_com_security_initialized {
        return Flow::ret(RPC_E_TOO_LATE);
    }
    const E_NOTIMPL: u64 = 0x8000_4001;
    const RPC_C_AUTHN_LEVEL_NONE: u32 = 1;
    const RPC_C_IMP_LEVEL_IDENTIFY: u32 = 2;
    const EOAC_DISABLE_AAA: u32 = 0x1000;
    const EOAC_NO_CUSTOM_MARSHAL: u32 = 0x2000;
    // The local profile accepts the GDK's default client policy. It has no
    // COM server registrations, remote authentication, or custom marshaling.
    if c.ptr(0)? != 0
        || c.u32(1)? != u32::MAX
        || c.ptr(2)? != 0
        || c.ptr(3)? != 0
        || c.u32(4)? != RPC_C_AUTHN_LEVEL_NONE
        || c.u32(5)? != RPC_C_IMP_LEVEL_IDENTIFY
        || c.ptr(6)? != 0
        || c.u32(7)? != EOAC_DISABLE_AAA | EOAC_NO_CUSTOM_MARSHAL
        || c.ptr(8)? != 0
    {
        return Flow::ret(E_NOTIMPL);
    }
    c.p.gameos_com_security_initialized = true;
    Flow::ret(0)
}

fn analysis_open_manager(c: &mut Ctx) -> ApiResult {
    if !c.p.cfg.gameos_analysis {
        return Err(c.unsupported("OpenSCManagerA"));
    }
    if c.ptr(0)? != 0 || c.ptr(1)? != 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let access = c.u32(2)?;
    if access & !(SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE) != 0 {
        return c.fail(ERROR_ACCESS_DENIED, 0);
    }
    analysis_service_handle(c, ANALYSIS_SCM, access | SC_MANAGER_CONNECT)
}

fn analysis_open_service(c: &mut Ctx) -> ApiResult {
    if !c.p.cfg.gameos_analysis {
        return Err(c.unsupported("OpenServiceA"));
    }
    let (manager, name, access) = (c.ptr(0)?, c.ptr(1)?, c.u32(2)?);
    if !matches!(c.p.objects.get(manager), Some(Object::Opaque(ANALYSIS_SCM))) {
        return c.fail(ERROR_INVALID_HANDLE, 0);
    }
    if name == 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    if !c.mem().cstr(name, 6)?.eq_ignore_ascii_case(b"RpcSs") {
        const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
        return c.fail(ERROR_SERVICE_DOES_NOT_EXIST, 0);
    }
    if access & !(SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS) != 0 {
        return c.fail(ERROR_ACCESS_DENIED, 0);
    }
    analysis_service_handle(c, ANALYSIS_RPCSS, access)
}

fn analysis_service_handle(c: &mut Ctx, kind: &'static str, access: u32) -> ApiResult {
    let Some(id) = c.p.objects.try_create(Object::Opaque(kind)) else {
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
    };
    let Some(handle) = c.p.objects.open_access(id, false, access) else {
        c.p.objects.release(id);
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
    };
    Flow::ret(handle.into())
}

fn analysis_notify_service(c: &mut Ctx) -> ApiResult {
    if !c.p.cfg.gameos_analysis {
        return Err(c.unsupported("NotifyServiceStatusChangeA"));
    }
    let (service, mask, buffer) = (c.ptr(0)?, c.u32(1)?, c.ptr(2)?);
    let Some(id) = c.p.objects.id(service) else {
        return Flow::ret(ERROR_INVALID_HANDLE.into());
    };
    if !matches!(c.p.objects.obj(id), Some(Object::Opaque(ANALYSIS_RPCSS))) {
        return Flow::ret(ERROR_INVALID_HANDLE.into());
    }
    if c.p.objects.access(service).unwrap_or(0) & SERVICE_QUERY_STATUS == 0 {
        return Flow::ret(ERROR_ACCESS_DENIED.into());
    }
    if mask != SERVICE_NOTIFY_RUNNING || buffer == 0 || c.mem().u32(buffer)? != 2 {
        return Flow::ret(ERROR_INVALID_PARAMETER.into());
    }
    let pending = |apc: &UserApc| matches!(apc, UserApc::Service { object, .. } if *object == id);
    if c.t.apcs.iter().any(pending) || c.p.threads.values().any(|t| t.apcs.iter().any(pending)) {
        const ERROR_ALREADY_REGISTERED: u32 = 1242;
        return Flow::ret(ERROR_ALREADY_REGISTERED.into());
    }
    let routine = c.mem().u64(buffer + 8)?;
    if routine == 0 {
        return Flow::ret(ERROR_INVALID_PARAMETER.into());
    }
    // x64 SERVICE_NOTIFY_2A output tail, beginning at dwNotificationStatus.
    let mut result = [0u8; 56];
    const SERVICE_WIN32_SHARE_PROCESS: u32 = 0x20;
    const SERVICE_RUNNING: u32 = 4;
    result[4..8].copy_from_slice(&SERVICE_WIN32_SHARE_PROCESS.to_le_bytes());
    result[8..12].copy_from_slice(&SERVICE_RUNNING.to_le_bytes());
    result[40..44].copy_from_slice(&SERVICE_NOTIFY_RUNNING.to_le_bytes());
    c.mem().wr(buffer + 24, &result)?;
    c.t.apcs.push_back(UserApc::Service {
        routine,
        buffer,
        object: id,
    });
    Flow::ret(0)
}

fn analysis_close_service(c: &mut Ctx) -> ApiResult {
    if !c.p.cfg.gameos_analysis {
        return Err(c.unsupported("CloseServiceHandle"));
    }
    let handle = c.ptr(0)?;
    let id = c.p.objects.id(handle);
    if !matches!(
        c.p.objects.get(handle),
        Some(Object::Opaque(ANALYSIS_SCM | ANALYSIS_RPCSS))
    ) || c.p.objects.close(handle).is_err()
    {
        return c.fail(ERROR_INVALID_HANDLE, 0);
    }
    let keep =
        |apc: &UserApc| !matches!(apc, UserApc::Service { object, .. } if Some(*object) == id);
    c.t.apcs.retain(keep);
    for t in c.p.threads.values_mut() {
        t.apcs.retain(keep);
    }
    Flow::ret(1)
}

fn direct_graphics_call(c: &mut Ctx) -> ApiResult {
    // D3D12 and XMem probe the direct transport before using their device
    // paths. The portable profile handles device requests separately.
    if enabled(c)
        && matches!(c.u32(0)?, 0x7900_0000 | 0x0015_0000)
        && c.ptr(1)? == 0
        && c.u32(2)? == 0
        && c.ptr(3)? == 0
        && c.u32(4)? == 0
    {
        return Flow::ret(STATUS_NOT_SUPPORTED.into());
    }
    Err(c.unsupported("NtDirectGraphicsCall"))
}

fn acquire(c: &mut Ctx) -> ApiResult {
    let (privileges, count, flags, output) = (c.ptr(0)?, c.u32(1)?, c.u32(2)?, c.ptr(3)?);
    if count == 0 || flags & !3 != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if !enabled(c)
        || count != 1
        || flags != RTL_ACQUIRE_PRIVILEGE_PROCESS
        || c.mem().u32(privileges)? != SE_LOCK_MEMORY
    {
        return Flow::ret(STATUS_PRIVILEGE_NOT_HELD.into());
    }
    // This scope denotes the guest profile's sole synthetic privilege. It
    // does not alter any captured token or authorize a host memory operation.
    publish_handle(c, output, Object::GameOsLockMemoryScope, false, 0)
}

fn release(c: &mut Ctx) -> ApiResult {
    let scope = c.ptr(0)?;
    if !matches!(c.p.objects.get(scope), Some(Object::GameOsLockMemoryScope)) {
        return Err(c.unsupported("RtlReleasePrivilege for unknown guest scope"));
    }
    c.p.objects
        .close(scope)
        .map_err(|()| c.unsupported("RtlReleasePrivilege for protected guest scope"))?;
    Flow::void()
}

fn open(c: &mut Ctx) -> ApiResult {
    kernel_result(open_checked(c))
}

fn open_checked(c: &mut Ctx) -> ApiResult {
    let (output, access, attributes) = (c.ptr(0)?, c.u32(1)?, c.ptr(2)?);
    if !enabled(c) {
        return Err(c.unsupported("NtOpenPartition outside the portable GameOS x64 profile"));
    }
    if access & !PARTITION_ALL_ACCESS != 0 {
        return Flow::ret(STATUS_ACCESS_DENIED.into());
    }
    if attributes % 8 != 0 || output % 8 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    let attrs = c.mem().bytes(attributes, 48)?;
    let word = |i| u32::from_le_bytes(attrs[i..i + 4].try_into().unwrap());
    let pointer = |i| u64::from_le_bytes(attrs[i..i + 8].try_into().unwrap());
    let flags = word(24);
    if word(0) != 48
        || flags & !(OBJ_INHERIT | OBJ_CASE_INSENSITIVE) != 0
        || pointer(8) != 0
        || pointer(32) != 0
        || pointer(40) != 0
    {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let descriptor = pointer(16);
    let length = c.mem().u16(descriptor)? as usize;
    if length == 0 || length % 2 != 0 {
        return Flow::ret(STATUS_OBJECT_NAME_INVALID.into());
    }
    let buffer = c.read_ptr(descriptor + 8)?;
    let name = c.mem().bytes(buffer, length)?;
    let name_matches = |candidate: &str| {
        let bytes = candidate.as_bytes();
        name.len() == bytes.len() * 2
            && name.chunks_exact(2).zip(bytes).all(|(unit, byte)| {
                unit[1] == 0
                    && if flags & OBJ_CASE_INSENSITIVE != 0 {
                        unit[0].eq_ignore_ascii_case(byte)
                    } else {
                        unit[0] == *byte
                    }
            })
    };
    let partition_id = if name_matches(r"\KernelObjects\MemoryPartition0") {
        0
    } else if name_matches(r"\GLOBAL??\MemoryPartitionXboxTitle") {
        1
    } else {
        return Flow::ret(STATUS_OBJECT_NAME_NOT_FOUND.into());
    };
    publish_handle(
        c,
        output,
        Object::MemoryPartition { partition_id },
        flags & OBJ_INHERIT != 0,
        access,
    )
}

fn publish_handle(
    c: &mut Ctx,
    output: u64,
    object: Object,
    inherit: bool,
    access: u32,
) -> ApiResult {
    c.mem()
        .probe(output, c.psize() as usize, MemoryAccessKind::Write)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: true,
        })?;
    let Some(id) = c.p.objects.try_create(object) else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let Some(handle) = c.p.objects.open_access(id, inherit, access) else {
        c.p.objects.release(id);
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let handle = u64::from(handle);
    if let Err(fault) = c.write_ptr(output, handle) {
        let _ = c.p.objects.close(handle);
        return Err(fault.into());
    }
    Flow::ret(STATUS_SUCCESS.into())
}

fn manage(c: &mut Ctx) -> ApiResult {
    kernel_result(manage_checked(c))
}

fn manage_checked(c: &mut Ctx) -> ApiResult {
    let (target, source, class, output, length) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.u32(2)?,
        c.ptr(3)?,
        c.u32(4)? as usize,
    );
    if !enabled(c) || class != 0 || source != 0 {
        return Err(c.unsupported(format!("NtManagePartition information class {class}")));
    }
    let partition_id = match c.p.objects.get(target) {
        Some(Object::MemoryPartition { partition_id }) => *partition_id,
        Some(_) => return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into()),
        None => return Flow::ret(STATUS_INVALID_HANDLE.into()),
    };
    if c.p.objects.access(target).unwrap_or(0) & PARTITION_QUERY_ACCESS == 0 {
        return Flow::ret(STATUS_ACCESS_DENIED.into());
    }
    if length < CONFIGURATION_BYTES {
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    if output % 8 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    let usage =
        c.p.vm
            .memory_usage()
            .map_err(|err| c.unsupported(format!("guest partition accounting: {err:?}")))?;
    let mut record = [0; CONFIGURATION_BYTES];
    // Preserve the input selectors. The profile reports a single guest NUMA
    // node, with the available pool counted as free in its no-paging model.
    let selectors = c.mem().bytes(output, 12)?;
    record[..12].copy_from_slice(&selectors);
    record[12..16].copy_from_slice(&1u32.to_le_bytes());
    for (offset, bytes) in [
        (0x10, usage.available_bytes),
        (0x18, usage.committed_bytes),
        (0x20, usage.commit_limit_bytes),
        (0x28, usage.peak_commitment_bytes),
        (0x30, usage.total_physical_bytes),
        (0x38, usage.available_bytes),
        (0x48, usage.available_bytes),
        (0xd8, usage.commit_limit_bytes),
    ] {
        record[offset..offset + 8].copy_from_slice(&(bytes / PAGE_SIZE).to_le_bytes());
    }
    record[0xe8..0xec].copy_from_slice(&partition_id.to_le_bytes());
    c.mem().wr(output, &record)?;
    Flow::ret(STATUS_SUCCESS.into())
}

fn kernel_result(result: ApiResult) -> ApiResult {
    match result {
        Err(ApiErr::Fault(_)) => Flow::ret(STATUS_ACCESS_VIOLATION.into()),
        result => result,
    }
}

fn product_info(c: &mut Ctx) -> ApiResult {
    kernel_result(product_info_checked(c))
}

fn product_info_checked(c: &mut Ctx) -> ApiResult {
    const PRODUCT_NAME: &str = "Kernel-ProductInfo";
    const PRODUCT_XBOX_GAMEOS: u32 = 0xc2;
    const REG_DWORD: u32 = 4;
    let (name, kind, data, capacity, required) =
        (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?, c.u32(3)?, c.ptr(4)?);
    if !enabled(c) {
        return Err(c.unsupported("NtQueryLicenseValue outside the portable GameOS x64 profile"));
    }
    if name == 0 || required == 0 || (data == 0 && capacity != 0) {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let bytes = usize::from(c.mem().u16(name)?);
    if bytes == PRODUCT_NAME.len() * 2 {
        let buffer = c.read_ptr(name + 8)?;
        if c.mem()
            .wunits(buffer, bytes / 2)?
            .into_iter()
            .eq(PRODUCT_NAME.encode_utf16())
        {
            c.mem().w32(required, 4)?;
            if kind != 0 {
                c.mem().w32(kind, REG_DWORD)?;
            }
            if capacity < 4 {
                return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
            }
            c.mem().w32(data, PRODUCT_XBOX_GAMEOS)?;
            return Flow::ret(STATUS_SUCCESS.into());
        }
    }
    Err(c.unsupported("NtQueryLicenseValue GameOS profile only supplies the kernel product ID"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::{
        WindowsConfig, WindowsProcess,
        hle::{Item, Value},
        memory::{mem, prot},
        process::{Proc, Thread},
    };

    fn setup(gameos: bool) -> WindowsProcess {
        setup_launch(gameos, false)
    }

    fn setup_launch(gameos: bool, gameos_analysis: bool) -> WindowsProcess {
        let mut config = WindowsConfig::new("gameos-test.exe", Vec::new());
        config.gameos = gameos;
        config.gameos_analysis = gameos_analysis;
        config.arena_bytes = 64 << 20;
        let image = include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe");
        WindowsProcess::spawn_image(config, image.to_vec()).unwrap()
    }

    fn invoke<const N: usize>(
        p: &mut Proc,
        t: &mut Thread,
        name: &str,
        args: [u64; N],
    ) -> ApiResult {
        let api = EXPORTS
            .iter()
            .chain(GRAPHICS_EXPORTS)
            .chain(ANALYSIS_SERVICE_EXPORTS)
            .chain(ANALYSIS_COM_EXPORTS)
            .chain(wnf::EXPORTS)
            .chain(crate::user::windows::dll::native::EXPORTS)
            .chain(crate::user::windows::dll::native::EXTENDED_SECTION_CREATE_EXPORTS)
            .chain(crate::user::windows::dll::native::APPCONTAINER_PATH_EXPORTS)
            .chain(crate::user::windows::dll::native::IO_CANCEL_EXPORTS)
            .chain(crate::user::windows::dll::native::OBJECT_DUPLICATION_EXPORTS)
            .chain(crate::user::windows::dll::native::OBJECT_COMPARE_EXPORTS)
            .chain(crate::user::windows::dll::rtl_string::EXPORTS)
            .chain(crate::user::windows::dll::native::WIN32_TOKEN_EXPORTS)
            .chain(crate::user::windows::dll::native::WIN32_PROCESS_TOKEN_EXPORTS)
            .chain(crate::user::windows::dll::native::WIN32_REVERT_EXPORTS)
            .chain(crate::user::windows::dll::native::WIN32_SID_EXPORTS)
            .chain(crate::user::windows::dll::native::NTDLL_SID_EXPORTS)
            .chain(crate::user::windows::dll::rtl_string::COMPARE_EXPORTS)
            .chain(crate::user::windows::dll::threadpool::NATIVE_ANALYSIS_EXPORTS)
            .chain(crate::user::windows::dll::kernel::NTDLL_LAST_ERROR_EXPORTS)
            .chain(crate::user::windows::dll::kernel::EXPORTS)
            .chain(crate::user::windows::dll::files::EXPORTS)
            .find_map(|export| match &export.item {
                Item::Func(api) if export.name == name => Some(api),
                _ => None,
            })
            .unwrap();
        let sp = t.cpu.sp() - 0x100;
        for (reg, value) in [1, 2, 8, 9].into_iter().zip(args) {
            t.cpu.set_gpr(reg, value);
        }
        for (index, argument) in args.into_iter().skip(4).enumerate() {
            p.space.w64(sp + 0x28 + index as u64 * 8, argument).unwrap();
        }
        (api.imp)(&mut Ctx {
            p,
            t,
            api,
            entry_pc: 0,
            entry_sp: sp,
            ret_addr: 0,
            cursor: sp,
        })
    }

    #[test]
    fn analysis_rpc_uses_empty_appcontainer_path_and_a_bounded_absent_directory() {
        let mut process = setup_launch(true, true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        let output = thread.cpu.sp() - 0x800;
        p.space.wr(output, &[0xa5; 16]).unwrap();
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "RtlGetAppContainerNamedObjectPath",
                [0, 0, 0, output]
            )),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.bytes(output, 16).unwrap(), [0; 16]);
        let (attrs, descriptor, buffer) = (output + 0x20, output + 0x60, output + 0x80);
        p.space.w32(attrs, 48).unwrap();
        p.space.w64(attrs + 16, descriptor).unwrap();
        p.space.w64(descriptor + 8, buffer).unwrap();
        for (path, expected_absent) in [(r"\RPC Control", true), (r"\RPC Control2", false)] {
            let units: Vec<_> = path.encode_utf16().collect();
            p.space.put_wstr(buffer, &units).unwrap();
            p.space.w16(descriptor, (units.len() * 2) as u16).unwrap();
            p.space
                .w16(descriptor + 2, (units.len() * 2 + 2) as u16)
                .unwrap();
            let result = invoke(
                p,
                &mut thread,
                "NtOpenDirectoryObject",
                [output, 0x20001, attrs],
            );
            if expected_absent {
                assert_eq!(status(result), STATUS_OBJECT_NAME_NOT_FOUND);
            } else {
                assert!(matches!(result, Err(ApiErr::Unimplemented(_))));
            }
        }
    }

    #[test]
    fn analysis_wnf_queries_and_releases_a_dormant_subscription() {
        let mut process = setup_launch(true, true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        let name = thread.cpu.sp() - 0x800;
        let (stamp, length, handle_out) = (name + 8, name + 12, name + 16);
        let state = 0x41c6_0d2a_a3bc_3875;
        p.space.w64(name, state).unwrap();
        p.space.w32(stamp, 1).unwrap();
        p.space.w32(length, 0).unwrap();
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "NtQueryWnfStateData",
                [name, 0, 0, stamp, 0, length]
            )),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u32(stamp).unwrap(), 0);
        assert_eq!(p.space.u32(length).unwrap(), 0);
        let connectivity = 0x418b_0223_a3bc_2075;
        let data = name + 0x40;
        let query = [name, 0, 0, stamp, data, length];
        p.space.w64(name, connectivity).unwrap();
        p.space.w64(data, u64::MAX).unwrap();
        p.space.w32(length, 7).unwrap();
        assert_eq!(
            status(invoke(p, &mut thread, "NtQueryWnfStateData", query)),
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(p.space.u32(length).unwrap(), 8);
        assert_eq!(p.space.u64(data).unwrap(), u64::MAX);
        assert_eq!(
            status(invoke(p, &mut thread, "NtQueryWnfStateData", query)),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u64(data).unwrap(), 0);
        let subscription = invoke(
            p,
            &mut thread,
            "RtlSubscribeWnfStateChangeNotification",
            [handle_out, connectivity, 0, 0x140001000, 0, 0, 0, 0],
        );
        assert_eq!(status(subscription), STATUS_SUCCESS);
        let handle = p.space.u64(handle_out).unwrap();
        let release = "RtlUnsubscribeWnfNotificationWaitForCompletion";
        assert_eq!(
            status(invoke(p, &mut thread, release, [handle])),
            STATUS_SUCCESS
        );
        assert_eq!(
            status(invoke(p, &mut thread, release, [handle])),
            STATUS_INVALID_HANDLE
        );
    }

    #[test]
    fn analysis_storage_adapter_only_accepts_the_identification_request() {
        let mut process = setup_launch(true, true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        let path = thread.cpu.sp() - 0x800;
        let (io, header) = (path + 0x40, path + 0x50);
        p.space
            .put_wstr(path, &r"\\.\Scsi0:".encode_utf16().collect::<Vec<_>>())
            .unwrap();
        let opened = invoke(
            p,
            &mut thread,
            "CreateFileW",
            [path, 0xc010_0000, 0, 0, 3, 0, 0],
        )
        .unwrap();
        let Flow::Ret(Value::Int(handle)) = opened else {
            panic!("expected a storage adapter handle");
        };
        assert!(matches!(
            p.objects.get(handle),
            Some(Object::GameOsScsiAdapter)
        ));
        p.space.wr(header, &[0; 28]).unwrap();
        p.space.w32(header, 28).unwrap();
        p.space.w32(header + 16, 0x7800_0009).unwrap();
        let args = [handle, 0, 0, 0, io, 0x4d008, header, 28, header, 28];
        assert_eq!(
            status(invoke(p, &mut thread, "NtDeviceIoControlFile", args)),
            STATUS_INVALID_DEVICE_REQUEST
        );
        p.space.w32(header + 16, 0x7800_000c).unwrap();
        p.space.w32(header + 20, 0xc000_0185).unwrap();
        assert_eq!(
            status(invoke(p, &mut thread, "NtDeviceIoControlFile", args)),
            STATUS_SUCCESS
        );
        let mut signature = [0; 8];
        p.space.rd(header + 4, &mut signature).unwrap();
        assert_eq!(&signature, b"MSFT_XVD");
        assert_eq!(p.space.u32(header + 20).unwrap(), 0);
        assert_eq!(p.space.u64(io + 8).unwrap(), 28);
    }

    #[test]
    fn analysis_token_supports_sizing_and_native_counted_string_comparison() {
        let mut process = setup_launch(true, true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        let base = thread.cpu.sp() - 0x500;
        let length = base + 0x100;
        let query = |out, capacity| [u64::MAX - 3, 39, out, capacity, length];
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "NtQueryInformationToken",
                query(0, 0)
            )),
            STATUS_BUFFER_TOO_SMALL
        );
        let bytes = u64::from(p.space.u32(length).unwrap());
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "NtQueryInformationToken",
                query(base, bytes)
            )),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u32(base + 4).unwrap(), 1);
        let attr = p.space.u64(base + 8).unwrap();
        let name_pointer = p.space.u64(attr + 8).unwrap();
        assert_eq!(
            p.space.wstr(name_pointer, 9).unwrap().as_slice(),
            &"XBOX://LI".encode_utf16().collect::<Vec<_>>()
        );
        let values = p.space.u64(attr + 32).unwrap();
        assert_eq!(p.space.u32(values + 8).unwrap(), 16);
        let second = base + 0x118;
        let text = base + 0x130;
        p.space
            .put_wstr(text, &"xbox://li".encode_utf16().collect::<Vec<_>>())
            .unwrap();
        invoke(p, &mut thread, "RtlInitUnicodeString", [second, text]).unwrap();
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "RtlCompareUnicodeString",
                [attr, second, 1]
            )),
            0
        );
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "RtlCompareUnicodeString",
                [attr, second, 0]
            )) as i32,
            -32
        );
    }

    #[test]
    fn analysis_token_returns_a_query_only_user_sid() {
        let mut process = setup_launch(true, true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        let base = thread.cpu.sp() - 0x500;
        let length = base + 0x100;
        let query = |out, capacity| [u64::MAX - 3, 1, out, capacity, length];
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "NtQueryInformationToken",
                query(0, 0)
            )),
            STATUS_BUFFER_TOO_SMALL
        );
        let required = u64::from(p.space.u32(length).unwrap());
        assert_eq!(required, 44);
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "GetTokenInformation",
                query(base, required)
            )),
            1
        );
        let sid = p.space.u64(base).unwrap();
        assert_eq!(sid, base + 16);
        assert_eq!(p.space.u32(base + 8).unwrap(), 0);
        assert!(p.objects.primary_token_subject().is_none());
        assert_eq!(status(invoke(p, &mut thread, "GetLengthSid", [sid])), 28);
        let data = p.space.bytes(sid, 28).unwrap();
        assert_eq!(
            crate::user::windows::security::sid(&data),
            Some(data.as_slice())
        );
        assert_eq!(
            status(invoke(p, &mut thread, "CopySid", [28, sid + 1, sid])),
            1
        );
        assert_eq!(p.space.bytes(sid + 1, 28).unwrap(), data);

        let string = base + 0x200;
        let blocks = p.heaps.blocks(p.process_heap);
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "RtlConvertSidToUnicodeString",
                [string, sid + 1, 1]
            )),
            STATUS_SUCCESS
        );
        let chars = p.space.u16(string).unwrap() as usize / 2;
        let buffer = p.space.u64(string + 8).unwrap();
        let expected = "S-1-5-21-5783890-1701667143-21327-1000";
        assert_eq!(
            String::from_utf16(&p.space.wstr(buffer, chars + 1).unwrap()).unwrap(),
            expected
        );
        assert_eq!(p.space.u16(string + 2).unwrap() as usize, (chars + 1) * 2);
        invoke(p, &mut thread, "RtlFreeUnicodeString", [string]).unwrap();
        assert_eq!(p.space.bytes(string, 16).unwrap(), [0; 16]);
        assert_eq!(p.heaps.blocks(p.process_heap), blocks);
    }

    fn status(result: ApiResult) -> u32 {
        match result.unwrap() {
            Flow::Ret(Value::Int(value)) => value.try_into().unwrap(),
            _ => panic!("expected a status return"),
        }
    }

    #[test]
    fn analysis_companion_transport_returns_unsupported_without_an_interface() {
        let mut process = setup_launch(true, true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        let server = thread.cpu.sp() - 0x800;
        let name = server + 0x30;
        let results = server + 0x90;
        p.space
            .put_wstr(name, &COMPANION_VM.encode_utf16().collect::<Vec<_>>())
            .unwrap();
        p.space.w64(server + 8, name).unwrap();
        p.space.w64(results, 0x1234).unwrap();
        p.space.w64(results + 8, 0x5678).unwrap();
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "CoCreateInstanceEx",
                [1, 0, 0x10, server, 1, results]
            )),
            0x80070032
        );
        assert_eq!(p.space.u64(results).unwrap(), 0x1234);
        assert_eq!(p.space.u64(results + 8).unwrap(), 0);
        assert_eq!(p.space.u32(results + 16).unwrap(), 0x80070032);
    }

    #[test]
    fn analysis_com_policy_is_set_only_once_and_never_accepts_other_authentication() {
        let mut process = setup_launch(true, true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        let mut args = [0, u64::from(u32::MAX), 0, 0, 1, 2, 0, 0x3000, 0];
        args[4] = 6;
        assert_eq!(
            status(invoke(p, &mut thread, "CoInitializeSecurity", args)),
            0x8000_4001
        );
        assert!(!p.gameos_com_security_initialized);
        args[4] = 1;
        assert_eq!(
            status(invoke(p, &mut thread, "CoInitializeSecurity", args)),
            0
        );
        assert!(p.gameos_com_security_initialized);
        assert_eq!(
            status(invoke(p, &mut thread, "CoInitializeSecurity", args)),
            0x8001_0119
        );
    }

    #[test]
    fn analysis_rpc_service_queues_an_alertable_notification_and_cancels_on_close() {
        let mut process = setup_launch(true, true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        let name = thread.cpu.sp() - 0x600;
        let buffer = name + 0x20;
        p.space.put_cstr(name, b"RpcSs").unwrap();
        let manager = u64::from(status(invoke(p, &mut thread, "OpenSCManagerA", [0, 0, 4])));
        assert_ne!(manager, 0);
        let service = u64::from(status(invoke(
            p,
            &mut thread,
            "OpenServiceA",
            [manager, name, 5],
        )));
        assert_ne!(service, 0);
        p.space.w32(buffer, 2).unwrap();
        p.space.w64(buffer + 8, 0x50000).unwrap();
        p.space.w64(buffer + 16, 0x1234).unwrap();
        let notify = [service, 8, buffer];
        assert_eq!(
            status(invoke(p, &mut thread, "NotifyServiceStatusChangeA", notify)),
            0
        );
        assert_eq!(p.space.u64(buffer + 16).unwrap(), 0x1234);
        assert_eq!(p.space.u32(buffer + 24).unwrap(), 0);
        assert_eq!(p.space.u32(buffer + 32).unwrap(), 4);
        assert_eq!(p.space.u32(buffer + 64).unwrap(), 8);
        assert_eq!(
            thread.apcs.front(),
            Some(&UserApc::Service {
                routine: 0x50000,
                buffer,
                object: p.objects.id(service).unwrap(),
            })
        );
        assert_eq!(
            status(invoke(p, &mut thread, "NotifyServiceStatusChangeA", notify)),
            1242
        );
        assert_eq!(
            status(invoke(p, &mut thread, "CloseServiceHandle", [service])),
            1
        );
        assert!(thread.apcs.is_empty());
        assert_eq!(
            status(invoke(p, &mut thread, "NotifyServiceStatusChangeA", notify)),
            ERROR_INVALID_HANDLE
        );
        assert_eq!(
            status(invoke(p, &mut thread, "CloseServiceHandle", [manager])),
            1
        );
    }

    #[test]
    fn the_portable_graphics_transport_probe_reports_unavailable() {
        for gameos in [false, true] {
            let mut process = setup(gameos);
            let p = process.state_mut();
            let mut thread = p.threads.pop_first().unwrap().1;
            let args = [0x7900_0000, 0, 0, 0, 0];
            let result = invoke(p, &mut thread, "NtDirectGraphicsCall", args);
            if gameos {
                assert_eq!(status(result), STATUS_NOT_SUPPORTED);
            } else {
                assert!(matches!(result, Err(ApiErr::Unimplemented(_))));
            }
            for index in 0..args.len() {
                let mut other = args;
                other[index] += 1;
                let result = invoke(p, &mut thread, "NtDirectGraphicsCall", other);
                assert!(matches!(result, Err(ApiErr::Unimplemented(_))));
            }
        }
    }

    #[test]
    fn xvc_device_publishes_only_the_portable_capability_counter() {
        let mut process = setup(true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        let base = thread.cpu.sp() - 0x500;
        let (name, unicode, attributes, handle, io, output) = (
            base,
            base + 0x40,
            base + 0x60,
            base + 0x90,
            base + 0xa0,
            base + 0xb0,
        );
        let name_bytes: Vec<_> = r"\Device\xvcmgmt"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        p.space.wr(name, &name_bytes).unwrap();
        assert!(invoke(p, &mut thread, "RtlInitUnicodeString", [unicode, name]).is_ok());
        p.space.wr(attributes, &[0; 0x30]).unwrap();
        p.space.w32(attributes, 0x30).unwrap();
        p.space.w64(attributes + 0x10, unicode).unwrap();
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "NtCreateFile",
                [handle, 0x100003, attributes, io, 0, 0, 2, 3, 1, 0, 0],
            )),
            STATUS_SUCCESS
        );
        let handle = p.space.u64(handle).unwrap();
        assert!(matches!(p.objects.get(handle), Some(Object::GameOsXvcFile)));
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "NtDirectGraphicsCall",
                [0x150000, 0, 0, 0, 0],
            )),
            STATUS_NOT_SUPPORTED
        );
        p.space.w64(output, u64::MAX).unwrap();
        let mut query = [handle, 0, 0, 0, io, 0x150068, 0, 0, output, 7];
        assert_eq!(
            status(invoke(p, &mut thread, "NtDeviceIoControlFile", query)),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(p.space.u64(output).unwrap(), u64::MAX);
        query[9] = 8;
        assert_eq!(
            status(invoke(p, &mut thread, "NtDeviceIoControlFile", query)),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u64(io).unwrap(), 0);
        assert_eq!(p.space.u64(io + 8).unwrap(), 8);
        assert_eq!(p.space.u64(output).unwrap(), 0);
        assert_eq!(
            status(invoke(p, &mut thread, "NtClose", [handle])),
            STATUS_SUCCESS
        );
        assert_eq!(
            status(invoke(p, &mut thread, "NtDeviceIoControlFile", query)),
            STATUS_INVALID_HANDLE
        );
    }

    #[test]
    fn analysis_xvc_queue_checks_the_claim_cookie_and_registration_order() {
        let mut process = setup_launch(true, true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        let base = thread.cpu.sp() - 0x800;
        let (name, unicode, attributes) = (base, base + 0x40, base + 0x60);
        let (handle_out, io, input, cookie_out) =
            (base + 0x90, base + 0xa0, base + 0xb0, base + 0xd0);
        p.space
            .put_wstr(name, &r"\Device\xvcmgmt".encode_utf16().collect::<Vec<_>>())
            .unwrap();
        invoke(p, &mut thread, "RtlInitUnicodeString", [unicode, name]).unwrap();
        p.space.wr(attributes, &[0; 0x30]).unwrap();
        p.space.w32(attributes, 0x30).unwrap();
        p.space.w64(attributes + 0x10, unicode).unwrap();
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "NtOpenFile",
                [handle_out, 0x100003, attributes, io, 3, 0],
            )),
            STATUS_SUCCESS
        );
        let handle = p.space.u64(handle_out).unwrap();
        let event = u64::from(p.objects.insert(Object::Event {
            manual: false,
            signaled: 0,
        }));
        let mut control = [handle, event, 0, 0, io, 0x150098, input, 32, cookie_out, 8];
        // The first observed queue identifier, in Windows GUID byte order.
        p.space
            .wr(
                input,
                &[
                    0x6b, 0x41, 0x2a, 0xc1, 0x47, 0xf3, 0x5c, 0x40, 0xb7, 0x65, 0x2d, 0xe0, 0x27,
                    0xa6, 0x24, 0x9e,
                ],
            )
            .unwrap();
        p.space.wr(input + 16, &[0; 16]).unwrap();
        assert_eq!(
            status(invoke(p, &mut thread, "NtDeviceIoControlFile", control)),
            STATUS_ACCESS_DENIED
        );
        assert!(matches!(
            p.objects.get(event),
            Some(Object::Event { signaled: 0, .. })
        ));
        p.space.wr(input + 16, b"RAX GameOS Probe").unwrap();
        assert_eq!(
            status(invoke(p, &mut thread, "NtDeviceIoControlFile", control)),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u64(io + 8).unwrap(), 8);
        assert!(matches!(
            p.objects.get(event),
            Some(Object::Event { signaled: 1, .. })
        ));
        let cookie = p.space.u64(cookie_out).unwrap();
        assert_ne!(cookie, 0);

        control[5..].copy_from_slice(&[0x1500a0, input, 8, 0, 0]);
        p.space.w64(input, cookie ^ 1).unwrap();
        assert_eq!(
            status(invoke(p, &mut thread, "NtDeviceIoControlFile", control)),
            STATUS_INVALID_HANDLE
        );
        p.space.w64(input, cookie).unwrap();
        assert_eq!(
            status(invoke(p, &mut thread, "NtDeviceIoControlFile", control)),
            STATUS_SUCCESS
        );
        assert_eq!(
            status(invoke(p, &mut thread, "NtDeviceIoControlFile", control)),
            STATUS_INVALID_PARAMETER
        );
        let cancellation_out = base + 0xe0;
        let receive = [handle, 0, 0, 0x1234, io, 0x1500ac, input, 8, cookie_out, 8];
        assert_eq!(
            status(invoke(p, &mut thread, "NtDeviceIoControlFile", receive)),
            STATUS_PENDING
        );
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "NtCancelIoFileEx",
                [handle, io + 8, cancellation_out]
            )),
            STATUS_NOT_FOUND
        );
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "NtCancelIoFileEx",
                [handle, io, cancellation_out]
            )),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u64(io).unwrap(), u64::from(STATUS_CANCELLED));
        assert_eq!(p.space.u64(io + 8).unwrap(), 0);
        assert_eq!(p.space.u64(cookie_out).unwrap(), cookie);
        assert_eq!(p.space.u64(cancellation_out).unwrap(), 0);
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "NtCancelIoFileEx",
                [handle, io, cancellation_out]
            )),
            STATUS_NOT_FOUND
        );
        control[5] = 0x1500f4;
        assert_eq!(
            status(invoke(p, &mut thread, "NtDeviceIoControlFile", control)),
            STATUS_CONNECTION_ABORTED
        );
        assert!(matches!(
            p.objects.get(handle),
            Some(Object::GameOsXvcQueue {
                registered: true,
                bound: true,
                pending: None
            })
        ));
        control[5] = 0x1500b0;
        assert_eq!(
            status(invoke(p, &mut thread, "NtDeviceIoControlFile", control)),
            STATUS_SUCCESS
        );
        assert!(matches!(
            p.objects.get(handle),
            Some(Object::GameOsXvcQueue {
                registered: false,
                bound: false,
                ..
            })
        ));
    }

    #[test]
    fn duplicate_current_thread_pseudo_handle_can_be_closed() {
        let mut process = setup_launch(true, true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        let output = thread.cpu.sp() - 0x800;
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "NtDuplicateObject",
                [u64::MAX, u64::MAX - 1, u64::MAX, output, 0, 0, 2]
            )),
            STATUS_SUCCESS
        );
        let handle = p.space.u64(output).unwrap();
        assert_eq!(p.objects.id(handle), Some(thread.obj));
        for (other, expected) in [
            (u64::MAX - 1, STATUS_SUCCESS),
            (u64::MAX, STATUS_NOT_SAME_OBJECT),
            (0, STATUS_INVALID_HANDLE),
        ] {
            assert_eq!(
                status(invoke(p, &mut thread, "NtCompareObjects", [handle, other])),
                expected
            );
        }
        assert!(p.objects.close(handle).is_ok());
        assert!(p.objects.obj(thread.obj).is_some());
    }

    #[test]
    fn reverting_a_thread_without_an_impersonation_token_succeeds() {
        let mut process = setup_launch(true, true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        assert_eq!(status(invoke(p, &mut thread, "RevertToSelf", [])), 1);
    }

    #[test]
    fn rtl_and_win32_last_error_share_the_thread_teb_value() {
        let mut process = setup(false);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        invoke(p, &mut thread, "RtlSetLastWin32Error", [0x1122_3344]).unwrap();
        assert_eq!(
            status(invoke(p, &mut thread, "GetLastError", [])),
            0x1122_3344
        );
        invoke(p, &mut thread, "SetLastError", [7]).unwrap();
        assert_eq!(
            status(invoke(p, &mut thread, "RtlGetLastWin32Error", [])),
            7
        );
    }

    #[test]
    fn system_numa_available_memory_reports_the_single_guest_budget() {
        let mut process = setup(true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        let output = thread.cpu.sp() - 0x800;
        let returned = output + 0x408;
        let budget = p.vm.memory_usage().unwrap().available_bytes;
        p.space.w32(output + 4, 0x1234_5678).unwrap();
        p.space.w64(output + 16, u64::MAX).unwrap();
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "NtQuerySystemInformation",
                [60, output, 0x408, returned, 0],
            )),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u32(returned).unwrap(), 16);
        assert_eq!(p.space.u32(output).unwrap(), 0);
        assert_eq!(p.space.u64(output + 8).unwrap(), budget);
        assert_eq!(p.space.u32(output + 4).unwrap(), 0x1234_5678);
        assert_eq!(p.space.u64(output + 16).unwrap(), u64::MAX);
    }

    #[test]
    fn creates_a_partition_owned_64k_physical_section() {
        let mut process = setup(true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        let output = thread.cpu.sp() - 0x300;
        let maximum = output + 8;
        let parameters = output + 16;
        let partition = p
            .objects
            .insert(Object::MemoryPartition { partition_id: 1 });
        p.space.w64(maximum, 0).unwrap();
        p.space.w64(parameters, 1).unwrap();
        p.space.w64(parameters + 8, 1).unwrap();
        let args = [
            output,
            0xe,
            0,
            maximum,
            4,
            0x040c_0000,
            partition.into(),
            parameters,
            1,
        ];
        assert_eq!(
            status(invoke(p, &mut thread, "NtCreateSectionEx", args)),
            STATUS_SUCCESS
        );
        let section = p.space.u64(output).unwrap();
        assert_eq!(p.objects.access(section), Some(0xe));
        assert!(matches!(
            p.objects.get(section),
            Some(Object::GameOsPhysicalSection(section)) if section.partition_id == 1
        ));
        p.objects.close(partition.into()).unwrap();
        assert_eq!(
            status(invoke(p, &mut thread, "NtCreateSectionEx", args)),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(p.space.u64(output).unwrap(), section);
        assert_eq!(p.objects.get(section).unwrap().type_name(), "Section");
    }

    #[test]
    fn physical_reserve_rounds_to_64k_and_retains_its_section_until_release() {
        let mut process = setup(true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        let base_ptr = thread.cpu.sp() - 0x300;
        let size_ptr = base_ptr + 8;
        let parameters = base_ptr + 16;
        let section = std::sync::Arc::new(crate::user::windows::memory::GameOsPhysicalSection {
            partition_id: 1,
        });
        let weak = std::sync::Arc::downgrade(&section);
        let id = p.objects.create(Object::GameOsPhysicalSection(section));
        let handle = u64::from(p.objects.open_access(id, false, 0xe).unwrap());
        p.space.w64(base_ptr, 0).unwrap();
        p.space.w64(size_ptr, 0x1_0010).unwrap();
        for (index, entry) in [4, handle, 5, 8].into_iter().enumerate() {
            p.space.w64(parameters + index as u64 * 8, entry).unwrap();
        }
        let before = p.vm.committed_bytes();
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "NtAllocateVirtualMemoryEx",
                [
                    u64::MAX,
                    base_ptr,
                    size_ptr,
                    (mem::RESERVE | mem::PHYSICAL).into(),
                    prot::READWRITE.into(),
                    parameters,
                    2,
                ],
            )),
            STATUS_SUCCESS
        );
        let base = p.space.u64(base_ptr).unwrap();
        assert_eq!(base % 0x1_0000, 0);
        assert_eq!(p.space.u64(size_ptr).unwrap(), 0x2_0000);
        assert_eq!(p.vm.query(base).unwrap().state, mem::RESERVE);
        assert!(p.space.u8(base).is_err());
        assert_eq!(p.vm.committed_bytes(), before);
        assert!(p.vm.commit(base, PAGE_SIZE, prot::READWRITE).is_err());
        p.objects.close(handle).unwrap();
        assert!(weak.upgrade().is_some());
        assert_eq!(p.vm.release(base).unwrap(), 0x2_0000);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn xmem_graphics_reservation_and_nonpaged_commit_preserve_cpu_access() {
        for gameos in [false, true] {
            let mut process = setup(gameos);
            let p = process.state_mut();
            let mut thread = p.threads.pop_first().unwrap().1;
            let base = thread.cpu.sp() - 0x300;
            let size = base + 8;
            let parameter = base + 16;
            let address_requirement = parameter + 32;
            const LENGTH: u64 = 0x20_0000;
            let before = p.vm.committed_bytes();
            for (flags, protection, attributes, commit) in [
                (0x2040_2000, 0x801, 7, false),
                (0x2040_3000, 4, 6, true),
                (0x2000_3000, 0x2_2004, 0xd, true),
                (0x2000_3000, 0x2404, 0xd, true),
            ] {
                p.space.w64(base, 0).unwrap();
                p.space.w64(size, LENGTH).unwrap();
                p.space.w64(parameter, 5).unwrap();
                p.space.w64(parameter + 8, attributes).unwrap();
                p.space.w64(parameter + 16, 1).unwrap();
                p.space.w64(parameter + 24, address_requirement).unwrap();
                p.space.w64(address_requirement, 0x1_0000_0000).unwrap();
                p.space
                    .w64(address_requirement + 8, 0xff_ffff_ffff)
                    .unwrap();
                p.space.w64(address_requirement + 16, LENGTH).unwrap();
                let result = invoke(
                    p,
                    &mut thread,
                    "NtAllocateVirtualMemoryEx",
                    [u64::MAX, base, size, flags, protection, parameter, 2],
                );
                if !gameos {
                    assert_eq!(status(result), STATUS_INVALID_PARAMETER);
                    assert_eq!(p.space.u64(base).unwrap(), 0);
                    continue;
                }
                assert_eq!(status(result), STATUS_SUCCESS);
                let address = p.space.u64(base).unwrap();
                assert!((0x1_0000_0000..=0x100_0000_0000 - LENGTH).contains(&address));
                assert_eq!(address % LENGTH, 0);
                assert_eq!(p.space.u64(size).unwrap(), LENGTH);
                if commit {
                    assert_eq!(p.vm.committed_bytes(), before + LENGTH);
                    assert_eq!(
                        p.vm.query(address).unwrap().protect,
                        prot::READWRITE | (protection as u32 & prot::WRITECOMBINE)
                    );
                    assert_eq!(p.space.u8(address).unwrap(), 0);
                    p.space.w8(address, 0x7e).unwrap();
                    assert_eq!(p.space.u8(address).unwrap(), 0x7e);
                } else {
                    assert_eq!(p.vm.committed_bytes(), before);
                    assert_eq!(p.vm.query(address).unwrap().state, mem::RESERVE);
                    assert!(p.space.u8(address).is_err());
                }
                assert_eq!(p.vm.release(address).unwrap(), LENGTH);
                assert_eq!(p.vm.committed_bytes(), before);
            }
        }
    }

    #[test]
    fn privilege_scope_is_opt_in_and_requires_a_writable_result() {
        for gameos in [false, true] {
            let mut process = setup(gameos);
            let p = process.state_mut();
            let mut thread = p.threads.pop_first().unwrap().1;
            let input = thread.cpu.sp() - 0x80;
            let output = input + 8;
            let count = p.objects.handle_count();
            p.space.w32(input, SE_LOCK_MEMORY).unwrap();
            p.space.w64(output, u64::MAX).unwrap();
            let args = [input, 1, 2, output, 0];
            if !gameos {
                assert_eq!(
                    status(invoke(p, &mut thread, "RtlAcquirePrivilege", args)),
                    STATUS_PRIVILEGE_NOT_HELD
                );
                assert_eq!(p.space.u64(output).unwrap(), u64::MAX);
            } else {
                let mut fault = args;
                fault[3] = 0;
                assert!(matches!(
                    invoke(p, &mut thread, "RtlAcquirePrivilege", fault),
                    Err(ApiErr::Fault(_))
                ));
                assert_eq!(p.objects.handle_count(), count);
                assert_eq!(
                    status(invoke(p, &mut thread, "RtlAcquirePrivilege", args)),
                    STATUS_SUCCESS
                );
                let scope = p.space.u64(output).unwrap();
                assert!(matches!(
                    p.objects.get(scope),
                    Some(Object::GameOsLockMemoryScope)
                ));
                assert!(matches!(
                    invoke(p, &mut thread, "RtlReleasePrivilege", [scope, 0, 0, 0, 0]),
                    Ok(Flow::Ret(Value::None))
                ));
            }
            assert_eq!(p.objects.handle_count(), count);
        }
    }

    #[test]
    fn reports_only_the_gameos_product_identity() {
        let mut process = setup(true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        let descriptor = thread.cpu.sp() - 0x80;
        let string = descriptor + 0x10;
        let data = descriptor + 0x40;
        let name: Vec<u16> = "Kernel-ProductInfo".encode_utf16().collect();
        p.space.put_wstr(string, &name).unwrap();
        assert!(matches!(
            invoke(
                p,
                &mut thread,
                "RtlInitUnicodeString",
                [descriptor, string, 0, 0, 0]
            ),
            Ok(Flow::Ret(Value::None))
        ));
        assert_eq!(p.space.u16(descriptor).unwrap(), 36);
        assert_eq!(p.space.u16(descriptor + 2).unwrap(), 38);
        assert_eq!(p.space.u64(descriptor + 8).unwrap(), string);
        let kind = data + 4;
        let needed = data + 8;
        let args = [descriptor, kind, data, 4, needed];
        assert_eq!(
            status(invoke(p, &mut thread, "NtQueryLicenseValue", args)),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u32(data).unwrap(), 0xc2);
        assert_eq!(p.space.u32(kind).unwrap(), 4);
        assert_eq!(p.space.u32(needed).unwrap(), 4);
        p.space.w16(string, b'X'.into()).unwrap();
        assert!(invoke(p, &mut thread, "NtQueryLicenseValue", args).is_err());
    }

    #[test]
    fn analysis_primary_token_does_not_grant_duplication_rights() {
        let mut process = setup_launch(true, true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        let output = thread.cpu.sp() - 0x800;
        p.space.w64(output, 0x5a).unwrap();
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "OpenProcessToken",
                [u64::MAX, 0x2000a, output]
            )),
            0
        );
        assert_eq!(p.space.u64(output).unwrap(), 0x5a);
        let offset = crate::user::windows::layout::offsets(WinArch::X64).teb_last_error;
        assert_eq!(
            p.space.u32(thread.teb + offset).unwrap(),
            ERROR_NOT_SUPPORTED
        );
        assert_eq!(
            status(invoke(
                p,
                &mut thread,
                "OpenProcessToken",
                [u64::MAX, 8, output]
            )),
            1
        );
        assert_eq!(p.objects.access(p.space.u64(output).unwrap()), Some(8));
    }

    #[test]
    fn win32_token_query_reports_the_unprivileged_guest_process() {
        for gameos in [false, true] {
            let mut process = setup(gameos);
            let p = process.state_mut();
            let mut thread = p.threads.pop_first().unwrap().1;
            let data = thread.cpu.sp() - 0x80;
            let needed = data + 4;
            for (class, expected) in [(18, 1), (20, 0), (26, 0), (29, 0)] {
                p.space.w32(data, u32::MAX).unwrap();
                let result = invoke(
                    p,
                    &mut thread,
                    "GetTokenInformation",
                    [u64::MAX - 3, class, data, 4, needed],
                );
                if gameos {
                    assert_eq!(status(result), 1);
                    assert_eq!(p.space.u32(data).unwrap(), expected);
                    assert_eq!(p.space.u32(needed).unwrap(), 4);
                } else {
                    assert!(result.is_err());
                    assert_eq!(p.space.u32(data).unwrap(), u32::MAX);
                }
            }
            p.space.w64(data, 0x5a).unwrap();
            assert_eq!(
                status(invoke(
                    p,
                    &mut thread,
                    "OpenThreadToken",
                    [u64::MAX - 1, 4, 1, data, 0],
                )),
                0
            );
            assert_eq!(p.space.u64(data).unwrap(), 0x5a);
            let offset = crate::user::windows::layout::offsets(WinArch::X64).teb_last_error;
            assert_eq!(
                p.space.u32(thread.teb + offset).unwrap(),
                crate::user::windows::nt::error::ERROR_NO_TOKEN
            );
        }
    }

    #[test]
    fn partitions_have_distinct_ids_and_report_the_guest_budget() {
        let mut process = setup(true);
        let p = process.state_mut();
        let mut thread = p.threads.pop_first().unwrap().1;
        let page =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let output = page;
        let attrs = page + 0x10;
        let descriptor = page + 0x50;
        let name = page + 0x60;
        let info = page + 0x100;
        p.space.w32(attrs, 48).unwrap();
        p.space.w64(attrs + 16, descriptor).unwrap();
        p.space.w32(attrs + 24, OBJ_CASE_INSENSITIVE).unwrap();
        p.space.w64(descriptor + 8, name).unwrap();
        for (partition, id) in [
            (r"\kernelobjects\memorypartition0", Some(0)),
            (r"\GLOBAL??\MemoryPartitionXboxTitle", Some(1)),
            (r"\GLOBAL??\MemoryPartitionXboxTools", None),
        ] {
            let bytes: Vec<u8> = partition
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            p.space.w16(descriptor, bytes.len() as u16).unwrap();
            p.space.wr(name, &bytes).unwrap();
            p.space.w64(output, u64::MAX).unwrap();
            let open = [output, 1, attrs, 0, 0];
            let result = status(invoke(p, &mut thread, "NtOpenPartition", open));
            let Some(id) = id else {
                assert_eq!(result, STATUS_OBJECT_NAME_NOT_FOUND);
                assert_eq!(p.space.u64(output).unwrap(), u64::MAX);
                continue;
            };
            assert_eq!(result, STATUS_SUCCESS);
            let handle = p.space.u64(output).unwrap();
            let query = [handle, 0, 0, info, CONFIGURATION_BYTES as u64];
            assert_eq!(
                status(invoke(p, &mut thread, "NtManagePartition", query)),
                STATUS_SUCCESS
            );
            assert_eq!(p.space.u32(info + 0xe8).unwrap(), id);
            assert_eq!(
                p.space.u64(info + 0x30).unwrap(),
                p.vm.memory_usage().unwrap().total_physical_bytes / PAGE_SIZE
            );
            p.objects.close(handle).unwrap();
            assert_eq!(
                status(invoke(p, &mut thread, "NtManagePartition", query)),
                STATUS_INVALID_HANDLE
            );
        }
    }
}
