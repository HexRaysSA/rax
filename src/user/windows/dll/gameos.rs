//! Portable GameOS system services.
//!
//! The guest system and title partitions share the emulator's memory budget.
//! Named tools partitions and operations that change memory ownership are absent.

use super::super::{
    WinArch,
    hle::{ApiErr, ApiResult, Archs, Arg::*, Conv::Stdcall, Ctx, Export, Flow},
    memory::{Mem, MemFault},
    nt::status::*,
    objects::Object,
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
        let mut config = WindowsConfig::new("gameos-test.exe", Vec::new());
        config.gameos = gameos;
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
            .chain(crate::user::windows::dll::native::EXPORTS)
            .chain(crate::user::windows::dll::native::EXTENDED_SECTION_CREATE_EXPORTS)
            .chain(crate::user::windows::dll::rtl_string::EXPORTS)
            .chain(crate::user::windows::dll::native::WIN32_TOKEN_EXPORTS)
            .chain(crate::user::windows::dll::kernel::NTDLL_LAST_ERROR_EXPORTS)
            .chain(crate::user::windows::dll::kernel::EXPORTS)
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

    fn status(result: ApiResult) -> u32 {
        match result.unwrap() {
            Flow::Ret(Value::Int(value)) => value.try_into().unwrap(),
            _ => panic!("expected a status return"),
        }
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
