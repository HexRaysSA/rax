//! Fixed host acquisition; directory/link handles close and image sections pin identity.
use super::*;
use std::ffi::c_void;
use std::ptr::null_mut;
mod csr;
mod data;
mod directory_alias;
pub(super) mod file_image;
pub(super) mod gui;
pub(super) mod image;
mod section;
type Handle = *mut c_void;
#[repr(C)]
#[derive(Clone, Copy)]
struct Unicode {
    length: u16,
    maximum: u16,
    buffer: *mut u16,
}
#[repr(C)]
struct Attributes {
    length: u32,
    root: Handle,
    name: *mut Unicode,
    flags: u32,
    security: *mut c_void,
    qos: *mut c_void,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Info {
    name: Unicode,
    kind: Unicode,
}
const _: [(); if std::mem::size_of::<usize>() == 8 {
    48
} else {
    24
}] = [(); std::mem::size_of::<Attributes>()];
#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlGetNtSystemRoot() -> *const u16;
    fn NtOpenDirectoryObject(out: *mut Handle, access: u32, attributes: *mut Attributes) -> i32;
    fn NtQueryDirectoryObject(
        handle: Handle,
        buffer: *mut c_void,
        length: u32,
        single: u8,
        restart: u8,
        context: *mut u32,
        returned: *mut u32,
    ) -> i32;
    fn NtQueryObject(
        handle: Handle,
        class: u32,
        buffer: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
    fn NtOpenSymbolicLinkObject(out: *mut Handle, access: u32, attributes: *mut Attributes) -> i32;
    fn NtQuerySymbolicLinkObject(handle: Handle, target: *mut Unicode, returned: *mut u32) -> i32;
    fn NtClose(handle: Handle) -> i32;
}
struct Owned(Handle);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: exclusive successful native open; no retained guest/native aliases.
            unsafe {
                NtClose(self.0);
            }
        }
    }
}
impl Owned {
    fn close(mut self) -> io::Result<()> {
        let h = self.0;
        self.0 = null_mut(); // SAFETY: h is the sole owned successful open and is consumed exactly once.
        let s = unsafe { NtClose(h) };
        check(s, "NtClose selected NT directory/link")
    }
}
fn check(s: i32, what: &str) -> io::Result<()> {
    if s < 0 {
        Err(invalid(&format!("{what}: {:#010x}", s as u32)))
    } else {
        Ok(())
    }
}
fn open(
    path: &[u16],
    root: Handle,
    access: u32,
    link: bool,
    flags: u32,
) -> io::Result<Result<Owned, u32>> {
    if path.len() > MAX_UNITS {
        return Err(invalid("selected NT host name exceeds bounds"));
    }
    let mut storage = path.to_vec();
    let mut name = Unicode {
        length: (storage.len() * 2) as u16,
        maximum: (storage.len() * 2) as u16,
        buffer: storage.as_mut_ptr(),
    };
    let mut attrs = Attributes {
        length: std::mem::size_of::<Attributes>() as u32,
        root,
        name: &mut name,
        flags,
        security: null_mut(),
        qos: null_mut(),
    };
    let mut h = null_mut();
    // SAFETY: initialized repr(C) native structures, bounded live UTF-16 backing,
    // optional live owned root, exclusive HANDLE output. APIs retain no pointers.
    let s = unsafe {
        if link {
            NtOpenSymbolicLinkObject(&mut h, access, &mut attrs)
        } else {
            NtOpenDirectoryObject(&mut h, access, &mut attrs)
        }
    };
    if s < 0 {
        return Ok(Err(s as u32));
    }
    if h.is_null() {
        return Err(invalid("native NT open returned a NULL successful handle"));
    }
    Ok(Ok(Owned(h)))
}
fn text(buffer: &[u64], u: Unicode) -> io::Result<Vec<u16>> {
    let start = buffer.as_ptr() as usize;
    let bytes = std::mem::size_of_val(buffer);
    let at = u.buffer as usize;
    let length = usize::from(u.length);
    if length % 2 != 0
        || at % 2 != 0
        || at < start
        || at - start > bytes
        || length > bytes - (at - start)
        || length / 2 > MAX_UNITS
    {
        return Err(invalid(
            "native NT enumeration string is outside its buffer",
        ));
    }
    // SAFETY: checked even length/alignment and containment in initialized,
    // exclusively owned acquisition scratch. Returned data is copied, not retained.
    Ok(unsafe { std::slice::from_raw_parts(u.buffer, length / 2) }.to_vec())
}
fn enumerate(h: &Owned) -> io::Result<Vec<CapturedEntry>> {
    let mut scratch = vec![0u64; 16384];
    let mut context = 0u32;
    let mut entries = Vec::new();
    loop {
        let mut returned = 0;
        scratch.fill(0);
        // SAFETY: live owned directory, aligned initialized 128 KiB output, exact
        // byte capacity, exclusive native ULONG counters, no retained output pointer.
        let s = unsafe {
            NtQueryDirectoryObject(
                h.0,
                scratch.as_mut_ptr().cast(),
                (scratch.len() * 8) as u32,
                1,
                0,
                &mut context,
                &mut returned,
            )
        };
        if s as u32 == STATUS_NO_MORE_ENTRIES {
            break;
        }
        check(s, "NtQueryDirectoryObject selected namespace")?;
        if returned as usize > scratch.len() * 8
            || (returned as usize) < std::mem::size_of::<Info>()
            || entries.len() >= MAX_ENTRIES
        {
            return Err(invalid("native NT directory enumeration exceeds bounds"));
        }
        // SAFETY: scratch is aligned for the native repr(C) record; returned extent
        // contains that record, and both pointed-to strings are separately bounded.
        let info = unsafe { std::ptr::read(scratch.as_ptr().cast::<Info>()) };
        entries.push(CapturedEntry {
            section: None,
            name: text(&scratch, info.name)?,
            kind: text(&scratch, info.kind)?,
            target: None,
            link_access: None,
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}
fn target(parent: &Owned, name: &[u16]) -> io::Result<(Vec<u16>, LinkAccess)> {
    let link = open(name, parent.0, 0x0200_0000, true, 0x40)?
        .map_err(|s| invalid(&format!("selected NT symbolic-link open: {s:#010x}")))?;
    let maximum_access = basic(&link)?;
    if maximum_access & 1 == 0 || maximum_access & !0x000F_0001 != 0 {
        return Err(invalid(
            "selected NT symbolic-link authorization ceiling changed",
        ));
    }
    let system_security_status = match open(name, parent.0, 0x0100_0000, true, 0x40)? {
        Ok(security) => {
            if basic(&security)? != 0x0100_0000 {
                return Err(invalid("selected link system-security grant changed"));
            }
            security.close()?;
            0
        }
        Err(s @ (STATUS_PRIVILEGE_NOT_HELD | STATUS_ACCESS_DENIED)) => s,
        Err(s) => {
            return Err(invalid(&format!(
                "selected link system-security capture: {s:#010x}"
            )));
        }
    };
    let mut units = vec![0u16; 32767];
    let mut descriptor = Unicode {
        length: 0,
        maximum: (units.len() * 2) as u16,
        buffer: units.as_mut_ptr(),
    };
    let mut returned = 0;
    // SAFETY: live query-only link, initialized native descriptor and exclusive
    // bounded UTF-16 destination. Query does not retain either pointer.
    let s = unsafe { NtQuerySymbolicLinkObject(link.0, &mut descriptor, &mut returned) };
    check(s, "NtQuerySymbolicLinkObject selected NT symbolic-link")?;
    if descriptor.length % 2 != 0
        || usize::from(descriptor.length) > units.len() * 2
        || descriptor.buffer != units.as_mut_ptr()
        || returned > units.len() as u32 * 2
    {
        return Err(invalid("selected NT symbolic-link exceeds output bounds"));
    }
    units.truncate(usize::from(descriptor.length) / 2);
    if basic(&link)? != maximum_access {
        return Err(invalid(
            "selected NT symbolic-link grant changed during capture",
        ));
    }
    link.close()?;
    Ok((
        units,
        LinkAccess {
            maximum_access,
            system_security_status,
        },
    ))
}
fn basic(h: &Owned) -> io::Result<u32> {
    let mut data = [0u32; 14];
    let mut returned = 0;
    // SAFETY: initialized 56-byte OBJECT_BASIC_INFORMATION storage, live handle,
    // exclusive returned-length ULONG. Only GrantedAccess is retained.
    let s = unsafe { NtQueryObject(h.0, 0, data.as_mut_ptr().cast(), 56, &mut returned) };
    check(s, "NtQueryObject selected directory access")?;
    if returned != 56 {
        return Err(invalid("selected directory basic-information size changed"));
    }
    Ok(data[1])
}
fn forced_case(path: &[u16], h: &Owned, entries: &[CapturedEntry]) -> io::Result<bool> {
    let probe = |name: &[u16], flags: u32| -> io::Result<u32> {
        match open(name, h.0, 1, false, flags)? {
            Ok(handle) => {
                handle.close()?;
                Ok(0)
            }
            Err(status) => Ok(status),
        }
    };
    // A live namespace can remove a sampled child after enumeration. Try a
    // bounded set of candidates, and never infer policy from a missing child.
    for sample in entries
        .iter()
        .filter(|e| {
            e.name
                .iter()
                .any(|u| (65..=90).contains(u) || (97..=122).contains(u))
        })
        .take(16)
    {
        let altered: Vec<_> = sample
            .name
            .iter()
            .map(|&u| {
                if (65..=90).contains(&u) {
                    u + 32
                } else if (97..=122).contains(&u) {
                    u - 32
                } else {
                    u
                }
            })
            .collect();
        if let Some(policy) = case_probe_policy(
            probe(&sample.name, 0)?,
            probe(&altered, 0)?,
            probe(&altered, 0x40)?,
        ) {
            return Ok(policy);
        }
    }
    Err(invalid(&format!(
        "selected NT directory has no stable accessible case-policy sample: {}",
        String::from_utf16_lossy(path)
    )))
}
fn system_root() -> io::Result<Vec<u16>> {
    // SAFETY: the installed native export returns the current process's stable
    // NUL-terminated NT system root, backed by shared-user/silo data. The native
    // root buffer holds at most 260 WCHARs; no guest pointer crosses this call.
    let pointer = unsafe { RtlGetNtSystemRoot() };
    if pointer.is_null() {
        return Err(invalid("native NT system root is NULL"));
    }
    let mut root = Vec::new();
    for index in 0..260 {
        // SAFETY: bounded scan of that live native root buffer, stopping at NUL.
        let unit = unsafe { pointer.add(index).read() };
        if unit == 0 {
            return Ok(root);
        }
        root.push(unit);
    }
    Err(invalid(
        "native NT system root is not terminated within 260 WCHARs",
    ))
}
pub(crate) fn snapshot(upcase: Arc<[u16]>, session: u32) -> io::Result<Namespace> {
    let mut sources = Vec::new();
    let mut selected: Vec<SelectedDirectory> = Vec::new();
    let mut incomplete = Vec::new();
    // Retain the exact captured objects until any alias identity comparison.
    // The fixed selection bounds this to at most ten directory handles.
    let mut handles = Vec::new();
    let session_parent: Vec<u16> = format!("\\Sessions\\{session}").encode_utf16().collect();
    let session_windows: Vec<u16> = format!("\\Sessions\\{session}\\Windows")
        .encode_utf16()
        .collect();
    for units in selection_paths(Some(session)) {
        // A captured current-session Windows link is parsed through its pinned
        // absolute target. Do not manufacture a second Directory node for it.
        if units == session_windows
            && selected
                .iter()
                .find(|directory| directory.path == session_parent)
                .and_then(|directory| {
                    directory
                        .entries
                        .iter()
                        .find(|entry| is(&entry.name, "Windows"))
                })
                .is_some_and(|entry| is(&entry.kind, "SymbolicLink"))
        {
            continue;
        }
        let path =
            String::from_utf16(&units).map_err(|_| invalid("selected NT path is not UTF-16"))?;
        let h = match open(&units, null_mut(), 0x0200_0000, false, 0x40)? {
            Ok(h) => h,
            Err(STATUS_OBJECT_NAME_NOT_FOUND) if path == PATHS[2] || path == PATHS[3] => continue,
            Err(s) => return Err(invalid(&format!("selected NT directory {path}: {s:#010x}"))),
        };
        let maximum_access = basic(&h)?;
        // Capture the current host subject without enabling any privilege or
        // forwarding guest-desired rights to the host. MAXIMUM_ALLOWED excludes
        // ACCESS_SYSTEM_SECURITY even when SeSecurityPrivilege is enabled.
        let system_security_status = match open(&units, null_mut(), 0x0100_0000, false, 0x40)? {
            Ok(security) => {
                if basic(&security)? != 0x0100_0000 {
                    return Err(invalid("selected NT system-security grant changed"));
                }
                security.close()?;
                0
            }
            Err(s @ (STATUS_PRIVILEGE_NOT_HELD | STATUS_ACCESS_DENIED)) => s,
            Err(s) => {
                return Err(invalid(&format!(
                    "selected NT system-security capture: {s:#010x}"
                )));
            }
        };
        let mut entries = None;
        let mut last = None;
        for _ in 0..3 {
            let first = enumerate(&h)?;
            let second = enumerate(&h)?;
            if entries_coherent(&upcase, &first, &second) {
                entries = Some(first);
                break;
            }
            last = Some((first, second));
        }
        let mut entries = match entries {
            Some(entries) => entries,
            None if !image_directory(&units) => {
                let (first, second) = last.expect("three bounded captures were attempted");
                incomplete.push(units.clone());
                stable_volatile_entries(&upcase, &first, &second)
                    .ok_or_else(|| invalid("partial NT directory capture exceeds bounds"))?
            }
            None => {
                return Err(invalid(&format!(
                    "selected image directory changed during bounded capture: {path}"
                )));
            }
        };
        let force_case_insensitive = forced_case(&units, &h, &entries)?;
        if image_directory(&units) {
            for entry in &mut entries {
                if is(&entry.kind, "Section") {
                    let (captured, source) = section::capture(&units, &entry.name)?;
                    let path: Vec<_> = units
                        .iter()
                        .copied()
                        .chain([92])
                        .chain(entry.name.iter().copied())
                        .collect();
                    entry.section = Some(captured);
                    sources.push((path, source));
                }
            }
        }
        // These are object-manager directory links, distinct from native DOS
        // KnownDllPath values. Capture bounded metadata now; guest parsing uses
        // only this immutable copy and selected directory identities.
        let base_directory =
            units.ends_with(&"\\BaseNamedObjects".encode_utf16().collect::<Vec<_>>());
        for entry in &mut entries {
            let known_dll = image_directory(&units) && is(&entry.name, "KnownDllPath");
            let base_link = base_directory
                && ["Local", "Global", "Session"]
                    .iter()
                    .any(|name| is(&entry.name, name));
            let session_link = units == session_parent
                && (is(&entry.name, "Windows")
                    || session != 0 && is(&entry.name, "BaseNamedObjects"));
            if is(&entry.kind, "SymbolicLink") && (known_dll || base_link || session_link) {
                let (target, access) = target(&h, &entry.name)?;
                entry.target = Some(target);
                entry.link_access = Some(access);
            }
        }
        if basic(&h)? != maximum_access {
            return Err(invalid(
                "selected NT directory grant changed during capture",
            ));
        }
        handles.push((units.clone(), h));
        selected.push(SelectedDirectory {
            path: units,
            maximum_access,
            system_security_status,
            force_case_insensitive,
            entries,
        });
    }
    let windows_uses_global = directory_alias::verified_windows(&selected, &handles, session)?;
    let aliases = directory_alias::verified(&selected, &handles, session)?;
    for (_, handle) in handles {
        handle.close()?;
    }
    let mut namespace = Namespace::selected_with_directory_aliases(
        upcase,
        selected,
        Some(session),
        &incomplete,
        &aliases,
    )?;
    for (path, source) in sources {
        let section = namespace
            .lookup_section(None, &path, 0x40, false)
            .map_err(|_| invalid("pinned section disappeared from selected namespace"))?;
        section
            .source
            .set(source)
            .map_err(|_| invalid("selected section already has a native source"))?;
    }
    let native_machine = section::native_machine()?;
    namespace.native_machine = native_machine;
    #[cfg(target_pointer_width = "64")]
    {
        // Capture the host kernel's native query capability before guest
        // execution. Guest queries never call the host or infer availability
        // from whether their particular image happens to contain payload.
        let ntdll = namespace
            .lookup_section(
                None,
                &"\\KnownDlls\\ntdll.dll".encode_utf16().collect::<Vec<_>>(),
                0x40,
                false,
            )
            .map_err(|_| invalid("native image-query authority is not selected"))?;
        namespace.image_extension_query = Some(ntdll.image()?.extension_query);
    }
    let arm64 = match native_machine {
        Some(value) => value == 0xAA64,
        None => match namespace.lookup(
            None,
            &"\\KnownDllsChpe32".encode_utf16().collect::<Vec<_>>(),
            0x40,
        ) {
            Err(LookupError::Status(STATUS_OBJECT_NAME_NOT_FOUND)) => false,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "selected CHPE namespace requires native host architecture detection",
                ));
            }
        },
    };
    // Preserve the global section independently. Only the current session's
    // section can be bound to this host process's initialized CSR client data.
    let (mut section, mut csr) = data::capture(None, windows_uses_global)?;
    namespace.select_data_section(section.clone())?;
    if !windows_uses_global {
        (section, csr) = data::capture(Some(session), true)?;
        namespace.select_data_section(section.clone())?;
    }
    if let Some(metadata) = csr {
        let client_data = csr::capture_client_data(&metadata)?;
        namespace.select_csr_server(super::csr::CsrServer::selected_with_client_data(
            section,
            metadata,
            client_data,
        )?)?;
    }
    namespace.select_wow_section_root(arm64)?;
    namespace.select_wow_system_root(&system_root()?)?;
    Ok(namespace)
}
