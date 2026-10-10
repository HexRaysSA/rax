//! Capture fixed NLS types and installed numeric code-page candidates only.
//! Guest services never call these native interfaces or retain host addresses.
use super::{MAX_SECTION_BYTES, MAX_TOTAL_BYTES, Nls, invalid};
use crate::user::windows::nt::status::STATUS_OBJECT_NAME_NOT_FOUND;
use crate::user::windows::registry::Registry;
use std::ffi::c_void;
use std::io;
use std::path::Path;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtGetNlsSectionPtr(
        kind: u32,
        data: u32,
        context: *const c_void,
        out: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
    fn NtUnmapViewOfSection(process: *mut c_void, address: *mut c_void) -> i32;
}
struct View(*mut c_void);
impl Drop for View {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: process-local mapped view returned by NtGetNlsSectionPtr.
            unsafe {
                NtUnmapViewOfSection((-1isize) as *mut c_void, self.0);
            }
        }
    }
}
fn capture(kind: u32, data: u32) -> io::Result<Option<Vec<u8>>> {
    let (mut address, mut size) = (std::ptr::null_mut(), 0);
    // SAFETY: fixed admitted type and a selection-time system numeric ID;
    // NULL context, exclusive correctly-sized native outputs; no guest input.
    let status =
        unsafe { NtGetNlsSectionPtr(kind, data, std::ptr::null(), &mut address, &mut size) };
    if status as u32 == STATUS_OBJECT_NAME_NOT_FOUND {
        return Ok(None);
    }
    if status < 0 {
        return Err(invalid_status("NtGetNlsSectionPtr", status));
    }
    let mut view = View(address);
    if address.is_null()
        || size == 0
        || size as usize > MAX_SECTION_BYTES
        || size % 4096 != 0
        || (address as usize).checked_add(size as usize).is_none()
    {
        return Err(invalid("installed NLS mapping exceeds bounds"));
    }
    // SAFETY: successful native call owns a readable process-local section of
    // its returned page-rounded size. Bounds are checked, no alias mutates it,
    // and ownership remains live until the complete byte copy has finished.
    let bytes = unsafe { std::slice::from_raw_parts(address.cast::<u8>(), size as usize) }.to_vec();
    // SAFETY: exclusive owned view in this process; no pointer escapes capture.
    let status = unsafe { NtUnmapViewOfSection((-1isize) as *mut c_void, address) };
    if status < 0 {
        return Err(invalid_status("NtUnmapViewOfSection", status));
    }
    view.0 = std::ptr::null_mut();
    Ok(Some(bytes))
}
fn invalid_status(name: &str, status: i32) -> io::Error {
    io::Error::other(format!(
        "installed NLS {name} returned NTSTATUS {:#010x}",
        status as u32
    ))
}
pub(crate) fn snapshot(registry: &Registry, directory: &Path) -> io::Result<Nls> {
    let mut codes = registry.codepages();
    // Fixed system-directory namespace enumeration, never a guest-selected
    // path. Include installed C_<decimal>.NLS files without registry entries.
    for entry in std::fs::read_dir(directory)? {
        let name = entry?.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let name = name.to_ascii_lowercase();
        if let Some(number) = name.strip_prefix("c_").and_then(|s| s.strip_suffix(".nls"))
            && !number.is_empty()
            && number.bytes().all(|b| b.is_ascii_digit())
            && let Ok(code) = number.parse::<u32>()
        {
            codes.insert(code);
        }
    }
    if codes.len() > 4096 {
        return Err(invalid("too many installed NLS code-page candidates"));
    }
    let candidates = codes
        .into_iter()
        .map(|code| (11, code))
        .chain([1, 2, 5, 6, 13].into_iter().map(|form| (12, form)))
        .chain([(14, 0)]);
    let (mut sections, mut total) = (Vec::new(), 0usize);
    for key in candidates {
        if let Some(bytes) = capture(key.0, key.1)? {
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| invalid("NLS size overflow"))?;
            if total > MAX_TOTAL_BYTES {
                return Err(invalid("installed NLS snapshot exceeds 64 MiB"));
            }
            sections.push((key, bytes));
        }
    }
    Nls::new(sections)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installed_nls_section_bytes_match_independent_files_and_padding() {
        let registry = crate::user::windows::registry::snapshot().unwrap();
        let arch = if cfg!(target_arch = "aarch64") {
            crate::user::windows::arch::WinArch::Arm64
        } else if cfg!(target_arch = "x86_64") {
            crate::user::windows::arch::WinArch::X64
        } else {
            crate::user::windows::arch::WinArch::X86
        };
        let runtime = crate::user::windows::native::NativeRuntime::select(arch).unwrap();
        let directory = std::path::Path::new(&runtime.guest_root).join("System32");
        let nls = snapshot(&registry, &directory).unwrap();
        for (kind, data, name) in [
            (11, 1252, "c_1252.nls"),
            (11, 437, "c_437.nls"),
            (12, 1, "normnfc.nls"),
            (12, 2, "normnfd.nls"),
            (12, 5, "normnfkc.nls"),
            (12, 6, "normnfkd.nls"),
            (12, 13, "normidna.nls"),
            (14, 0, "l_intl.nls"),
        ] {
            let file = std::fs::read(directory.join(name)).unwrap();
            let bytes = nls.section(kind, data).unwrap();
            assert_eq!(bytes.len(), (file.len() + 4095) & !4095, "{name}");
            assert_eq!(&bytes[..file.len()], file.as_slice(), "{name}");
            assert!(bytes[file.len()..].iter().all(|&b| b == 0), "{name}");
        }
    }
}
