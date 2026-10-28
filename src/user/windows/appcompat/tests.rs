use super::*;

fn variable(kind: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = kind.to_le_bytes().to_vec();
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    if bytes.len() % 2 != 0 {
        bytes.push(0xdb);
    }
    bytes
}

fn number(kind: u16, value: u32) -> Vec<u8> {
    let mut bytes = kind.to_le_bytes().to_vec();
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes
}

fn database(entries: &[(&str, u32)]) -> Vec<u8> {
    let mut strings = Vec::new();
    let mut records = Vec::new();
    for (name, flags) in entries {
        let reference = 6 + strings.len() as u32;
        let mut units: Vec<_> = name
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        strings.extend(variable(0x8801, &units));
        units = number(0x6001, reference);
        units.extend(number(0x4032, *flags));
        // A nested conflicting flag is not a direct executable flag.
        units.extend(variable(0x7008, &number(0x4032, 0x8000_0000)));
        records.extend(variable(0x7007, &units));
    }
    let mut result = b"\x03\0\0\0\0\0\0\0sdbf".to_vec();
    result.extend(variable(0x7001, &records));
    result.extend(variable(0x7801, &strings));
    result
}

fn parse(bytes: &[u8]) -> io::Result<Catalog> {
    Catalog::parse(bytes, Catalog::fixture(&[]).upcase)
}

#[test]
fn appcompat_sdb_counted_names_fold_merge_and_ignore_nested_flags() {
    let input = database(&[("Alpha.dll", 0x10), ("ALPHA.DLL", 0x80), ("Beta.exe", 1)]);
    let catalog = parse(&input).unwrap();
    for (name, expected) in [
        ("alpha.dll", 0x90),
        ("BETA.EXE", 1),
        ("missing.dll", 0),
        ("Alpha.dll\0", 0),
        ("C:\\Alpha.dll", 0),
    ] {
        assert_eq!(
            catalog.lookup(&name.encode_utf16().collect::<Vec<_>>()),
            expected
        );
    }
    assert_eq!(catalog.flags.len(), 2);
    assert_eq!(Catalog::default().lookup(&[0xffff]), 0);
}

#[test]
fn appcompat_sdb_odd_binary_and_byte_payloads_preserve_word_tag_alignment() {
    // Installed 0x7033 contains 17 binary bytes, pad0xDB, then DWORD0x4053.
    let mut payload = variable(0x9013, b"ProductVersion=9.");
    payload.extend(number(0x4053, 2));
    let mut list = variable(0x7033, &payload);
    list.extend_from_slice(&[1, 0x20, 0x7f, 0xdb]);
    list.extend(number(0x4032, 0x80));
    let mut input = database(&[("Alpha.dll", 0x80)]);
    input.extend(variable(0x7008, &list));
    let catalog = parse(&input).unwrap();
    assert_eq!(
        catalog.lookup(&"Alpha.dll".encode_utf16().collect::<Vec<_>>()),
        0x80
    );
    let mut bad = variable(0x7008, &variable(0x9013, b"x"));
    bad.pop();
    let mut broken = database(&[("Alpha.dll", 0x80)]);
    broken.extend(bad);
    assert!(parse(&broken).is_err());
}

#[test]
fn appcompat_sdb_rejects_truncation_bad_extent_reference_and_duplicates() {
    let input = database(&[("Alpha.dll", 0x80)]);
    for length in 0..input.len() {
        assert!(parse(&input[..length]).is_err(), "prefix={length}");
    }
    for (at, value) in [(0, 4), (8, 0), (12, 0xff), (14, 0xff), (26, 0xff)] {
        let mut changed = input.clone();
        changed[at] = value;
        assert!(parse(&changed).is_err(), "corruption at {at}");
    }
    let mut duplicated = input.clone();
    duplicated.extend_from_slice(&input[12..]);
    assert!(parse(&duplicated).is_err());
    let mut broken_string = input.clone();
    *broken_string.last_mut().unwrap() = 1;
    assert!(parse(&broken_string).is_err());
    let mut wrong_type = input.clone();
    let at = wrong_type
        .windows(2)
        .rposition(|w| w == [0x01, 0x88])
        .unwrap();
    wrong_type[at] = 2;
    assert!(parse(&wrong_type).is_err());
    assert!(Catalog::parse(&input, Arc::from([0u16])).is_err());
}

#[test]
fn appcompat_sdb_rejects_depth_empty_name_and_name_budget() {
    let mut nested = number(0x4032, 1);
    for _ in 0..34 {
        nested = variable(0x7008, &nested);
    }
    let mut input = b"\x03\0\0\0\0\0\0\0sdbf".to_vec();
    input.extend(variable(0x7001, &nested));
    input.extend(variable(0x7801, &[]));
    assert!(parse(&input).is_err());
    assert!(parse(&database(&[("", 1)])).is_err());
    let name = "a".repeat(32_767);
    assert!(parse(&database(&[(&name, 1)])).is_err());
    let entries = vec![("a", 1); MAX_NAMES + 1];
    assert!(parse(&database(&entries)).is_err());
}

#[test]
fn appcompat_sdb_snapshot_reads_owned_regular_file_and_rejects_escape() {
    let root = std::env::temp_dir().join(format!(
        "rax-appcompat-{}-{}",
        std::process::id(),
        crate::host::time::system_now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0.join("AppPatch").join("sysmain.sdb"));
            let _ = std::fs::remove_file(self.0.join("outside.sdb"));
            let _ = std::fs::remove_dir(self.0.join("AppPatch"));
            let _ = std::fs::remove_dir(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    let directory = root.join("AppPatch");
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("sysmain.sdb");
    let data = database(&[("Alpha.dll", 0x80)]);
    std::fs::write(&path, &data).unwrap();
    let catalog = Catalog::snapshot(&root, Catalog::fixture(&[]).upcase).unwrap();
    assert_eq!(
        catalog.lookup(&"ALPHA.DLL".encode_utf16().collect::<Vec<_>>()),
        0x80
    );
    std::fs::remove_file(&path).unwrap();
    assert!(Catalog::snapshot(&root, Catalog::fixture(&[]).upcase).is_err());
    #[cfg(unix)]
    {
        let outside = root.join("outside.sdb");
        std::fs::write(&outside, &data).unwrap();
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        assert_eq!(
            Catalog::snapshot(&root, Catalog::fixture(&[]).upcase)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}

#[cfg(windows)]
#[test]
fn appcompat_installed_file_catalog_matches_live_kernel_name_flags() {
    use crate::user::windows::arch::WinArch;
    use std::ffi::c_void;
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtApphelpCacheControl(operation: u32, context: *mut c_void) -> i32;
    }
    let arch = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let runtime = crate::user::windows::native::NativeRuntime::select(arch).unwrap();
    let catalog = &runtime.appcompat;
    assert!(
        !catalog.flags.is_empty(),
        "installed base catalog has no flag candidates"
    );
    let name_at = if arch.is64() { 248 } else { 132 };
    let out_at = if arch.is64() { 376 } else { 196 };
    let width = std::mem::size_of::<usize>();
    let unknown: Vec<_> = "rax-cdb-control-6a52e834-62d6-41fb-918f.dll"
        .encode_utf16()
        .collect();
    let mut checked = 0;
    for name in catalog.flags.keys().chain(std::iter::once(&unknown)) {
        let length = name.len() * 2;
        let text: Vec<_> = name.iter().copied().chain([0]).collect();
        let mut packet = [0u8; 512];
        packet[name_at..name_at + 2].copy_from_slice(&(length as u16).to_le_bytes());
        packet[name_at + 2..name_at + 4].copy_from_slice(&((length + 2) as u16).to_le_bytes());
        let name_pointer = text.as_ptr() as usize;
        packet[name_at + width..name_at + width * 2].copy_from_slice(&name_pointer.to_le_bytes());
        let mut output = 0xa5a5_a5a5u32;
        let output_pointer = (&mut output as *mut u32) as usize;
        packet[out_at..out_at + width].copy_from_slice(&output_pointer.to_le_bytes());
        packet[out_at + width..out_at + width + 4].copy_from_slice(&4u32.to_le_bytes());
        // SAFETY: measured host ABI and read-only operation6; all context,
        // counted UTF-16 and aligned output storage is initialized and owned
        // by this test for the entire call. No guest pointer or input is used.
        let status = unsafe { NtApphelpCacheControl(6, packet.as_mut_ptr().cast()) };
        assert_eq!(status, 0, "native lookup for {name:?}");
        assert_eq!(
            catalog.lookup(name),
            output,
            "live selected CDB flags for {name:?}"
        );
        checked += 1;
    }
    eprintln!("live installed CDB controls: {checked} including one unknown name");
}
