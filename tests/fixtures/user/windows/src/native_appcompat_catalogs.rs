use std::collections::BTreeSet;
use std::ffi::c_void;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[path = "../../../../../src/user/windows/appcompat.rs"]
mod appcompat;
use appcompat::Catalog;

const MAX_FILE_BYTES: u64 = 64 << 20;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtApphelpCacheControl(operation: u32, context: *mut c_void) -> i32;
    fn RtlUpcaseUnicodeChar(unit: u16) -> u16;
}

#[repr(align(16))]
struct Packet([u8; 512]);

fn native_lookup(name: &[u16]) -> (i32, u32) {
    let width = size_of::<usize>();
    let (name_at, output_at) = if width == 8 { (248, 376) } else { (132, 196) };
    let text: Vec<_> = name.iter().copied().chain([0]).collect();
    let length = u16::try_from(name.len() * 2).unwrap();
    let limit = length.checked_add(2).unwrap();
    let mut packet = Packet([0; 512]);
    packet.0[name_at..name_at + 2].copy_from_slice(&length.to_le_bytes());
    packet.0[name_at + 2..name_at + 4].copy_from_slice(&limit.to_le_bytes());
    packet.0[name_at + width..name_at + width * 2]
        .copy_from_slice(&(text.as_ptr() as usize).to_le_bytes());
    let mut output = 0xa5a5_a5a5u32;
    packet.0[output_at..output_at + width]
        .copy_from_slice(&((&mut output as *mut u32) as usize).to_le_bytes());
    packet.0[output_at + width..output_at + width + 4].copy_from_slice(&4u32.to_le_bytes());
    // SAFETY: the aligned packet, counted UTF-16 name and output word are
    // initialized, disjoint and live for this read-only lookup.
    let status = unsafe { NtApphelpCacheControl(6, packet.0.as_mut_ptr().cast()) };
    (status, output)
}

fn installed_files(root: &Path) -> io::Result<BTreeSet<PathBuf>> {
    let mut files = BTreeSet::new();
    for directory in [
        root.to_owned(),
        root.join("AppPatch64"),
        root.join("AppPatchArm64"),
    ] {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !directory.canonicalize()?.starts_with(root) {
            return Err(io::Error::other(
                "installed AppPatch directory escaped its root",
            ));
        }
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy().to_ascii_lowercase();
            if (name == "sysmain.sdb" || name.ends_with(".sysmain.sdb"))
                && entry.file_type()?.is_file()
            {
                let path = entry.path().canonicalize()?;
                if !path.starts_with(root) {
                    return Err(io::Error::other("installed SDB escaped AppPatch"));
                }
                files.insert(path);
            }
        }
    }
    Ok(files)
}

fn load(path: &Path, upcase: Arc<[u16]>) -> io::Result<Catalog> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    Catalog::parse(&bytes, upcase)
}

fn main() -> io::Result<()> {
    let root = PathBuf::from(std::env::var_os("SystemRoot").expect("Windows system root"))
        .join("AppPatch")
        .canonicalize()?;
    let files = installed_files(&root)?;
    assert!(
        !files.is_empty() && files.len() <= 32,
        "Unexpected installed SDB count"
    );
    let upcase: Arc<[u16]> = (0..=u16::MAX)
        .map(|unit| {
            // SAFETY: RtlUpcaseUnicodeChar takes one UTF-16 code unit by
            // value and returns its installed upcase-table value.
            unsafe { RtlUpcaseUnicodeChar(unit) }
        })
        .collect::<Vec<_>>()
        .into();
    let mut catalogs = Vec::new();
    let mut names = BTreeSet::new();
    for path in files {
        match load(&path, upcase.clone()) {
            Ok(catalog) => {
                println!(
                    "catalog {:?} names={}",
                    path,
                    catalog.observed_names().count()
                );
                names.extend(catalog.observed_names().map(<[u16]>::to_vec));
                catalogs.push((path, catalog));
            }
            Err(error) => println!("unreadable catalog {path:?} {error}"),
        }
    }
    assert!(!catalogs.is_empty() && !names.is_empty() && names.len() <= 16384);
    let unknown: Vec<_> = "rax-cdb-control-6a52e834-62d6-41fb-918f.dll"
        .encode_utf16()
        .collect();
    assert_eq!(native_lookup(&unknown), (0, 0), "absent-name control");
    let mut mismatches = vec![0usize; catalogs.len()];
    let mut nonzero = 0;
    for name in &names {
        let (status, flags) = native_lookup(name);
        assert_eq!(
            status,
            0,
            "lookup failed for {:?}",
            String::from_utf16_lossy(name)
        );
        assert_ne!(flags, 0xa5a5_a5a5, "lookup did not write its output");
        nonzero += usize::from(flags != 0);
        for (index, (path, catalog)) in catalogs.iter().enumerate() {
            let expected = catalog.lookup(name);
            if expected != flags {
                mismatches[index] += 1;
                if mismatches[index] <= 32 {
                    println!(
                        "difference {:?} {:?} file={expected:#x} live={flags:#x}",
                        path,
                        String::from_utf16_lossy(name)
                    );
                }
            }
        }
    }
    for ((path, _), count) in catalogs.iter().zip(mismatches) {
        println!(
            "summary {:?} queried={} mismatches={count} live_nonzero={nonzero}",
            path,
            names.len()
        );
    }
    Ok(())
}
