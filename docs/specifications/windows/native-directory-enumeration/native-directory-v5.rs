//! Ordinary, owned-handle enumeration controls. No invalid pointer or callback probes.
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

#[repr(C)]
struct Io {
    status: usize,
    information: usize,
}

#[repr(C)]
struct Unicode {
    length: u16,
    maximum: u16,
    buffer: *const u16,
}

#[repr(C, align(8))]
struct Buffer([u8; 8192]);

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryDirectoryFileEx(
        file: *mut c_void,
        event: *mut c_void,
        apc: *mut c_void,
        context: *mut c_void,
        io: *mut Io,
        output: *mut c_void,
        length: u32,
        class: u32,
        flags: u32,
        name: *const Unicode,
    ) -> i32;
    fn NtQueryDirectoryFile(
        file: *mut c_void,
        event: *mut c_void,
        apc: *mut c_void,
        context: *mut c_void,
        io: *mut Io,
        output: *mut c_void,
        length: u32,
        class: u32,
        single: u8,
        name: *const Unicode,
        restart: u8,
    ) -> i32;
    fn NtWaitForSingleObject(file: *mut c_void, alertable: u8, timeout: *const i64) -> i32;
    fn NtSetEaFile(file: *mut c_void, io: *mut Io, input: *const c_void, bytes: u32) -> i32;

}

#[repr(C)]
struct Basic {
    times: [i64; 4],
    attributes: u32,
    padding: u32,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetFileInformationByHandle(
        file: *mut c_void,
        class: u32,
        input: *const Basic,
        length: u32,
    ) -> i32;
}
fn fixed_times(path: &Path) {
    let file = open(path, 0x100100);
    //2030-01-01T00:00:00Z, in exact100 ns intervals after1601-01-01.
    let basic = Basic {
        times: [135379296000000000; 4],
        attributes: 0,
        padding: 0,
    };
    assert_eq!(std::mem::size_of::<Basic>(), 40);
    // SAFETY: owned synchronous file/directory handle, repr(C) initialized
    // fixed-size input, no callbacks, and this synchronous Win32 API retains
    // no pointer on return. Only the private fixture paths are passed here.
    let result = unsafe { SetFileInformationByHandle(file.as_raw_handle(), 0, &basic, 40) };
    assert_ne!(
        result,
        0,
        "private fixed metadata: {}",
        std::io::Error::last_os_error()
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

fn open(path: &Path, access: u32) -> File {
    OpenOptions::new()
        .access_mode(access)
        .share_mode(7)
        .custom_flags(0x0200_0000)
        .open(path)
        .expect("owned native fixture open")
}

fn query(
    id: &str,
    file: &File,
    class: u32,
    length: u32,
    flags: u32,
    pattern: Option<&str>,
    legacy: bool,
) -> (u32, usize, Vec<u8>) {
    assert!(length <= 4096);
    let pattern_units = pattern.map(|value| value.encode_utf16().collect::<Vec<_>>());
    let name = pattern_units.as_ref().map(|units| Unicode {
        length: (units.len() * 2) as u16,
        maximum: (units.len() * 2) as u16,
        buffer: units.as_ptr(),
    });
    let io = Box::new(UnsafeCell::new(Io {
        status: usize::MAX / 255 * 0xa5,
        information: usize::MAX / 255 * 0xa5,
    }));
    let output = Box::new(UnsafeCell::new(Buffer([0xa5; 8192])));
    let null = std::ptr::null_mut();
    // SAFETY: the private, initialized, aligned allocations and optional counted
    // UTF-16 string remain live through terminal completion. Only an owned File
    // is passed, with no callback or guest address. Length is at most4096 B of
    // an8192 B allocation. UnsafeCell admits OS writes without shared references.
    let returned = unsafe {
        if legacy {
            NtQueryDirectoryFile(
                file.as_raw_handle(),
                null,
                null,
                null,
                io.get(),
                output.get().cast(),
                length,
                class,
                u8::from(flags & 2 != 0),
                name.as_ref().map_or(std::ptr::null(), |value| value),
                u8::from(flags & 1 != 0),
            )
        } else {
            NtQueryDirectoryFileEx(
                file.as_raw_handle(),
                null,
                null,
                null,
                io.get(),
                output.get().cast(),
                length,
                class,
                flags,
                name.as_ref().map_or(std::ptr::null(), |value| value),
            )
        }
    } as u32;
    if returned == 0x103 {
        loop {
            // SAFETY: this synchronous owned open has SYNCHRONIZE access and
            // remains live with both request buffers. NULL is an infinite wait;
            // alertable=false prevents user APC delivery or Rust callbacks.
            let waited =
                unsafe { NtWaitForSingleObject(file.as_raw_handle(), 0, std::ptr::null()) };
            if waited != 0 {
                // A wait failure does not release kernel ownership of buffers.
                std::process::abort();
            }
            // SAFETY: successful wait synchronizes observation of the completed
            // IOSB. Preserve both owners if the kernel still reports pending.
            if unsafe { (*io.get()).status as u32 } != 0x103 {
                break;
            }
        }
    }
    // SAFETY: a synchronous return or observed terminal completion releases OS
    // access to these allocations; all scalar fields and bytes are initialized.
    let (status, information, bytes) = unsafe {
        (
            (*io.get()).status,
            (*io.get()).information,
            (*output.get()).0,
        )
    };
    assert!(bytes[length as usize..].iter().all(|value| *value == 0xa5));
    let pattern_hex = pattern_units.as_ref().map_or(String::new(), |units| {
        hex(&units
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>())
    });
    println!(
        "{{\"id\":\"{id}\",\"legacy\":{legacy},\"class\":{class},\"length\":{length},\"flags\":{flags},\"pattern_present\":{},\"pattern_hex\":\"{pattern_hex}\",\"returned\":{returned},\"io_status\":{status},\"information\":{information},\"data\":\"{}\",\"trailing_untouched\":true}}",
        pattern.is_some(),
        hex(&bytes[..length as usize])
    );
    (returned, information, bytes[..length as usize].to_vec())
}

fn main() {
    let root = std::env::args_os().nth(1).expect("private fixture parent");
    let root = Path::new(&root).join("ordinary-enumeration-fixture-v1");
    std::fs::create_dir(&root).expect("fresh task-owned fixture directory");
    for (name, content) in [
        ("alpha.txt", b"alpha".as_slice()),
        ("beta.dat", b"beta-data".as_slice()),
        ("empty", b"".as_slice()),
        (
            "long supplementary \u{1f680} filename.txt",
            b"supplementary".as_slice(),
        ),
    ] {
        std::fs::write(root.join(name), content).unwrap();
    }
    std::fs::create_dir(root.join("subdir")).unwrap();
    for child in std::fs::read_dir(&root).unwrap() {
        fixed_times(&child.unwrap().path());
    }
    fixed_times(&root);
    fixed_times(root.parent().unwrap());

    println!(
        "{{\"schema\":\"rax-native-directory-ordinary-v5\",\"pointer_bytes\":{},\"invalid_pointer_probes\":false}}",
        std::mem::size_of::<usize>()
    );
    let classes = [1, 2, 3, 12, 37, 38, 60, 63];
    for class in classes {
        let file = open(&root, 0x100001);
        query(
            &format!("class-{class}"),
            &file,
            class,
            4096,
            0,
            None,
            false,
        );
    }
    for legacy in [false, true] {
        for length in [
            0, 1, 4, 63, 64, 67, 68, 93, 94, 95, 96, 97, 98, 99, 100, 103, 104, 128, 616,
        ] {
            let file = open(&root, 0x100001);
            query(
                &format!("length-{legacy}-{length}"),
                &file,
                3,
                length,
                2,
                None,
                legacy,
            );
            query(
                &format!("after-length-{legacy}-{length}"),
                &file,
                3,
                616,
                2,
                None,
                legacy,
            );
        }
        for (index, pattern) in [
            None,
            Some("*"),
            Some("*.txt"),
            Some("alpha.txt"),
            Some("ALPHA.TXT"),
            Some("absent.xyz"),
            Some(""),
            Some("a?pha.txt"),
            Some("<.txt"),
            Some("*.*"),
            Some("LONGSU~1.TXT"),
            Some("longsu~1.txt"),
        ]
        .into_iter()
        .enumerate()
        {
            let file = open(&root, 0x100001);
            for step in 0..10 {
                let (returned, _, _) = query(
                    &format!("pattern-{legacy}-{index}-{step}"),
                    &file,
                    3,
                    616,
                    2,
                    if step == 0 {
                        pattern
                    } else {
                        Some("ignored-after-first.dat")
                    },
                    legacy,
                );
                if returned != 0 {
                    break;
                }
            }
            query(
                &format!("restart-pattern-{legacy}-{index}"),
                &file,
                3,
                616,
                3,
                Some("different-filter.dat"),
                legacy,
            );
        }
        let file = open(&root, 0x100001);
        let duplicate = file.try_clone().unwrap();
        let independent = open(&root, 0x100001);
        query(
            &format!("cursor-{legacy}-first"),
            &file,
            3,
            616,
            2,
            None,
            legacy,
        );
        query(
            &format!("cursor-{legacy}-duplicate"),
            &duplicate,
            3,
            616,
            2,
            None,
            legacy,
        );
        query(
            &format!("cursor-{legacy}-independent"),
            &independent,
            3,
            616,
            2,
            None,
            legacy,
        );
        query(
            &format!("cursor-{legacy}-restart"),
            &duplicate,
            3,
            616,
            3,
            None,
            legacy,
        );
    }
    for flags in [0, 1, 2, 3, 8, 10, 16, 18] {
        let file = open(&root, 0x100001);
        for step in 0..3 {
            query(
                &format!("flags-{flags}-{step}"),
                &file,
                3,
                616,
                flags,
                Some("*"),
                false,
            );
        }
    }
    for legacy in [false, true] {
        for length in [96, 97, 98, 100, 110, 111, 112, 128] {
            let file = open(&root, 0x100001);
            query(
                &format!("overflow-{legacy}-{length}"),
                &file,
                3,
                length,
                2,
                Some("alpha.txt"),
                legacy,
            );
            query(
                &format!("overflow-next-{legacy}-{length}"),
                &file,
                3,
                616,
                2,
                None,
                legacy,
            );
        }
        for (index, restart_name) in [None, Some("*.txt"), Some("beta.dat"), Some("absent.xyz")]
            .into_iter()
            .enumerate()
        {
            let file = open(&root, 0x100001);
            query(
                &format!("restart-first-{legacy}-{index}"),
                &file,
                3,
                616,
                0,
                Some("*.txt"),
                legacy,
            );
            query(
                &format!("restart-exhaust-{legacy}-{index}"),
                &file,
                3,
                616,
                0,
                None,
                legacy,
            );
            query(
                &format!("restart-apply-{legacy}-{index}"),
                &file,
                3,
                616,
                3,
                restart_name,
                legacy,
            );
            query(
                &format!("restart-after-{legacy}-{index}"),
                &file,
                3,
                616,
                2,
                None,
                legacy,
            );
        }
    }

    for flags in [16, 18] {
        let file = open(&root, 0x100001);
        query(
            &format!("nocursor-{flags}-first"),
            &file,
            3,
            616,
            flags,
            Some("*.txt"),
            false,
        );
        query(
            &format!("nocursor-{flags}-ordinary"),
            &file,
            3,
            616,
            2,
            None,
            false,
        );
        query(
            &format!("nocursor-{flags}-different"),
            &file,
            3,
            616,
            flags,
            Some("beta.dat"),
            false,
        );
        query(
            &format!("nocursor-{flags}-ordinary-after"),
            &file,
            3,
            616,
            2,
            None,
            false,
        );
    }
    for (class, minimum) in [
        (1, 72u32),
        (2, 72),
        (3, 96),
        (12, 16),
        (37, 112),
        (38, 88),
        (60, 96),
        (63, 120),
    ] {
        for length in [minimum - 1, minimum, minimum + 1] {
            let file = open(&root, 0x100001);
            query(
                &format!("minimum-{class}-{length}"),
                &file,
                class,
                length,
                2,
                Some("alpha.txt"),
                false,
            );
        }
    }
    for (index, (name, value)) in [
        ("X", b"x".as_slice()),
        ("ONE", b"xyz".as_slice()),
        ("FOUR", b"abcde".as_slice()),
    ]
    .into_iter()
    .enumerate()
    {
        let file = open(&root.join("alpha.txt"), 0x100010);
        let mut ea = vec![0u8; 8];
        ea[5] = name.len() as u8;
        ea[6..8].copy_from_slice(&(value.len() as u16).to_le_bytes());
        ea.extend_from_slice(name.as_bytes());
        ea.push(0);
        ea.extend_from_slice(value);
        let mut io = Io {
            status: 0,
            information: 0,
        };
        // SAFETY: owned synchronous File and initialized bounded valid EA record;
        // this call receives no callback or invalid pointer and retains no input.
        let code = unsafe {
            NtSetEaFile(
                file.as_raw_handle(),
                &mut io,
                ea.as_ptr().cast(),
                ea.len() as u32,
            )
        };
        println!(
            "{{\"ea_set_case\":{index},\"ea_name_bytes\":{},\"ea_value_bytes\":{},\"returned\":{code}}}",
            name.len(),
            value.len()
        );
        assert_eq!(code, 0);
        drop(file);
        let directory = open(&root, 0x100001);
        query(
            &format!("ea-directory-{index}"),
            &directory,
            3,
            616,
            2,
            Some("alpha.txt"),
            false,
        );
    }
    let denied = open(&root, 0x100080);
    query("metadata-only", &denied, 3, 616, 2, None, false);
    let regular = open(&root.join("alpha.txt"), 0x100001);
    query("regular-file", &regular, 3, 616, 2, None, false);
    // Retained identity must not follow a replacement of the original path.
    drop(denied);
    drop(regular);
    let file = open(&root, 0x110001);
    query("rename-before", &file, 3, 616, 2, Some("alpha.txt"), false);
    let renamed = root.with_file_name("ordinary-enumeration-retained-v1");
    let renamed_ok = match std::fs::rename(&root, &renamed) {
        Ok(()) => true,
        Err(error) => {
            println!(
                "{{\"rename_control_error\":{},\"retained_rename_qualified\":false}}",
                error.raw_os_error().unwrap_or(-1)
            );
            false
        }
    };
    if !renamed_ok {
        println!(
            "{{\"schema\":\"rax-native-directory-ordinary-v5-complete\",\"original_processes_signalled\":false}}"
        );
        return;
    }
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("replacement.txt"), b"replacement").unwrap();
    query("rename-retained-restart", &file, 3, 616, 3, None, false);
    println!(
        "{{\"schema\":\"rax-native-directory-ordinary-v5-complete\",\"original_processes_signalled\":false}}"
    );
}
