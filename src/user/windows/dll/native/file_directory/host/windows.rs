//! Installed NT enumeration uses the same retained native directory object.
use super::super::{Checked, Completion, Ctx, Request};
use crate::user::windows::hle::ApiErr;
use crate::user::windows::objects::Object;
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;

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
#[repr(C)]
struct Overlapped {
    io: Io,
    offsets: [u32; 2],
    event: *mut c_void,
}
const _: () =
    assert!(std::mem::offset_of!(Overlapped, offsets) == 2 * std::mem::size_of::<usize>());
const SENTINEL: usize = usize::MAX / 255 * 0xa5;

#[link(name = "ntdll")]
unsafe extern "system" {
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
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetOverlappedResult(
        file: *mut c_void,
        io: *mut Overlapped,
        bytes: *mut u32,
        wait: i32,
    ) -> i32;
    fn GetLastError() -> u32;
}

type QueryEx = unsafe extern "system" fn(
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut Io,
    *mut c_void,
    u32,
    u32,
    u32,
    *const Unicode,
) -> i32;

fn extended() -> Option<QueryEx> {
    let name: Vec<_> = "ntdll.dll\0".encode_utf16().collect();
    // SAFETY: terminated fixed module/export names remain live; the borrowed
    // NTDLL is held for process lifetime by our existing static NT imports.
    let address = unsafe {
        let module = GetModuleHandleW(name.as_ptr());
        if module.is_null() {
            return None;
        }
        GetProcAddress(module, c"NtQueryDirectoryFileEx".as_ptr().cast())
    };
    if address.is_null() {
        None
    } else {
        // SAFETY: this named installed export has the declared system ABI and
        // fixed NT signature; its module cannot disappear during the request.
        Some(unsafe { std::mem::transmute::<*mut c_void, QueryEx>(address) })
    }
}

pub(super) fn query(c: &Ctx, request: Request) -> Checked<Completion> {
    let Some(Object::File(file)) = c.p.objects.get(request.handle) else {
        return Err(c
            .unsupported("directory object changed during synchronous query")
            .into());
    };
    let file = file
        .host
        .as_ref()
        .ok_or_else(|| c.unsupported("directory query requires a retained native handle"))?;
    query_file(file, request, extended())
}

fn query_file(
    file: &std::fs::File,
    request: Request,
    extended: Option<QueryEx>,
) -> Checked<Completion> {
    if extended.is_none() && request.flags & 0x18 != 0 {
        return Err(ApiErr::Unimplemented(
            "host NTDLL lacks extended directory-query flags".into(),
        )
        .into());
    }
    let name = request.pattern.as_ref().map(|units| Unicode {
        length: (units.len() * 2) as u16,
        maximum: (units.len() * 2) as u16,
        buffer: units.as_ptr(),
    });
    let mut words = vec![0u64; request.bytes.len().div_ceil(8)];
    for (word, part) in words.iter_mut().zip(request.bytes.chunks(8)) {
        let mut raw = [0; 8];
        raw[..part.len()].copy_from_slice(part);
        *word = u64::from_ne_bytes(raw);
    }
    let output = UnsafeCell::new(words);
    let io = Box::new(UnsafeCell::new(Overlapped {
        io: Io {
            status: 0x103,
            information: SENTINEL,
        },
        offsets: [0; 2],
        event: std::ptr::null_mut(),
    }));
    let null = std::ptr::null_mut();
    // SAFETY: all addresses refer to initialized private host allocations with
    // eight-byte output alignment and repr(C) native layouts. Length is bounded
    // by the owned vector; no guest pointer, APC or event is forwarded. UnsafeCell
    // admits OS mutation. The retained File, pattern and buffers outlive terminal
    // completion, including an unexpected pending return on a synchronous open.
    let code = unsafe {
        if let Some(query) = extended {
            query(
                file.as_raw_handle(),
                null,
                null,
                null,
                io.get().cast(),
                (*output.get()).as_mut_ptr().cast(),
                request.bytes.len() as u32,
                request.class,
                request.flags,
                name.as_ref().map_or(std::ptr::null(), |name| name),
            )
        } else {
            NtQueryDirectoryFile(
                file.as_raw_handle(),
                null,
                null,
                null,
                io.get().cast(),
                (*output.get()).as_mut_ptr().cast(),
                request.bytes.len() as u32,
                request.class,
                u8::from(request.flags & 2 != 0),
                name.as_ref().map_or(std::ptr::null(), |name| name),
                u8::from(request.flags & 1 != 0),
            )
        }
    } as u32;
    if code == 0x103 {
        loop {
            let mut count = 0;
            // SAFETY: IOSB is the first repr(C) OVERLAPPED field, and every owner
            // remains live. FALSE observes completion without requiring a host
            // SYNCHRONIZE grant; the call retains no pointer and cannot unwind.
            let ready =
                unsafe { GetOverlappedResult(file.as_raw_handle(), io.get(), &mut count, 0) };
            if ready != 0 {
                break;
            }
            // SAFETY: scalar thread-local error query has no retained argument.
            let error = unsafe { GetLastError() };
            if error != 996 {
                // SAFETY: terminal GetOverlappedResult synchronizes IOSB reads.
                if unsafe { (*io.get()).io.status as u32 } != 0x103 {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    // SAFETY: synchronous return or observed completion releases kernel access.
    let io = unsafe { &(*io.get()).io };
    let mut bytes = Vec::with_capacity(request.bytes.len());
    for word in output.into_inner() {
        bytes.extend_from_slice(&word.to_ne_bytes());
    }
    bytes.truncate(request.bytes.len());
    Ok(Completion {
        code: if code == 0x103 {
            io.status as u32
        } else {
            code
        },
        bytes,
        status: (io.status as u32 != 0x103).then_some(io.status as u32),
        information: (io.information != SENTINEL).then_some(io.information as u64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;

    #[test]
    fn nt_directory_native_legacy_fallback_executes_and_extended_flags_fail_explicitly() {
        let root =
            std::env::temp_dir().join(format!("rax-nt-directory-legacy-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("alpha.txt"), b"owned").unwrap();
        let open = || {
            std::fs::OpenOptions::new()
                .access_mode(0x100001)
                .share_mode(7)
                .custom_flags(0x0200_0000)
                .open(&root)
                .unwrap()
        };
        let entry = extended().expect("native extended control available on qualification host");
        for class in [1, 2, 3, 12, 37, 38, 60, 63] {
            let request = || Request {
                handle: 0,
                class,
                flags: 2,
                pattern: Some("alpha.txt".encode_utf16().collect()),
                bytes: vec![0xa5; 616],
            };
            let legacy = query_file(&open(), request(), None)
                .unwrap_or_else(|_| panic!("legacy class{class}"));
            let modern = query_file(&open(), request(), Some(entry))
                .unwrap_or_else(|_| panic!("extended class{class}"));
            assert_eq!(legacy.code, 0);
            assert_eq!(modern.code, 0);
            assert_eq!(legacy.status, modern.status);
            assert_eq!(legacy.information, modern.information);
            assert_eq!(legacy.bytes, modern.bytes, "legacy versus extended/{class}");
        }
        let result = query_file(
            &open(),
            Request {
                handle: 0,
                class: 3,
                flags: 16,
                pattern: None,
                bytes: vec![0xa5; 616],
            },
            None,
        );
        assert!(matches!(
            result,
            Err(super::super::super::super::named_object::Failure::Api(
                ApiErr::Unimplemented(_)
            ))
        ));
        std::fs::remove_dir_all(root).unwrap();
    }
}
