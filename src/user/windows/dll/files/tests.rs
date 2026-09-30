use super::*;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, Flow, Item, Value};
use crate::user::windows::memory::{mem, prot};
use crate::user::windows::process::{Thread, WindowsConfig, WindowsProcess};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let path = std::env::temp_dir().join(format!(
                "rax-windows-file-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("unique temporary directory: {e}"),
            }
        }
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Harness {
    // Drop process/file objects before removing the owned temporary directory.
    process: WindowsProcess,
    thread: Thread,
    memory: u64,
    directory: Temp,
}

impl Harness {
    fn new(arch: WinArch) -> Self {
        let directory = Temp::new();
        let image: &[u8] = match arch {
            WinArch::X86 => {
                include_bytes!("../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
            WinArch::X64 => {
                include_bytes!("../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::Arm64 => {
                include_bytes!("../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
            }
        };
        let mut cfg = WindowsConfig::new("files.exe", vec![]);
        cfg.seed = Some(1);
        cfg.arena_bytes = 64 << 20;
        cfg.cwd = Some("C:\\".into());
        cfg.drives = crate::user::windows::fs::DriveMap::empty();
        cfg.drives.set('C', &directory.0);
        let mut process = WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let thread = p.threads.remove(&tid).unwrap();
        let memory =
            p.vm.allocate(None, 0x20000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        Self {
            process,
            thread,
            memory,
            directory,
        }
    }
    fn call(&mut self, name: &str, args: &[u64]) -> ApiResult {
        let api = EXPORTS
            .iter()
            .find_map(|e| match &e.item {
                Item::Func(a) if a.name == name => Some(a),
                _ => None,
            })
            .unwrap();
        assert_eq!(args.len(), api.args.len());
        let p = self.process.state_mut();
        let sp = self.thread.cpu.sp();
        let mut stack = sp + 4;
        for (i, &value) in args.iter().enumerate() {
            match p.arch {
                WinArch::X86 => {
                    if api.args[i] == crate::user::windows::hle::Arg::I64 {
                        p.space.w64(stack, value).unwrap();
                        stack += 8;
                    } else {
                        p.space.w32(stack, value as u32).unwrap();
                        stack += 4;
                    }
                }
                WinArch::X64 if i < 4 => self.thread.cpu.set_gpr([1, 2, 8, 9][i], value),
                WinArch::X64 => p.space.w64(sp + 0x28 + 8 * (i - 4) as u64, value).unwrap(),
                WinArch::Arm64 => self.thread.cpu.set_gpr(i, value),
            }
        }
        let mut c = Ctx {
            p,
            t: &mut self.thread,
            api,
            entry_pc: 0x1234,
            entry_sp: sp,
            ret_addr: 0,
            cursor: sp,
        };
        (api.imp)(&mut c)
    }
    fn value(&mut self, name: &str, args: &[u64]) -> u64 {
        match self.call(name, args).unwrap() {
            Flow::Ret(Value::Int(v)) => self.process.state().arch.ptr(v),
            _ => panic!("integer return from {name}"),
        }
    }
    fn error(&self) -> u32 {
        self.process
            .state()
            .space
            .u32(self.thread.teb + offsets(self.process.state().arch).teb_last_error)
            .unwrap()
    }
    fn filename(&self, name: &str, wide: bool) {
        if wide {
            self.process
                .state()
                .space
                .put_wstr(self.memory, &name.encode_utf16().collect::<Vec<_>>())
                .unwrap();
        } else {
            self.process
                .state()
                .space
                .put_cstr(self.memory, name.as_bytes())
                .unwrap();
        }
    }
    fn open(&mut self, name: &str, access: u32, share: u32, disposition: u32, flags: u32) -> u64 {
        self.filename(name, true);
        self.value(
            "CreateFileW",
            &[
                self.memory,
                access.into(),
                share.into(),
                0,
                disposition.into(),
                flags.into(),
                0,
            ],
        )
    }
    fn invalid(&self) -> u64 {
        self.process.state().arch.ptr(u64::MAX)
    }
    fn close(&mut self, handle: u64) {
        assert_eq!(self.value("CloseHandle", &[handle]), 1);
    }
    fn write(&mut self, handle: u64, bytes: &[u8]) -> u64 {
        self.process
            .state()
            .space
            .wr(self.memory + 0x10000, bytes)
            .unwrap();
        self.value(
            "WriteFile",
            &[
                handle,
                self.memory + 0x10000,
                bytes.len() as u64,
                self.memory + 0x11000,
                0,
            ],
        )
    }
    fn read(&mut self, handle: u64, len: u64) -> Vec<u8> {
        assert_eq!(
            self.value(
                "ReadFile",
                &[handle, self.memory + 0x10000, len, self.memory + 0x11000, 0]
            ),
            1
        );
        let n = self
            .process
            .state()
            .space
            .u32(self.memory + 0x11000)
            .unwrap() as usize;
        self.process
            .state()
            .space
            .bytes(self.memory + 0x10000, n)
            .unwrap()
    }
    fn seek(&mut self, handle: u64, distance: i64, method: u32) -> u64 {
        assert_eq!(
            self.value(
                "SetFilePointerEx",
                &[
                    handle,
                    distance as u64,
                    self.memory + 0x12000,
                    method.into()
                ]
            ),
            1
        );
        self.process
            .state()
            .space
            .u64(self.memory + 0x12000)
            .unwrap()
    }
    fn size(&mut self, handle: u64) -> u64 {
        assert_eq!(
            self.value("GetFileSizeEx", &[handle, self.memory + 0x12000]),
            1
        );
        self.process
            .state()
            .space
            .u64(self.memory + 0x12000)
            .unwrap()
    }
    fn cursor(&mut self, handle: u64) -> u64 {
        self.seek(handle, 0, 1)
    }
}

#[test]
fn dispositions_roundtrip_eof_seek_extension_truncation_and_flush_all_abis() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let file = h.open("round.bin", GENERIC_READ | GENERIC_WRITE, 7, 1, 0x80);
        assert_ne!(file, h.invalid());
        assert_eq!(h.value("GetFileType", &[file]), 1);
        assert_eq!(h.write(file, b"abcdef"), 1);
        assert_eq!(h.size(file), 6);
        assert_eq!(h.seek(file, 2, 0), 2);
        assert_eq!(h.read(file, 2), b"cd");
        assert_eq!(h.seek(file, 0, 2), 6);
        assert_eq!(h.read(file, 1), b"");
        assert_eq!(h.seek(file, 3, 2), 9);
        assert_eq!(h.size(file), 6, "seeking does not extend a file");
        assert_eq!(h.write(file, b"Z"), 1);
        assert_eq!(
            std::fs::read(h.directory.0.join("round.bin")).unwrap(),
            b"abcdef\0\0\0Z"
        );
        assert_eq!(h.seek(file, -6, 2), 4);
        assert_eq!(h.value("SetEndOfFile", &[file]), 1);
        assert_eq!(h.size(file), 4);
        assert_eq!(h.value("FlushFileBuffers", &[file]), 1);
        h.close(file);
        assert_eq!(h.open("round.bin", GENERIC_WRITE, 7, 1, 0), h.invalid());
        assert_eq!(h.error(), ERROR_FILE_EXISTS);
        let reopened = h.open("round.bin", GENERIC_READ, 7, 4, 0);
        assert_eq!(h.error(), ERROR_ALREADY_EXISTS);
        assert_eq!(h.read(reopened, 8), b"abcd");
        h.close(reopened);
        assert_eq!(h.open("round.bin", GENERIC_READ, 7, 5, 0), h.invalid());
        assert_eq!(h.error(), ERROR_ACCESS_DENIED);
        assert_eq!(
            std::fs::read(h.directory.0.join("round.bin")).unwrap(),
            b"abcd"
        );
        let truncated = h.open("round.bin", GENERIC_WRITE, 7, 5, 0);
        assert_eq!(h.size(truncated), 0);
        h.close(truncated);
        let always = h.open("round.bin", GENERIC_READ | GENERIC_WRITE, 7, 2, 0);
        assert_eq!(h.error(), ERROR_ALREADY_EXISTS);
        h.close(always);
        h.filename("round.bin", true);
        assert_eq!(h.value("DeleteFileW", &[h.memory]), 1);
        assert_eq!(h.open("round.bin", GENERIC_READ, 7, 3, 0), h.invalid());
        assert_eq!(h.error(), ERROR_FILE_NOT_FOUND);
        assert_eq!(h.open("round.bin", GENERIC_WRITE, 7, 5, 0), h.invalid());
        let new = h.open("round.bin", GENERIC_WRITE, 7, 4, 0);
        assert_eq!(h.error(), ERROR_SUCCESS);
        h.close(new);
        let new = h.open("created-always.bin", GENERIC_READ, 7, 2, 0);
        assert_ne!(new, h.invalid());
        assert_eq!(h.error(), ERROR_SUCCESS);
        h.close(new);
    }
}

#[test]
fn access_grants_metadata_and_both_sharing_directions_all_abis() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        std::fs::write(h.directory.0.join("share.bin"), b"abc").unwrap();
        let exclusive = h.open("SHARE.BIN", GENERIC_READ, 0, 3, 0);
        assert_ne!(exclusive, h.invalid(), "ASCII case-insensitive lookup");
        assert_eq!(h.open("share.bin", GENERIC_READ, 7, 3, 0), h.invalid());
        assert_eq!(h.error(), ERROR_SHARING_VIOLATION);
        let metadata = h.open("share.bin", 0, SHARE_READ, 3, 0);
        assert_ne!(metadata, h.invalid());
        assert_eq!(h.size(metadata), 3);
        assert_eq!(h.write(metadata, b"z"), 0);
        assert_eq!(h.error(), ERROR_ACCESS_DENIED);
        h.close(metadata);
        h.close(exclusive);
        let reader = h.open("share.bin", GENERIC_READ, SHARE_READ, 3, 0);
        assert_eq!(h.open("share.bin", GENERIC_WRITE, 7, 3, 0), h.invalid());
        assert_eq!(h.error(), ERROR_SHARING_VIOLATION);
        assert_eq!(h.open("share.bin", GENERIC_WRITE, 7, 2, 0), h.invalid());
        assert_eq!(
            std::fs::read(h.directory.0.join("share.bin")).unwrap(),
            b"abc",
            "share check before truncation"
        );
        h.close(reader);
        let writer = h.open("share.bin", GENERIC_WRITE, SHARE_READ | SHARE_WRITE, 3, 0);
        assert_eq!(
            h.open("share.bin", GENERIC_READ, SHARE_READ, 3, 0),
            h.invalid()
        );
        assert_eq!(h.error(), ERROR_SHARING_VIOLATION);
        h.close(writer);
        let rw = h.open("share.bin", GENERIC_READ | GENERIC_WRITE, 7, 3, 0);
        let id = h.process.state().objects.id(rw).unwrap();
        let reduced = u64::from(
            h.process
                .state_mut()
                .objects
                .open_access(id, false, READ_DATA)
                .unwrap(),
        );
        assert_eq!(h.write(reduced, b"z"), 0);
        assert_eq!(h.error(), ERROR_ACCESS_DENIED);
        assert_eq!(h.read(reduced, 1), b"a");
        h.close(rw);
        assert_eq!(
            h.write(reduced, b"z"),
            0,
            "closing original must not widen duplicate grant"
        );
        assert!(h.process.state_mut().objects.set_flags(reduced, 2, 2));
        assert_eq!(h.value("CloseHandle", &[reduced]), 0);
        assert_eq!(h.error(), ERROR_INVALID_HANDLE);
        assert!(h.process.state_mut().objects.set_flags(reduced, 2, 0));
        h.close(reduced);
    }
}

#[test]
fn duplicate_cursors_independent_opens_and_append_only_grants_all_abis() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        std::fs::write(h.directory.0.join("cursor.bin"), b"abc").unwrap();
        let a = h.open("cursor.bin", GENERIC_READ | GENERIC_WRITE, 7, 3, 0);
        let b = u64::from(h.process.state_mut().objects.duplicate(a, false).unwrap());
        assert_eq!(h.read(a, 1), b"a");
        assert_eq!(h.read(b, 1), b"b");
        assert_eq!(h.seek(b, 0, 0), 0);
        assert_eq!(h.read(a, 1), b"a");
        h.close(a);
        let separate = h.open("cursor.bin", GENERIC_READ, 7, 3, 0);
        assert_eq!(h.read(separate, 1), b"a");
        assert_eq!(h.read(b, 1), b"b");
        h.close(separate);
        let id = h.process.state().objects.id(b).unwrap();
        let append_duplicate = u64::from(
            h.process
                .state_mut()
                .objects
                .open_access(id, false, APPEND_DATA)
                .unwrap(),
        );
        assert_eq!(h.seek(b, 0, 0), 0);
        assert_eq!(h.write(append_duplicate, b"X"), 1);
        assert_eq!(h.value("SetEndOfFile", &[append_duplicate]), 0);
        assert_eq!(h.error(), ERROR_ACCESS_DENIED);
        assert_eq!(h.value("FlushFileBuffers", &[append_duplicate]), 0);
        assert_eq!(h.error(), ERROR_ACCESS_DENIED);
        h.close(append_duplicate);
        h.close(b);
        let append = h.open("cursor.bin", APPEND_DATA, 7, 3, 0);
        assert_eq!(h.seek(append, 0, 0), 0);
        assert_eq!(h.write(append, b"Y"), 1);
        h.close(append);
        assert_eq!(
            std::fs::read(h.directory.0.join("cursor.bin")).unwrap(),
            b"abcXY"
        );
    }
}

#[test]
fn console_zero_length_direction_and_reduced_grants_all_abis() {
    use crate::user::windows::objects::{Object, StdStream};
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let input = u64::from(
            h.process
                .state_mut()
                .objects
                .insert(Object::Console(StdStream::In)),
        );
        let output = u64::from(
            h.process
                .state_mut()
                .objects
                .insert(Object::Console(StdStream::Out)),
        );
        assert_eq!(h.value("GetFileType", &[input]), 2);
        assert_eq!(h.value("GetFileType", &[output]), 2);
        assert_eq!(h.read(input, 0), b"");
        assert_eq!(h.write(output, b""), 1);
        assert_eq!(h.write(input, b""), 0);
        assert_eq!(h.error(), ERROR_ACCESS_DENIED);
        assert_eq!(
            h.value("ReadFile", &[output, h.memory, 0, h.memory + 0x11000, 0]),
            0
        );
        assert_eq!(h.error(), ERROR_ACCESS_DENIED);
        assert_eq!(h.value("FlushFileBuffers", &[output]), 0);
        assert_eq!(h.error(), ERROR_INVALID_HANDLE);
        let id = h.process.state().objects.id(output).unwrap();
        let denied = u64::from(
            h.process
                .state_mut()
                .objects
                .open_access(id, false, 0)
                .unwrap(),
        );
        assert_eq!(h.write(denied, b""), 0);
        assert_eq!(h.error(), ERROR_ACCESS_DENIED);
        h.close(denied);
        h.close(input);
        h.close(output);
    }
}

#[cfg(unix)]
#[test]
fn delete_requests_wait_for_every_independent_and_duplicate_handle_all_abis() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let path = h.directory.0.join("delete.bin");
        let a = h.open(
            "delete.bin",
            GENERIC_READ | GENERIC_WRITE,
            7,
            1,
            DELETE_ON_CLOSE,
        );
        let duplicate = u64::from(h.process.state_mut().objects.duplicate(a, false).unwrap());
        let b = h.open("delete.bin", GENERIC_READ, 7, 3, 0);
        h.close(a);
        h.close(b);
        assert!(path.exists());
        assert_eq!(
            h.open("delete.bin", GENERIC_READ, SHARE_READ, 3, 0),
            h.invalid()
        );
        assert_eq!(h.error(), ERROR_SHARING_VIOLATION);
        let allowed = h.open("delete.bin", GENERIC_READ, 7, 3, 0);
        h.close(allowed);
        assert!(path.exists());
        h.close(duplicate);
        assert!(!path.exists());
        std::fs::write(&path, b"x").unwrap();
        let open = h.open("delete.bin", GENERIC_READ, SHARE_READ, 3, 0);
        h.filename("delete.bin", true);
        assert_eq!(h.value("DeleteFileW", &[h.memory]), 0);
        assert_eq!(h.error(), ERROR_SHARING_VIOLATION);
        h.close(open);
        let open = h.open("delete.bin", GENERIC_READ, 7, 3, 0);
        let duplicate = u64::from(
            h.process
                .state_mut()
                .objects
                .duplicate(open, false)
                .unwrap(),
        );
        h.filename("delete.bin", false);
        assert_eq!(h.value("DeleteFileA", &[h.memory]), 1);
        assert!(path.exists());
        assert_eq!(h.open("delete.bin", GENERIC_READ, 7, 3, 0), h.invalid());
        assert_eq!(h.error(), ERROR_ACCESS_DENIED);
        h.close(open);
        assert!(path.exists());
        h.close(duplicate);
        assert!(!path.exists());
    }
}

#[test]
fn invalid_guest_outputs_inputs_and_last_error_precede_host_effects_all_abis() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let path = h.directory.0.join("preflight.bin");
        std::fs::write(&path, b"abc").unwrap();
        let file = h.open("preflight.bin", GENERIC_READ | GENERIC_WRITE, 7, 3, 0);
        let buffer = h.memory + 0x10000;
        let count = h.memory + 0x11000;
        let output = h.memory + 0x12000;
        h.process
            .state_mut()
            .vm
            .protect(buffer, 4096, prot::READONLY)
            .unwrap();
        assert!(matches!(
            h.call("ReadFile", &[file, buffer, 2, count, 0]),
            Err(ApiErr::Fault(MemFault { write: true, .. }))
        ));
        assert_eq!(h.cursor(file), 0);
        h.process
            .state_mut()
            .vm
            .protect(buffer, 4096, prot::READWRITE)
            .unwrap();
        h.process.state().space.wr(buffer, b"XY").unwrap();
        h.process
            .state_mut()
            .vm
            .protect(count, 4096, prot::READONLY)
            .unwrap();
        assert!(matches!(
            h.call("WriteFile", &[file, buffer, 2, count, 0]),
            Err(ApiErr::Fault(MemFault { write: true, .. }))
        ));
        assert_eq!(h.cursor(file), 0);
        assert_eq!(std::fs::read(&path).unwrap(), b"abc");
        h.process
            .state_mut()
            .vm
            .protect(count, 4096, prot::READWRITE)
            .unwrap();
        h.process
            .state_mut()
            .vm
            .protect(buffer, 4096, prot::NOACCESS)
            .unwrap();
        assert!(matches!(
            h.call("WriteFile", &[file, buffer, 2, count, 0]),
            Err(ApiErr::Fault(MemFault { write: false, .. }))
        ));
        assert_eq!(h.process.state().space.u32(count).unwrap(), 0);
        assert_eq!(std::fs::read(&path).unwrap(), b"abc");
        h.process
            .state_mut()
            .vm
            .protect(output, 4096, prot::NOACCESS)
            .unwrap();
        assert!(matches!(
            h.call("SetFilePointerEx", &[file, 2, output, 0]),
            Err(ApiErr::Fault(_))
        ));
        h.process
            .state_mut()
            .vm
            .protect(output, 4096, prot::READWRITE)
            .unwrap();
        assert_eq!(h.cursor(file), 0);
        h.filename("preflight.bin", true);
        h.process
            .state_mut()
            .vm
            .protect(h.thread.teb, 4096, prot::NOACCESS)
            .unwrap();
        assert!(matches!(
            h.call(
                "CreateFileW",
                &[h.memory, GENERIC_WRITE.into(), 7, 0, 2, 0, 0]
            ),
            Err(ApiErr::Fault(_))
        ));
        assert!(matches!(
            h.call("DeleteFileW", &[h.memory]),
            Err(ApiErr::Fault(_))
        ));
        assert!(matches!(
            h.call("CloseHandle", &[file]),
            Err(ApiErr::Fault(_))
        ));
        assert!(h.process.state().objects.get(file).is_some());
        assert_eq!(std::fs::read(&path).unwrap(), b"abc");
        h.process
            .state_mut()
            .vm
            .protect(h.thread.teb, 4096, prot::READWRITE)
            .unwrap();
        h.close(file);
    }
}

#[test]
fn nul_access_zero_length_errors_and_unsupported_requests_all_abis() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        h.filename("NUL", false);
        let null = h.value(
            "CreateFileA",
            &[h.memory, GENERIC_READ.into(), 7, 0, 3, 0x80, 0],
        );
        assert_ne!(null, h.invalid());
        assert_eq!(h.value("GetFileType", &[null]), 2);
        assert_eq!(h.read(null, 1), b"");
        assert_eq!(h.write(null, b"x"), 0);
        assert_eq!(h.error(), ERROR_ACCESS_DENIED);
        h.close(null);
        let null = h.open("NUL", GENERIC_READ | GENERIC_WRITE, 7, 3, 0);
        assert_eq!(
            h.value("WriteFile", &[null, u64::MAX, 0, h.memory + 0x11000, 0]),
            1
        );
        assert_eq!(
            h.value("ReadFile", &[null, u64::MAX, 0, h.memory + 0x11000, 0]),
            1
        );
        assert_eq!(h.value("ReadFile", &[null, h.memory, 1, 0, 0]), 0);
        assert_eq!(h.error(), ERROR_INVALID_PARAMETER);
        assert!(matches!(
            h.call("ReadFile", &[null, h.memory, 1, h.memory + 0x11000, 1]),
            Err(ApiErr::Unimplemented(_))
        ));
        assert!(matches!(
            h.call(
                "WriteFile",
                &[null, h.memory, MAX_IO as u64 + 1, h.memory + 0x11000, 0]
            ),
            Err(ApiErr::Unimplemented(_))
        ));
        h.close(null);
        h.filename("unsupported.bin", true);
        for flags in [0x4000_0000, 0x2000_0000, 0x8000_0000, 1, 0x20] {
            assert!(matches!(
                h.call(
                    "CreateFileW",
                    &[h.memory, GENERIC_WRITE.into(), 7, 0, 2, flags, 0]
                ),
                Err(ApiErr::Unimplemented(_))
            ));
            assert!(!h.directory.0.join("unsupported.bin").exists());
        }
        h.process.state().space.wr(h.memory, &[0xE9, 0]).unwrap();
        assert!(matches!(
            h.call(
                "CreateFileA",
                &[h.memory, GENERIC_WRITE.into(), 7, 0, 1, 0, 0]
            ),
            Err(ApiErr::Unimplemented(_))
        ));
        let units = vec![0x61u16; MAX_PATH_UNITS + 1];
        h.process
            .state()
            .space
            .put_wunits(h.memory, &units)
            .unwrap();
        assert_eq!(
            h.value(
                "CreateFileW",
                &[h.memory, GENERIC_WRITE.into(), 7, 0, 1, 0, 0]
            ),
            h.invalid()
        );
        assert_eq!(h.error(), ERROR_FILENAME_EXCED_RANGE);
        h.filename("C:\\missing\\leaf", true);
        assert_eq!(
            h.value(
                "CreateFileW",
                &[h.memory, GENERIC_WRITE.into(), 7, 0, 1, 0, 0]
            ),
            h.invalid()
        );
        assert_eq!(h.error(), ERROR_PATH_NOT_FOUND);
        assert_eq!(h.value("GetFileType", &[0x12345678]), 0);
        assert_eq!(h.error(), ERROR_INVALID_HANDLE);
    }
}

#[cfg(unix)]
#[test]
fn hard_link_sharing_readonly_and_replacement_safe_deletion_all_abis() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let path = h.directory.0.join("identity.bin");
        std::fs::write(&path, b"original").unwrap();
        std::fs::hard_link(&path, h.directory.0.join("alias.bin")).unwrap();
        let file = h.open("identity.bin", GENERIC_READ, 0, 3, 0);
        assert_eq!(h.open("alias.bin", GENERIC_WRITE, 7, 3, 0), h.invalid());
        assert_eq!(h.error(), ERROR_SHARING_VIOLATION);
        h.close(file);
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        let original = permissions.clone();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).unwrap();
        assert_eq!(h.open("identity.bin", GENERIC_WRITE, 7, 3, 0), h.invalid());
        assert_eq!(h.error(), ERROR_ACCESS_DENIED);
        h.filename("identity.bin", true);
        assert_eq!(h.value("DeleteFileW", &[h.memory]), 0);
        std::fs::set_permissions(&path, original).unwrap();
        let file = h.open("identity.bin", GENERIC_READ, 7, 3, DELETE_ON_CLOSE);
        std::fs::rename(&path, h.directory.0.join("renamed.bin")).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        assert_eq!(
            h.value("CloseHandle", &[file]),
            0,
            "no success for deleting a replaced pathname"
        );
        assert_eq!(h.error(), ERROR_FILE_NOT_FOUND);
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        assert_eq!(
            std::fs::read(h.directory.0.join("renamed.bin")).unwrap(),
            b"original"
        );
        let file = h.open("renamed.bin", GENERIC_READ, 7, 3, DELETE_ON_CLOSE);
        let moved = h.directory.0.join("moved.bin");
        std::fs::rename(h.directory.0.join("renamed.bin"), &moved).unwrap();
        assert_eq!(h.value("CloseHandle", &[file]), 0);
        assert_eq!(h.error(), ERROR_FILE_NOT_FOUND);
        assert_eq!(std::fs::read(&moved).unwrap(), b"original");
        let metadata = h.open("identity.bin", 0, 7, 3, 0);
        std::fs::rename(&path, h.directory.0.join("metadata-original.bin")).unwrap();
        std::fs::write(&path, b"another replacement").unwrap();
        assert!(matches!(
            h.call("GetFileSizeEx", &[metadata, h.memory + 0x12000]),
            Err(ApiErr::Unimplemented(_))
        ));
        h.close(metadata);
    }
}

#[cfg(unix)]
#[test]
fn symlink_pending_opens_and_distinct_link_deletion_all_abis() {
    use std::os::unix::fs::symlink;
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let target = h.directory.0.join("target.bin");
        let link = h.directory.0.join("link.bin");
        std::fs::write(&target, b"target").unwrap();
        symlink("target.bin", &link).unwrap();
        let file = h.open("target.bin", GENERIC_READ, 7, 3, 0);
        h.filename("target.bin", true);
        assert_eq!(h.value("DeleteFileW", &[h.memory]), 1);
        assert_eq!(h.open("link.bin", GENERIC_READ, 7, 3, 0), h.invalid());
        assert_eq!(h.error(), ERROR_ACCESS_DENIED);
        assert_eq!(h.read(file, 6), b"target");
        h.close(file);
        assert!(!target.exists());
        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
        std::fs::write(&target, b"new").unwrap();
        h.filename("link.bin", true);
        assert_eq!(h.value("DeleteFileW", &[h.memory]), 1);
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert!(!link.exists());
        symlink("target.bin", &link).unwrap();
        let file = h.open("link.bin", GENERIC_READ, 7, 3, DELETE_ON_CLOSE);
        h.close(file);
        assert!(!target.exists());
        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
    }
}

#[cfg(unix)]
#[test]
fn process_destruction_performs_final_close_deletion_all_abis() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let path = h.directory.0.join("exit.bin");
        let file = h.open(
            "exit.bin",
            GENERIC_READ | GENERIC_WRITE,
            7,
            1,
            DELETE_ON_CLOSE,
        );
        assert_ne!(file, h.invalid());
        assert!(path.exists());
        let Harness {
            process,
            thread,
            directory,
            ..
        } = h;
        drop(process);
        assert!(!path.exists());
        drop(thread);
        drop(directory);
    }
}

#[test]
fn signed_seek_boundaries_security_attributes_and_directory_admission_all_abis() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let file = h.open("bounds.bin", GENERIC_READ | GENERIC_WRITE, 7, 1, 0);
        assert_eq!(
            h.value("SetFilePointerEx", &[file, (-1i64) as u64, 0, 1]),
            0
        );
        assert_eq!(h.error(), ERROR_NEGATIVE_SEEK);
        assert_eq!(h.cursor(file), 0);
        assert_eq!(h.value("SetFilePointerEx", &[file, u64::MAX, 0, 0]), 0);
        assert_eq!(h.error(), ERROR_INVALID_PARAMETER);
        assert_eq!(h.cursor(file), 0);
        assert_eq!(h.value("SetFilePointerEx", &[file, 0, 0, 3]), 0);
        h.close(file);
        h.filename("inherited.bin", true);
        let security = h.memory + 0x13000;
        let size = if arch.is64() { 24 } else { 12 };
        h.process.state().space.w32(security, size).unwrap();
        h.process
            .state()
            .space
            .wptr(security + arch.ptr_size(), arch.ptr_size(), 0)
            .unwrap();
        h.process
            .state()
            .space
            .w32(security + 2 * arch.ptr_size(), 1)
            .unwrap();
        let file = h.value(
            "CreateFileW",
            &[h.memory, GENERIC_READ.into(), 7, security, 1, 0, 0],
        );
        assert_eq!(h.process.state().objects.flags(file), Some(1));
        h.close(file);
        h.filename("bad-security.bin", true);
        h.process.state().space.w32(security, 0).unwrap();
        assert_eq!(
            h.value(
                "CreateFileW",
                &[h.memory, GENERIC_WRITE.into(), 7, security, 1, 0, 0]
            ),
            h.invalid()
        );
        assert!(!h.directory.0.join("bad-security.bin").exists());
        assert_eq!(h.open("C:\\", 0, 7, 3, 0), h.invalid());
        let directory = h.open("C:\\", 0, 7, 3, BACKUP_SEMANTICS);
        assert_ne!(directory, h.invalid());
        assert_eq!(h.value("GetFileType", &[directory]), 1);
        h.close(directory);
    }
}

#[test]
fn closed_filesystem_denies_existing_paths_and_captures_console_all_abis() {
    use crate::user::console::{CapturedConsole, Console, OutputStream};
    use crate::user::windows::objects::{Object, StdStream};
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let path = h.directory.0.join("untouched.bin");
        std::fs::write(&path, b"original").unwrap();
        let capture = CapturedConsole::new(b"input".to_vec(), 8).unwrap();
        let cfg = std::sync::Arc::make_mut(&mut h.process.state_mut().cfg);
        cfg.host_filesystem = false;
        cfg.console = Console::Captured(capture.clone());
        assert_eq!(h.open("untouched.bin", GENERIC_WRITE, 7, 2, 0), h.invalid());
        assert_eq!(h.error(), ERROR_ACCESS_DENIED);
        h.filename("untouched.bin", true);
        assert_eq!(h.value("DeleteFileW", &[h.memory]), 0);
        assert_eq!(h.error(), ERROR_ACCESS_DENIED);
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        let stdin = h
            .process
            .state_mut()
            .objects
            .insert(Object::Console(StdStream::In)) as u64;
        let stdout = h
            .process
            .state_mut()
            .objects
            .insert(Object::Console(StdStream::Out)) as u64;
        let stderr = h
            .process
            .state_mut()
            .objects
            .insert(Object::Console(StdStream::Err)) as u64;
        assert_eq!(h.read(stdin, 8), b"input");
        assert!(h.read(stdin, 8).is_empty());
        assert_eq!(h.write(stdout, b"hello"), 1);
        assert_eq!(h.write(stderr, b"err"), 1);
        assert_eq!(h.write(stdout, b"!"), 0);
        assert_eq!(capture.pending().unwrap(), (0, 5, 3));
        let mut bytes = [0; 8];
        assert_eq!(capture.drain(OutputStream::Stdout, &mut bytes).unwrap(), 5);
        assert_eq!(&bytes[..5], b"hello");
        assert_eq!(h.write(stdout, b"!"), 1);
    }
}
